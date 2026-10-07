package com.intyga.sdk.offline;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.intyga.verify.ApprovalRequirement;
import com.intyga.verify.ApproverTrustAnchor;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Offline trust bundle (DIV §5a.4) — the relying party's local answer to "whose signature counts,
 * and what does policy require?". Port of {@code packages/sdk/src/trust-bundle.ts}.
 *
 * <p>Offline verification needs two things the network normally supplies: the approver public keys
 * (DIV Invariant 3 forbids taking them from the proof under verification) and the approval
 * REQUIREMENT. The relying party builds its own offline challenge, so if it also invented the
 * quorum it would be setting its own policy. The bundle is the offline projection of the tenant's
 * real policy, exported while the gateway was reachable, as a compact JWS signed with the gateway's
 * OIDC key — which is why the verifying key must be PINNED at export rather than fetched.
 */
public final class TrustBundle {

  /** Bundle {@code type} discriminator, inside the signed JWS payload. */
  public static final String TYPE = "div-trust-bundle-v1";

  /**
   * Hard ceiling on bundle age, enforced regardless of the {@code expiresAt} the gateway wrote. A
   * stale bundle is a stale approver set: a revoked approver stays trusted, a tightened quorum
   * stays loose. Exactly 30 days is accepted.
   */
  public static final int MAX_AGE_DAYS = 30;

  static final String BUNDLE_FILE = "trust-bundle.jws";
  static final String KEY_FILE = "gateway-key.jwk.json";

  private static final long DAY_MS = 86_400_000L;

  private final Long v;
  private final String type;
  private final String tenantId;
  private final List<BundleApprover> approvers;
  private final List<BundlePolicy> policy;
  private final boolean policyIsList;
  private final String unmatchedActionPolicy;
  private final String issuedAt;
  private final String expiresAt;

  private TrustBundle(JsonNode payload) {
    JsonNode v = payload.get("v");
    this.v = Js.isSafeInteger(v) ? Long.valueOf(v.longValue()) : null;
    this.type = Js.text(payload.get("type"));
    this.tenantId = Js.text(payload.get("tenantId"));
    List<BundleApprover> approvers = new ArrayList<>();
    JsonNode a = payload.get("approvers");
    if (a != null && a.isArray()) {
      for (JsonNode entry : a) {
        JsonNode offline = entry.get("offlinePublicKeys");
        approvers.add(new BundleApprover(
            Js.text(entry.get("did")),
            Js.strings(entry.get("publicKeys")),
            offline == null || !offline.isArray() ? null : Js.strings(offline)));
      }
    }
    this.approvers = Collections.unmodifiableList(approvers);
    List<BundlePolicy> policy = new ArrayList<>();
    JsonNode p = payload.get("policy");
    this.policyIsList = p != null && p.isArray();
    if (policyIsList) {
      for (JsonNode entry : p) {
        policy.add(BundlePolicy.fromJson(entry));
      }
    }
    this.policy = Collections.unmodifiableList(policy);
    this.unmatchedActionPolicy = Js.text(payload.get("unmatchedActionPolicy"));
    this.issuedAt = Js.text(payload.get("issuedAt"));
    this.expiresAt = Js.text(payload.get("expiresAt"));
  }

  /**
   * Structural parse of a bundle payload with NO verification at all — no signature, no approver
   * or policy validation, no freshness. For tests, tooling and re-reading a payload you already
   * verified; never trust approvers that did not come through {@link #verify} or {@link #load}.
   * Resolution still fails closed on an unverified bundle's malformed policy ({@link
   * #requirementFor}).
   *
   * @throws IllegalArgumentException when {@code payload} is not a JSON object
   */
  public static TrustBundle parseUnverified(JsonNode payload) {
    if (payload == null || !payload.isObject()) {
      throw new IllegalArgumentException("a trust bundle payload is a JSON object");
    }
    return new TrustBundle(payload);
  }

  /** Always 1 for a verified bundle. Null when the payload's {@code v} is not a safe integer. */
  public Long v() {
    return v;
  }

  public String type() {
    return type;
  }

  public String tenantId() {
    return tenantId;
  }

  public List<BundleApprover> approvers() {
    return approvers;
  }

  public List<BundlePolicy> policy() {
    return policy;
  }

  /** {@code DENY} or {@code BASELINE}: what an action with no exact rule resolves to. */
  public String unmatchedActionPolicy() {
    return unmatchedActionPolicy;
  }

  public String issuedAt() {
    return issuedAt;
  }

  public String expiresAt() {
    return expiresAt;
  }

  // ---------------------------------------------------------------------------------------------
  // Verification
  // ---------------------------------------------------------------------------------------------

  /**
   * Verify a compact JWS bundle against a PINNED gateway key and return its payload.
   *
   * <p>Only RS256 is accepted, and the {@code alg} header is checked against that fixed expectation
   * rather than used to select an algorithm — trusting the token's own {@code alg} is the classic
   * JWS confusion bug ({@code none} skips verification; an HMAC alg would verify a MAC keyed with a
   * public key the attacker also has).
   *
   * @param gatewayJwk the gateway's RSA public key as a JWK ({@code kty}, {@code n}, {@code e}),
   *     pinned when the bundle was exported
   * @param asOf overrides "now" for the freshness check; null means the current instant
   */
  public static TrustBundleResult verify(String jws, JsonNode gatewayJwk, Instant asOf) {
    if (jws == null) {
      return TrustBundleResult.refuse("trust bundle is not a compact JWS");
    }
    String[] parts = jws.split("\\.", -1);
    if (parts.length != 3) {
      return TrustBundleResult.refuse("trust bundle is not a compact JWS");
    }
    JsonNode header = Js.parse(utf8(Base64Url.decodeLenient(parts[0])));
    if (header == null) {
      return TrustBundleResult.refuse("trust bundle header is not JSON");
    }
    if (!header.isObject() && !header.isArray()) {
      return TrustBundleResult.refuse("invalid trust bundle header");
    }
    JsonNode alg = header.get("alg");
    if (alg == null || !alg.isTextual() || !alg.textValue().equals("RS256")) {
      String got = alg == null || alg.isNull() ? "(none)" : alg.isTextual() ? alg.textValue() : alg.toString();
      return TrustBundleResult.refuse("trust bundle alg must be RS256, got " + got);
    }

    // RS256 means an RSA key. A pinned EC key would otherwise get ECDSA verification under an RS256
    // header — the key choice deciding the algorithm, which is the confusion the alg check exists for.
    if (gatewayJwk == null || !gatewayJwk.isObject() || !"RSA".equals(Js.text(gatewayJwk.get("kty")))) {
      return TrustBundleResult.refuse("pinned gateway key must be an RSA JWK");
    }
    PublicKey key;
    try {
      key = rsaPublicKey(gatewayJwk);
    } catch (GeneralSecurityException | IllegalArgumentException e) {
      return TrustBundleResult.refuse("pinned gateway key is unusable: " + e.getMessage());
    }

    boolean verified;
    try {
      Signature s = Signature.getInstance("SHA256withRSA");
      s.initVerify(key);
      s.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.UTF_8));
      verified = s.verify(Base64Url.decodeLenient(parts[2]));
    } catch (GeneralSecurityException | IllegalArgumentException e) {
      return TrustBundleResult.refuse("trust bundle signature check failed: " + e.getMessage());
    }
    if (!verified) {
      return TrustBundleResult.refuse(
          "trust bundle signature does not verify against the pinned gateway key");
    }

    JsonNode bundle = Js.parse(utf8(Base64Url.decodeLenient(parts[1])));
    if (bundle == null) {
      return TrustBundleResult.refuse("trust bundle payload is not JSON");
    }
    if (!bundle.isObject() && !bundle.isArray()) {
      return TrustBundleResult.refuse("invalid trust bundle payload");
    }
    if (!TYPE.equals(Js.text(bundle.get("type"))) || !Js.isNumberOne(bundle.get("v"))) {
      return TrustBundleResult.refuse("unsupported trust bundle type or version");
    }
    String unmatched = Js.text(bundle.get("unmatchedActionPolicy"));
    if (!"DENY".equals(unmatched) && !"BASELINE".equals(unmatched)) {
      return TrustBundleResult.refuse("trust bundle has no valid unmatched-action decision");
    }
    JsonNode approvers = bundle.get("approvers");
    if (approvers == null || !approvers.isArray() || approvers.isEmpty()) {
      return TrustBundleResult.refuse("trust bundle names no approvers");
    }
    for (JsonNode a : approvers) {
      if (!validApprover(a)) {
        return TrustBundleResult.refuse("invalid bundle approver keys");
      }
    }
    // A key listed as both ordinary and offline-only would undo the split the second list exists for.
    Set<String> ordinaryKeys = new HashSet<>();
    for (JsonNode a : approvers) {
      ordinaryKeys.addAll(Js.strings(a.get("publicKeys")));
    }
    for (JsonNode a : approvers) {
      for (String k : Js.strings(a.get("offlinePublicKeys"))) {
        if (ordinaryKeys.contains(k)) {
          return TrustBundleResult.refuse("trust bundle lists an offline signing key as an ordinary key");
        }
      }
    }
    JsonNode policy = bundle.get("policy");
    if (policy == null || !policy.isArray()) {
      return TrustBundleResult.refuse("trust bundle carries invalid or incomplete policy");
    }
    for (JsonNode p : policy) {
      if (!BundlePolicy.validBundlePolicy(p)) {
        return TrustBundleResult.refuse("trust bundle carries invalid or incomplete policy");
      }
    }
    TrustBundle parsed = new TrustBundle(bundle);
    try {
      ApprovalPolicy.validateExactApprovalPolicy(parsed.policy);
      if ("BASELINE".equals(unmatched) && parsed.policy.stream().noneMatch(r -> "*".equals(r.actionPattern()))) {
        return TrustBundleResult.refuse("trust bundle has no baseline for unknown actions");
      }
    } catch (ApprovalPolicyConflict conflict) {
      return TrustBundleResult.refuse(
          "trust bundle has invalid exact-action policy: " + String.join(", ", conflict.fields()));
    }
    return checkFreshness(parsed, asOf);
  }

  /** {@link #verify(String, JsonNode, Instant)} as of now. */
  public static TrustBundleResult verify(String jws, JsonNode gatewayJwk) {
    return verify(jws, gatewayJwk, null);
  }

  private static boolean validApprover(JsonNode a) {
    if (a == null || !a.isObject() || !Js.isNonEmptyString(a.get("did"))) {
      return false;
    }
    JsonNode keys = a.get("publicKeys");
    if (keys == null || !keys.isArray() || keys.isEmpty() || !Js.isStringArray(keys, true)) {
      return false;
    }
    JsonNode offline = a.get("offlinePublicKeys");
    // Absent is fine — bundles from before offline keys existed. Present (even as null) must be a list.
    return offline == null || Js.isStringArray(offline, true);
  }

  private static PublicKey rsaPublicKey(JsonNode jwk) throws GeneralSecurityException {
    if (jwk == null || !jwk.isObject()) {
      throw new IllegalArgumentException("the JWK is not a JSON object");
    }
    if (!"RSA".equals(Js.text(jwk.get("kty")))) {
      throw new IllegalArgumentException("the JWK is not an RSA key (kty must be RSA)");
    }
    String n = Js.text(jwk.get("n"));
    String e = Js.text(jwk.get("e"));
    if (n == null || n.isEmpty() || e == null || e.isEmpty()) {
      throw new IllegalArgumentException("the RSA JWK is missing n or e");
    }
    return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(
        new BigInteger(1, Base64Url.decodeLenient(n)), new BigInteger(1, Base64Url.decodeLenient(e))));
  }

  /**
   * Recheck a verified bundle — after an out-of-band signing ceremony, say — without changing its
   * trust keys. Two independent staleness checks: the gateway's own {@code expiresAt}, and the
   * local {@value #MAX_AGE_DAYS}-day cap from {@code issuedAt}, which is what actually bounds drift
   * when an exporter chose a generous expiry.
   *
   * @return the bundle when fresh
   */
  public static TrustBundleResult checkFreshness(TrustBundle bundle, Instant asOf) {
    long now = JsTime.nowOr(asOf).toEpochMilli();
    Long expiry = JsTime.parseMillis(bundle.expiresAt);
    if (expiry == null) {
      return TrustBundleResult.refuse("trust bundle expiresAt is not a valid RFC3339 timestamp");
    }
    if (now > expiry) {
      return TrustBundleResult.refuse(
          "trust bundle expired at " + bundle.expiresAt + " — export a fresh one");
    }
    Long issued = JsTime.parseMillis(bundle.issuedAt);
    if (issued == null) {
      return TrustBundleResult.refuse("trust bundle issuedAt is not a valid RFC3339 timestamp");
    }
    long ageMs = now - issued;
    if (ageMs > MAX_AGE_DAYS * DAY_MS) {
      return TrustBundleResult.refuse(String.format(Locale.ROOT,
          "trust bundle is %.1f days old, over the %d-day maximum — export a fresh one",
          ageMs / (double) DAY_MS, MAX_AGE_DAYS));
    }
    return TrustBundleResult.accept(bundle);
  }

  // ---------------------------------------------------------------------------------------------
  // Files
  // ---------------------------------------------------------------------------------------------

  /**
   * Write a bundle and its pinned verification key into {@code dir} ({@code trust-bundle.jws},
   * {@code gateway-key.jwk.json}), private (0700 / 0600), for use during a later outage.
   */
  public static void save(Path dir, String jws, JsonNode gatewayJwk) throws IOException {
    SecureFiles.ensurePrivateDir(dir);
    SecureFiles.writePrivateFile(dir.resolve(BUNDLE_FILE), jws);
    String jwk;
    try {
      jwk = Js.JSON.writerWithDefaultPrettyPrinter().writeValueAsString(gatewayJwk);
    } catch (JsonProcessingException e) {
      throw new IOException("could not serialize the gateway JWK", e);
    }
    SecureFiles.writePrivateFile(dir.resolve(KEY_FILE), jwk + "\n");
  }

  /**
   * Load and verify the bundle in {@code dir}. Fails closed and loudly: there is deliberately no
   * "continue without a bundle" path, because the fallback would be an unverified approver set —
   * the one thing DIV Invariant 3 forbids.
   */
  public static TrustBundleResult load(Path dir, Instant asOf) {
    String jws;
    try {
      jws = Js.trim(Files.readString(dir.resolve(BUNDLE_FILE), StandardCharsets.UTF_8));
    } catch (IOException | RuntimeException e) {
      return TrustBundleResult.refuse("no trust bundle at " + dir.resolve(BUNDLE_FILE)
          + " — export one with `intyga trust-bundle export` while the gateway is reachable");
    }
    JsonNode jwk;
    try {
      jwk = Js.parse(Files.readString(dir.resolve(KEY_FILE), StandardCharsets.UTF_8));
    } catch (IOException | RuntimeException e) {
      jwk = null;
    }
    if (jwk == null) {
      return TrustBundleResult.refuse("no pinned gateway key at " + dir.resolve(KEY_FILE));
    }
    return verify(jws, jwk, asOf);
  }

  /** {@link #load(Path, Instant)} as of now. */
  public static TrustBundleResult load(Path dir) {
    return load(dir, null);
  }

  // ---------------------------------------------------------------------------------------------
  // Anchors and requirements
  // ---------------------------------------------------------------------------------------------

  /**
   * The DID → keys mapping for a DID-mode anchor. {@code limitToDids} narrows the eligible set
   * (never widens it: a DID not in the bundle resolves to nothing). {@link AnchorPurpose#ORDINARY}
   * never admits an offline signing key; pass {@link AnchorPurpose#OFFLINE_INTENT} only when the
   * receipt being verified is a {@code div-offline-intent}.
   */
  public ApproverDirectory approverDirectory(List<String> limitToDids, AnchorPurpose purpose) {
    Map<String, List<String>> byDid = new LinkedHashMap<>();
    for (BundleApprover a : approvers) {
      // A DID-less entry (possible only in an unverified bundle) can never match a signer.
      if (a.did() == null || (limitToDids != null && !limitToDids.contains(a.did()))) {
        continue;
      }
      List<String> keys = new ArrayList<>(a.publicKeys());
      if (purpose == AnchorPurpose.OFFLINE_INTENT && a.offlinePublicKeys() != null) {
        keys.addAll(a.offlinePublicKeys());
      }
      byDid.put(a.did(), keys);
    }
    return new ApproverDirectory(byDid);
  }

  /** {@code approverAnchor(bundle, limitToDids, purpose)}: the verifier's DID-mode anchor. */
  public ApproverTrustAnchor approverAnchor(List<String> limitToDids, AnchorPurpose purpose) {
    return approverDirectory(limitToDids, purpose).toTrustAnchor();
  }

  /** The {@link AnchorPurpose#ORDINARY} anchor. */
  public ApproverTrustAnchor approverAnchor(List<String> limitToDids) {
    return approverAnchor(limitToDids, AnchorPurpose.ORDINARY);
  }

  /**
   * Resolve the requirement for an action from the bundle's offline policy projection, with the
   * gateway's exact-ID (v3) selection: the whole policy is validated, a differently cased match of
   * a configured ID refuses, the exact rule wins, else the {@code *} rule only under {@code
   * BASELINE}. {@code display} never selects.
   *
   * <p>Empty — a refusal — when the bundle is malformed, the action is unmatched, the policy
   * conflicts, the rule has fewer distinct approver DIDs than its quorum, or it uses a control an
   * offline ceremony cannot reproduce (requester attestation, an issuer allowlist, escalation, an
   * auto-approving requester). A hardware rule DOES resolve; challenge creation refuses it.
   */
  public Optional<ResolvedRequirement> requirementFor(String actionType, String display) {
    if (v == null || v != 1L
        || !TYPE.equals(type)
        || (!"DENY".equals(unmatchedActionPolicy) && !"BASELINE".equals(unmatchedActionPolicy))
        || !policyIsList
        || !policy.stream().allMatch(BundlePolicy::complete)) {
      return Optional.empty();
    }
    BundlePolicy winner;
    try {
      winner = ApprovalPolicy.selectExactApprovalRule(policy, actionType, unmatchedActionPolicy).orElse(null);
    } catch (ApprovalPolicyConflict conflict) {
      return Optional.empty();
    }
    // These online-only conditions cannot be reconstructed by an offline ceremony.
    if (winner == null
        || new LinkedHashSet<>(winner.approverDids()).size() < winner.requiredApprovals()
        || winner.requireAttestedRequester()
        || !winner.allowedIssuers().isEmpty()
        || winner.escalateAfterSeconds() != null
        || (winner.autoApproveRequesterDid() != null && !winner.autoApproveRequesterDid().isEmpty())) {
      return Optional.empty();
    }
    return Optional.of(new ResolvedRequirement(
        new ApprovalRequirement(
            (int) Math.max(1, winner.requiredApprovals()),
            winner.requireHardwareKey(),
            winner.allowedAaguids(),
            winner.requesterCannotApprove(),
            "human"),
        winner.approverDids()));
  }

  private static String utf8(byte[] bytes) {
    return new String(bytes, StandardCharsets.UTF_8);
  }
}
