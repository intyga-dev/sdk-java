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
  private final String webauthnOrigin;
  private final String webauthnRpId;
  private final List<BundleApprover> approvers;
  private final List<BundlePolicy> policy;
  private final boolean policyIsList;
  private final String unmatchedActionPolicy;
  private final String issuedAt;
  private final String expiresAt;
  private final Map<String, List<String>> requesterControllers;
  /** Raw {@code requesterControllers}, so resolution refuses an unverified bundle's malformed map. */
  private final JsonNode requesterControllersRaw;
  /** Raw {@code controllerKeys}: validated where it is used, since an unverified bundle may carry anything. */
  private final JsonNode controllerKeys;

  private TrustBundle(JsonNode payload) {
    JsonNode v = payload.get("v");
    this.v = Js.isSafeInteger(v) ? Long.valueOf(v.longValue()) : null;
    this.type = Js.text(payload.get("type"));
    this.tenantId = Js.text(payload.get("tenantId"));
    this.webauthnOrigin = Js.text(payload.path("webauthn").get("origin"));
    this.webauthnRpId = Js.text(payload.path("webauthn").get("rpId"));
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
        policy.add(BundlePolicy.fromJson(entry, this.v == null ? 0 : this.v));
      }
    }
    this.policy = Collections.unmodifiableList(policy);
    this.unmatchedActionPolicy = Js.text(payload.get("unmatchedActionPolicy"));
    this.issuedAt = Js.text(payload.get("issuedAt"));
    this.expiresAt = Js.text(payload.get("expiresAt"));
    Map<String, List<String>> controllers = new LinkedHashMap<>();
    JsonNode rc = payload.get("requesterControllers");
    if (rc != null && rc.isObject()) rc.fields().forEachRemaining(
        e -> controllers.put(e.getKey(), List.copyOf(Js.strings(e.getValue()))));
    this.requesterControllers = Collections.unmodifiableMap(controllers);
    this.requesterControllersRaw = rc == null ? null : rc.deepCopy();
    JsonNode ck = payload.get("controllerKeys");
    this.controllerKeys = ck == null ? null : ck.deepCopy();
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

  /**
   * 1 for a verified bundle, or 2 exactly when some policy entry carries {@code
   * requireEnrolledDevice} (DIV §5a.4). Null when the payload's {@code v} is not a safe integer.
   */
  public Long v() {
    return v;
  }

  public String type() {
    return type;
  }

  public String tenantId() {
    return tenantId;
  }

  /** Expectations pinned by the bundle signature; absent in older bundles. */
  public String webauthnOrigin() { return webauthnOrigin; }
  public String webauthnRpId() { return webauthnRpId; }

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
    // Strict base64url, as the reference decodes every JWS part: a character outside the alphabet is
    // refused, never skipped.
    byte[] headerBytes = Base64Url.decodeStrict(parts[0]);
    JsonNode header = headerBytes == null ? null : Js.parse(utf8(headerBytes));
    if (header == null) {
      return TrustBundleResult.refuse("trust bundle header is not JSON");
    }
    if (!header.isObject()) {
      return TrustBundleResult.refuse("invalid trust bundle header");
    }
    JsonNode alg = header.get("alg");
    if (alg == null || !alg.isTextual() || !alg.textValue().equals("RS256")) {
      String got = alg == null || alg.isNull() ? "(none)" : jsString(alg);
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
      byte[] signature = Base64Url.decodeStrict(parts[2]);
      // A malformed signature (wrong length, say) does not verify: the reference's OpenSSL check
      // returns false for it rather than failing, so it is not reported as a check failure here.
      try {
        verified = signature != null && s.verify(signature);
      } catch (java.security.SignatureException malformed) {
        verified = false;
      }
    } catch (GeneralSecurityException | IllegalArgumentException e) {
      return TrustBundleResult.refuse("trust bundle signature check failed: " + e.getMessage());
    }
    if (!verified) {
      return TrustBundleResult.refuse(
          "trust bundle signature does not verify against the pinned gateway key");
    }

    byte[] payloadBytes = Base64Url.decodeStrict(parts[1]);
    JsonNode bundle = payloadBytes == null ? null : Js.parse(utf8(payloadBytes));
    if (bundle == null) {
      return TrustBundleResult.refuse("trust bundle payload is not JSON");
    }
    if (!bundle.isObject()) {
      return TrustBundleResult.refuse("invalid trust bundle payload");
    }
    // DIV §5a.4: version 2 exists only to carry requireEnrolledDevice, so a version 2 bundle with no
    // such entry is an unsupported version — one policy has one form, and the refusal (and its order)
    // stays exactly what a version 1 reader reports for any unknown version.
    JsonNode rawPolicy = bundle.get("policy");
    boolean deviceRule = false;
    if (rawPolicy != null && rawPolicy.isArray()) {
      for (JsonNode entry : rawPolicy) {
        JsonNode device = entry == null ? null : entry.get("requireEnrolledDevice");
        if (device != null && device.isBoolean() && device.booleanValue()) deviceRule = true;
      }
    }
    JsonNode version = bundle.get("v");
    boolean v2 = version != null && version.isNumber() && version.doubleValue() == 2d;
    if (!TYPE.equals(Js.text(bundle.get("type"))) || !(Js.isNumberOne(version) || (v2 && deviceRule))) {
      return TrustBundleResult.refuse("unsupported trust bundle type or version");
    }
    long bundleVersion = v2 ? 2 : 1;
    String tenantId = Js.text(bundle.get("tenantId"));
    if (tenantId == null || tenantId.isEmpty()) {
      return TrustBundleResult.refuse("trust bundle tenantId must be a non-empty string");
    }
    if (bundle.has("webauthn")) {
      JsonNode pins = bundle.get("webauthn");
      String origin = Js.text(pins.get("origin"));
      String rpId = Js.text(pins.get("rpId"));
      if (origin == null || origin.isEmpty() || rpId == null || rpId.isEmpty()) {
        return TrustBundleResult.refuse("invalid trust bundle WebAuthn expectations");
      }
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
    JsonNode controllerKeys = bundle.get("controllerKeys");
    if (controllerKeys != null && !validControllerKeys(controllerKeys)) {
      return TrustBundleResult.refuse("trust bundle carries malformed controller key facts");
    }
    // Same position and text as the reference: after controllerKeys, before policy.
    JsonNode controllers = bundle.get("requesterControllers");
    if (controllers != null && !validRequesterControllers(controllers)) {
      return TrustBundleResult.refuse("trust bundle carries malformed requester controllers");
    }
    JsonNode policy = bundle.get("policy");
    if (policy == null || !policy.isArray()) {
      return TrustBundleResult.refuse("trust bundle carries invalid or incomplete policy");
    }
    for (JsonNode p : policy) {
      if (!BundlePolicy.validBundlePolicy(p, bundleVersion)) {
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
      return TrustBundleResult.refuse("trust bundle is " + toFixed1(ageMs / (double) DAY_MS)
          + " days old, over the " + MAX_AGE_DAYS + "-day maximum — export a fresh one");
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
   * (never widens it: a DID not in the bundle is not eligible). Keys stay resolvable for EVERY
   * bundle approver, eligible or not, so the verifier can refuse a signature under a key that is
   * also bound to a non-eligible or excluded identity. {@link AnchorPurpose#OFFLINE_INTENT}
   * requires an explicit DID restriction; {@code null} throws so every offline key in the tenant
   * bundle cannot become eligible for one action.
   */
  public ApproverDirectory approverDirectory(List<String> limitToDids, AnchorPurpose purpose) {
    return approverDirectory(limitToDids, purpose, List.of());
  }

  /**
   * As {@link #approverDirectory(List, AnchorPurpose)}, and also merges the bundle's {@code
   * controllerKeys} facts into each of {@code excludedDids}, so a key known for an excluded
   * controller who is not an approver is still recognised as theirs. Those facts never make an
   * identity eligible and never add a key to one that is not excluded.
   *
   * @throws IllegalArgumentException for an offline-intent anchor without a DID restriction, or
   *     when the bundle carries malformed controller key facts
   */
  public ApproverDirectory approverDirectory(List<String> limitToDids, AnchorPurpose purpose,
      List<String> excludedDids) {
    if (purpose == AnchorPurpose.OFFLINE_INTENT && limitToDids == null) {
      throw new IllegalArgumentException(
          "offline-intent anchors require an explicit eligible DID restriction");
    }
    Set<String> eligible = new LinkedHashSet<>();
    Map<String, List<String>> byDid = new LinkedHashMap<>();
    for (BundleApprover a : approvers) {
      // A DID-less entry (possible only in an unverified bundle) can never match a signer.
      if (a.did() == null) continue;
      if (limitToDids == null || limitToDids.contains(a.did())) eligible.add(a.did());
      List<String> keys = new ArrayList<>(a.publicKeys());
      if (purpose == AnchorPurpose.OFFLINE_INTENT && a.offlinePublicKeys() != null) {
        keys.addAll(a.offlinePublicKeys());
      }
      byDid.put(a.did(), keys);
    }
    if (controllerKeys != null) {
      if (!validControllerKeys(controllerKeys)) {
        throw new IllegalArgumentException("Malformed controller key facts");
      }
      for (String did : excludedDids == null ? List.<String>of() : excludedDids) {
        JsonNode facts = controllerKeys.get(did);
        if (facts == null) continue;
        Set<String> merged = new LinkedHashSet<>(byDid.getOrDefault(did, List.of()));
        merged.addAll(Js.strings(facts));
        byDid.put(did, new ArrayList<>(merged));
      }
    }
    return new ApproverDirectory(new ArrayList<>(eligible), byDid);
  }

  /** {@code approverAnchor(bundle, limitToDids, purpose)}: the verifier's DID-mode anchor. */
  public ApproverTrustAnchor approverAnchor(List<String> limitToDids, AnchorPurpose purpose) {
    return approverAnchor(limitToDids, purpose, List.of());
  }

  /** Keep excluded identities resolvable for key-alias tainting without making them eligible. */
  public ApproverTrustAnchor approverAnchor(List<String> limitToDids, AnchorPurpose purpose,
      List<String> excludedDids) {
    return approverDirectory(limitToDids, purpose, excludedDids).toTrustAnchor();
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
    return requirementFor(actionType, display, null);
  }

  /**
   * Resolve and bind controller exclusions for a specific requester. A rule with {@code
   * requesterCannotApprove} resolves only for a requester with a signed controller entry; a null
   * {@code requesterDid} then refuses (DIV §5a.4).
   */
  public Optional<ResolvedRequirement> requirementFor(String actionType, String display,
      String requesterDid) {
    if (v == null || (v != 1L && v != 2L)
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
    // Sorted and deduplicated, as in the reference: the SET is the policy.
    List<String> excluded = winner.excludedSignerDids() == null ? null
        : new ArrayList<>(new java.util.TreeSet<>(winner.excludedSignerDids()));
    if (winner.requesterCannotApprove()) {
      // DIV §5a.4: no requester, a missing entry or a malformed map all refuse; there is no
      // requester-only fallback.
      if (requesterDid == null || !validRequesterControllers(requesterControllersRaw)
          || !requesterControllers.containsKey(requesterDid)) return Optional.empty();
      Set<String> union = new LinkedHashSet<>();
      if (excluded != null) union.addAll(excluded);
      union.addAll(requesterControllers.get(requesterDid));
      excluded = new ArrayList<>(union); excluded.sort(String::compareTo);
    }
    return Optional.of(new ResolvedRequirement(
        new ApprovalRequirement(
            (int) Math.max(1, winner.requiredApprovals()),
            winner.requireHardwareKey(),
            winner.allowedAaguids(),
            winner.requesterCannotApprove(),
            "human", excluded,
            // Carried, never dropped: the offline ceremony refuses it explicitly (DIV §5a.3 step 4)
            // and a relying party's step-3d floor built from this requirement keeps demanding it.
            winner.requireEnrolledDevice() ? Boolean.TRUE : null),
        winner.approverDids()));
  }

  /** Optional controller identities exported for four-eyes offline challenge construction. */
  public Map<String, List<String>> requesterControllers() { return requesterControllers; }

  /**
   * JavaScript's {@code x.toFixed(1)} for a finite non-negative double: rounds the EXACT binary value
   * (ties to the larger), which {@code String.format("%.1f")} does not — it rounds the shortest
   * decimal representation, so 30.15 (stored as 30.1499…) printed 30.2 here and 30.1 in the reference.
   */
  static String toFixed1(double x) {
    return new java.math.BigDecimal(x).setScale(1, java.math.RoundingMode.HALF_UP).toPlainString();
  }

  /** JavaScript's {@code String(value)} for a parsed JSON value, as a template literal renders it. */
  static String jsString(JsonNode n) {
    if (n == null || n.isNull()) return "null";
    if (n.isTextual()) return n.textValue();
    if (n.isBoolean()) return n.booleanValue() ? "true" : "false";
    if (n.isNumber()) {
      try {
        return com.intyga.verify.Canonical.stableStringify(n.doubleValue());
      } catch (IllegalArgumentException e) {
        return n.asText();
      }
    }
    if (n.isArray()) {
      StringBuilder b = new StringBuilder();
      for (int i = 0; i < n.size(); i++) {
        if (i > 0) b.append(',');
        JsonNode e = n.get(i);
        if (!e.isNull()) b.append(jsString(e));
      }
      return b.toString();
    }
    return "[object Object]";
  }

  /** {@code validRequesterControllers}: an object of requester DID → array of valid DIDs. */
  static boolean validRequesterControllers(JsonNode value) {
    if (value == null || !value.isObject()) return false;
    var fields = value.fields();
    while (fields.hasNext()) {
      var entry = fields.next();
      if (!validDid(entry.getKey()) || !entry.getValue().isArray()) return false;
      // A set of controller DIDs: a repeated DID is accepted and deduplicated when signed.
      for (JsonNode did : entry.getValue()) if (!did.isTextual() || !validDid(did.textValue())) return false;
    }
    return true;
  }

  /** {@code validControllerKeys}: an object of controller DID → non-empty key strings. */
  static boolean validControllerKeys(JsonNode value) {
    if (value == null || !value.isObject()) return false;
    var fields = value.fields();
    while (fields.hasNext()) {
      var entry = fields.next();
      if (!validDid(entry.getKey()) || !Js.isStringArray(entry.getValue(), true)) return false;
    }
    return true;
  }

  private static boolean validDid(String did) {
    if (did == null || !did.startsWith("did:") || did.length() == 4
        || did.getBytes(StandardCharsets.UTF_8).length > 4096) return false;
    for (int i = 0; i < did.length(); i++) {
      char c = did.charAt(i);
      if (c <= 0x20 || c == 0x7f) return false;
      if (Character.isSurrogate(c)) {
        if (i + 1 >= did.length() || !Character.isSurrogatePair(c, did.charAt(i + 1))) return false;
        i++;
      }
    }
    return true;
  }

  private static String utf8(byte[] bytes) {
    return new String(bytes, StandardCharsets.UTF_8);
  }
}
