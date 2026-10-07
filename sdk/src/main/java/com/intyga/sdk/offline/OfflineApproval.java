package com.intyga.sdk.offline;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.intyga.verify.ApprovalReceipt;
import com.intyga.verify.ApprovalRequirement;
import com.intyga.verify.ApprovalWitness;
import com.intyga.verify.Canonical;
import com.intyga.verify.DelegationVerification;
import com.intyga.verify.Div;
import com.intyga.verify.Expected;
import com.intyga.verify.RequesterAttestation;
import com.intyga.verify.RequesterIdentity;
import com.intyga.verify.RequirementFloor;
import com.intyga.verify.VerifiedDelegation;
import com.intyga.verify.Verify;
import com.intyga.verify.VerifyOptions;
import com.intyga.verify.VerifyResult;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/**
 * Offline approval (DIV §5a) — the relying-party half, and the library half of an approver's
 * signing tool. Port of {@code packages/sdk/src/offline.ts}; the contract is {@code
 * docs/OFFLINE-APPROVAL-SDK.md} and the conformance suite {@code offline-approval-vectors.json}.
 *
 * <p>When the gateway is unreachable, the relying party builds the challenge ITSELF, the humans
 * review and sign it on a disconnected device, and the result is verified by the ordinary §5
 * procedure. The signing ceremony moves off the network; it does not move earlier in time.
 * Pre-signing approvals and holding them until needed is the rejected alternative: it puts a bearer
 * capability on disk and captures a judgment about a hypothetical rather than the incident.
 *
 * <p>Four properties are enforced structurally: (1) it only applies when the gateway could not be
 * ASKED — never after a refusal, DENIED or EXPIRED; (2) the client reports the distinct status
 * {@code OFFLINE_APPROVED}, never {@code APPROVED}; (3) the policy comes from the signed trust
 * bundle, never from the caller; (4) nothing written to disk authorizes anything — the files record
 * that an approval happened, for reconciliation.
 */
public final class OfflineApproval {

  /** Wire prefix for a challenge travelling OUT to the approvers. */
  public static final String CHALLENGE_ENVELOPE_PREFIX = "DIV1:";

  /** Wire prefix for a signature coming BACK from an approver. */
  public static final String SIGNATURE_ENVELOPE_PREFIX = "SIG1:";

  /**
   * Default validity window, in minutes. Deliberately short: an offline approval is created and
   * redeemed inside one incident, and the window is the only bound on a proof no one can revoke.
   */
  public static final int DEFAULT_WINDOW_MINUTES = 15;

  private static final Pattern SAFE_NONCE = Pattern.compile("[A-Za-z0-9._-]{1,200}");
  private static final String REDEEMED_DIR = ".redeemed";
  private static final String PENDING_DIR = ".pending";

  /** File-name order in UTF-16 code units — what the reference's {@code readdirSync().sort()} gives. */
  private static final Comparator<Path> BY_NAME = Comparator.comparing(p -> String.valueOf(p.getFileName()));

  private OfflineApproval() {}

  /**
   * Nonces become path segments in the redemption store and the reconciliation buffer; anything
   * that could traverse out of those directories is refused rather than trusted.
   */
  static boolean isPathSafeNonce(String nonce) {
    return nonce != null && SAFE_NONCE.matcher(nonce).matches();
  }

  /**
   * The short code an approver reads back to the operator (DIV §5a.8): the first eight hex digits
   * of SHA-256 over the canonical payload's UTF-8 bytes, uppercase, as {@code XXXX-XXXX}.
   */
  public static String verificationCode(String canonicalPayload) {
    String hex = HexFormat.of().withUpperCase().formatHex(sha256(canonicalPayload.getBytes(StandardCharsets.UTF_8)));
    return hex.substring(0, 4) + "-" + hex.substring(4, 8);
  }

  // ---------------------------------------------------------------------------------------------
  // Challenge
  // ---------------------------------------------------------------------------------------------

  /**
   * Build an offline challenge for an action, taking the approval requirement from the trust bundle.
   *
   * <p>Refuses when the bundle has no unambiguous rule for the action (there is no implicit 1-of-1
   * fallback — an unmatched action is an unconfigured one), when the rule requires a hardware or
   * allowlisted authenticator (nobody could produce a valid offline signature, DIV §5a.3), when a
   * delegation would LOWER the quorum (it may narrow who approves, never how many — DIV §5a.5), or
   * when the nonce is not a safe path segment. The window is {@code min(60, max(1, windowMinutes ??
   * 15))} minutes.
   */
  public static ChallengeResult createOfflineChallenge(ChallengeRequest req) {
    // DIV §3 Invariant 5 (Target Isolation): a blank target binds no execution environment, so the
    // approval would verify at every relying party that also asserts it.
    if (req.target() == null || Js.trim(req.target()).isEmpty()) {
      return ChallengeResult.refuse("target is required (DIV Target Isolation)");
    }
    ResolvedRequirement resolved = req.bundle().requirementFor(req.actionType(), req.display()).orElse(null);
    if (resolved == null) {
      return ChallengeResult.refuse("the trust bundle has no approval rule matching \"" + req.actionType()
          + "\" that can be selected unambiguously — configure the rule or export a fresh bundle with"
          + " rule-selection metadata (DIV §5a.3)");
    }
    // A hardware-key policy cannot be satisfied offline (DIV §5a.3 step 4). Refuse at CHALLENGE time
    // as well as at verification: sending approvers a payload nobody can validly sign wastes the
    // one resource an incident is short of. A non-empty AAGUID allowlist is the same policy class.
    if (resolved.requirement().requiresHardwareCredential()) {
      return ChallengeResult.refuse("\"" + req.actionType() + "\" requires a hardware-backed WebAuthn"
          + " credential, which cannot be produced offline — this action cannot be approved out of"
          + " band (DIV §5a.3)");
    }

    int requested = req.windowMinutes() == null ? DEFAULT_WINDOW_MINUTES : req.windowMinutes();
    int windowMinutes = Math.min(Div.MAX_OFFLINE_WINDOW_MINUTES, Math.max(1, requested));
    Instant now = JsTime.nowOr(req.asOf());
    String challengedAt = JsTime.iso(now);
    String expiresAt = JsTime.iso(now.plusSeconds(windowMinutes * 60L));
    String nonce = req.nonce() != null ? req.nonce() : "off_" + UUID.randomUUID();
    if (!isPathSafeNonce(nonce)) {
      return ChallengeResult.refuse("nonce must be a safe path segment");
    }

    // "Narrows who may approve, never the policy" has to be enforced, not merely intended. Without
    // this the swap below would silently LOWER the quorum: a delegation sealed against a permissive
    // rule could be presented against a strict one and overwrite its quorum (DIV §5a.5).
    VerifiedDelegation delegation = req.delegation();
    ApprovalRequirement base = resolved.requirement();
    if (delegation != null && delegation.delegatedQuorum() < base.requiredApprovals()) {
      return ChallengeResult.refuse("this delegation would lower the quorum for \"" + req.actionType()
          + "\" from " + base.requiredApprovals() + " to " + delegation.delegatedQuorum()
          + ". A delegation may narrow WHO approves, never HOW MANY (DIV §5a.5)");
    }
    // Under a delegation the eligible set and the quorum are the DELEGATED ones. Everything else in
    // the requirement still comes from the bundle.
    ApprovalRequirement requirement =
        delegation == null
            ? base
            : new ApprovalRequirement(delegation.delegatedQuorum(), base.requireHardwareKey(),
                base.allowedAaguids(), base.requesterCannotApprove(), base.signerClass());
    List<String> approverDids =
        delegation == null
            ? resolved.approverDids()
            : delegation.delegatedTo() == null ? List.of() : List.copyOf(delegation.delegatedTo());

    String canonicalPayload;
    try {
      canonicalPayload = Canonical.canonicalOfflineIntentPayload(req.target(), req.actionType(),
          req.display(), req.params(), req.requester(), requirement, nonce, challengedAt, expiresAt);
    } catch (Canonical.NonPortableValueException e) {
      return ChallengeResult.refuse("the action cannot be canonicalized portably: " + e.getMessage());
    }
    return new ChallengeResult(true, null, new OfflineChallenge(
        nonce,
        canonicalPayload,
        verificationCode(canonicalPayload),
        CHALLENGE_ENVELOPE_PREFIX + Base64Url.encode(canonicalPayload.getBytes(StandardCharsets.UTF_8)),
        challengedAt,
        expiresAt,
        req.target(),
        req.actionType(),
        req.display(),
        req.params(),
        req.requester(),
        requirement,
        approverDids));
  }

  /**
   * Decode a {@code DIV1:} envelope for review by a signing tool.
   *
   * <p>Only a {@code div-offline-intent} decodes: an approver's tool must not be usable to sign an
   * ORDINARY intent someone pasted in, which would be a live approval outside the gateway's
   * single-use accounting. And the parsed fields must re-canonicalize to exactly the decoded bytes:
   * otherwise the envelope is hand-edited, truncated or mis-shaped, and a signature over it would
   * verify nowhere over a payload the approver could not faithfully read.
   */
  public static DecodedChallengeResult decodeChallengeEnvelope(String envelope) {
    String trimmed = envelope == null ? "" : Js.trim(envelope);
    if (!trimmed.startsWith(CHALLENGE_ENVELOPE_PREFIX)) {
      return DecodedChallengeResult.refuse(
          "not a challenge envelope (expected a " + CHALLENGE_ENVELOPE_PREFIX + " prefix)");
    }
    byte[] bytes = Base64Url.decodeStrict(trimmed.substring(CHALLENGE_ENVELOPE_PREFIX.length()));
    if (bytes == null) {
      return DecodedChallengeResult.refuse("challenge envelope is not valid base64url");
    }
    String payload = new String(bytes, StandardCharsets.UTF_8);
    JsonNode parsed = Js.parse(payload);
    if (parsed == null) {
      return DecodedChallengeResult.refuse(
          "challenge envelope does not contain a JSON payload (truncated paste?)");
    }
    if (!parsed.isObject()) {
      return DecodedChallengeResult.refuse("challenge payload is not a JSON object");
    }
    JsonNode type = parsed.get("type");
    if (type == null || !Div.OFFLINE_INTENT_TYPE.equals(type.textValue())) {
      String shown = type == null ? "undefined" : type.isTextual() ? type.textValue() : type.toString();
      return DecodedChallengeResult.refuse(
          "this is a " + shown + " payload, not an offline approval challenge — refusing to sign it");
    }
    // Shapes before bytes. Canonicalization alone would accept `"target": 5` whenever it
    // re-serializes identically, and the approver would then review — and sign — something no
    // relying party builds. Every SDK refuses the same shapes (docs/OFFLINE-APPROVAL-SDK.md).
    String shapeProblem = challengeShapeProblem(parsed);
    if (shapeProblem != null) {
      return DecodedChallengeResult.refuse("challenge payload " + shapeProblem + " — refusing to sign it");
    }
    Fields f = Fields.of(parsed);
    if (f == null) {
      return DecodedChallengeResult.refuse(
          "challenge payload carries values that cannot be canonicalized — refusing to sign it");
    }
    String rebuilt;
    try {
      rebuilt = Canonical.canonicalOfflineIntentPayload(f.target, f.actionType, f.display, f.params,
          f.requester, f.requirement, f.nonce, f.challengedAt, f.expiresAt);
    } catch (RuntimeException e) {
      return DecodedChallengeResult.refuse(
          "challenge payload carries values that cannot be canonicalized — refusing to sign it");
    }
    if (!rebuilt.equals(payload)) {
      return DecodedChallengeResult.refuse("challenge payload is not canonical — re-serializing it"
          + " produces different bytes, so a signature over it would verify nowhere");
    }
    return new DecodedChallengeResult(true, null, new DecodedChallenge(
        payload,
        verificationCode(payload),
        f.target,
        f.actionType,
        f.display == null ? "" : f.display,
        f.params,
        f.requester,
        f.requirement,
        f.nonce,
        f.challengedAt,
        f.expiresAt));
  }

  /** Why a decoded challenge payload has the wrong shape, or null when every field is well-typed. */
  private static String challengeShapeProblem(JsonNode p) {
    for (String field : List.of("target", "actionType", "display", "nonce", "challengedAt", "expiresAt")) {
      if (!Js.isString(p.get(field))) {
        return "field " + field + " is not a string";
      }
    }
    if (Js.trim(p.get("target").textValue()).isEmpty()) {
      return "has a blank target";
    }
    JsonNode params = p.get("params");
    if (params == null || !params.isObject()) {
      return "params is not a JSON object";
    }
    JsonNode requester = p.get("requester");
    if (requester == null || !requester.isObject() || !Js.isString(requester.get("did"))) {
      return "requester is not an identity";
    }
    JsonNode requirement = p.get("requirement");
    if (requirement == null || !requirement.isObject()) {
      return "requirement is not a JSON object";
    }
    return null;
  }

  /**
   * The typed fields of a payload that passed {@link #challengeShapeProblem}. Null when a nested
   * value still cannot be typed (a fractional quorum, a malformed attestation): such a payload
   * cannot be faithfully canonicalized, so it is refused.
   */
  private static final class Fields {
    String target;
    String actionType;
    String display;
    Map<String, Object> params;
    RequesterIdentity requester;
    ApprovalRequirement requirement;
    String nonce;
    String challengedAt;
    String expiresAt;

    static Fields of(JsonNode p) {
      Fields f = new Fields();
      try {
        f.target = optText(p, "target");
        f.actionType = optText(p, "actionType");
        f.display = optText(p, "display");
        f.nonce = optText(p, "nonce");
        f.challengedAt = optText(p, "challengedAt");
        f.expiresAt = optText(p, "expiresAt");
      } catch (IllegalArgumentException e) {
        return null;
      }
      JsonNode params = p.get("params");
      if (params != null) {
        if (!params.isObject()) {
          return null;
        }
        f.params = Js.toMap(params);
      }
      f.requester = requester(p.get("requester"));
      f.requirement = requirement(p.get("requirement"));
      return f.requester == null || f.requirement == null ? null : f;
    }

    private static String optText(JsonNode p, String name) {
      JsonNode n = p.get(name);
      if (n == null) {
        return null;
      }
      if (!n.isTextual()) {
        throw new IllegalArgumentException(name);
      }
      return n.textValue();
    }
  }

  private static RequesterIdentity requester(JsonNode n) {
    if (n == null || !n.isObject() || !Js.isString(n.get("did"))) {
      return null;
    }
    JsonNode a = n.get("attestation");
    RequesterAttestation attestation = null;
    if (a != null && !a.isNull()) {
      if (!a.isObject()
          || !Js.isString(a.get("method"))
          || !Js.isString(a.get("issuer"))
          || !Js.isString(a.get("subject"))) {
        return null;
      }
      attestation = new RequesterAttestation(
          a.get("method").textValue(), a.get("issuer").textValue(), a.get("subject").textValue());
    }
    return new RequesterIdentity(n.get("did").textValue(), attestation);
  }

  private static ApprovalRequirement requirement(JsonNode n) {
    if (n == null || !n.isObject()) {
      return null;
    }
    JsonNode quorum = n.get("requiredApprovals");
    JsonNode hardware = n.get("requireHardwareKey");
    JsonNode fourEyes = n.get("requesterCannotApprove");
    JsonNode aaguids = n.get("allowedAaguids");
    JsonNode signerClass = n.get("signerClass");
    if (quorum == null || !quorum.canConvertToInt() || !Js.isInteger(quorum)
        || hardware == null || !hardware.isBoolean()
        || fourEyes == null || !fourEyes.isBoolean()
        || !Js.isStringArray(aaguids, false)
        || !Js.isString(signerClass)) {
      return null;
    }
    return new ApprovalRequirement(quorum.intValue(), hardware.booleanValue(), Js.strings(aaguids),
        fourEyes.booleanValue(), signerClass.textValue());
  }

  // ---------------------------------------------------------------------------------------------
  // Signature envelopes
  // ---------------------------------------------------------------------------------------------

  /**
   * Encode one approver's signature for the trip back to the relying party: {@code SIG1:} +
   * base64url of {@code {"did":…,"key":…,"sig":…,"alg":…}} — exactly that key order, no whitespace,
   * byte-identical to the reference ({@code alg} defaults to ES256; a null field is omitted, as
   * JSON.stringify omits an undefined one).
   */
  public static String encodeSignatureEnvelope(ApprovalWitness witness) {
    StringBuilder json = new StringBuilder("{");
    appendField(json, "did", witness.signerDid());
    appendField(json, "key", witness.signerPublicKey());
    appendField(json, "sig", witness.signature());
    appendField(json, "alg", witness.sigAlg() != null ? witness.sigAlg() : "ES256");
    json.append('}');
    return SIGNATURE_ENVELOPE_PREFIX + Base64Url.encode(json.toString().getBytes(StandardCharsets.UTF_8));
  }

  private static void appendField(StringBuilder json, String name, String value) {
    if (value == null) {
      return;
    }
    if (json.length() > 1) {
      json.append(',');
    }
    // stableStringify of a string is JSON.stringify's escaping exactly (RFC 8785).
    json.append('"').append(name).append("\":").append(Canonical.stableStringify(value));
  }

  /**
   * Decode a {@code SIG1:} envelope back into a witness. A missing {@code alg} defaults to ES256; a
   * missing or non-string {@code did}, {@code key} or {@code sig} refuses, as does an {@code alg}
   * that is present but not a non-empty string. Never throws: one bad paste discards that envelope,
   * not the whole ceremony.
   */
  public static SignatureEnvelopeResult decodeSignatureEnvelope(String envelope) {
    String trimmed = envelope == null ? "" : Js.trim(envelope);
    if (!trimmed.startsWith(SIGNATURE_ENVELOPE_PREFIX)) {
      return SignatureEnvelopeResult.refuse(
          "not a signature envelope (expected a " + SIGNATURE_ENVELOPE_PREFIX + " prefix)");
    }
    byte[] bytes = Base64Url.decodeStrict(trimmed.substring(SIGNATURE_ENVELOPE_PREFIX.length()));
    JsonNode compact = bytes == null ? null : Js.parse(new String(bytes, StandardCharsets.UTF_8));
    if (compact == null) {
      return SignatureEnvelopeResult.refuse(
          "signature envelope is not valid base64url JSON (truncated paste?)");
    }
    if (!compact.isObject()) {
      return SignatureEnvelopeResult.refuse("signature envelope is not a JSON object");
    }
    JsonNode did = compact.get("did");
    JsonNode key = compact.get("key");
    JsonNode sig = compact.get("sig");
    if (!Js.isNonEmptyString(did) || !Js.isNonEmptyString(key) || !Js.isNonEmptyString(sig)) {
      return SignatureEnvelopeResult.refuse("signature envelope is missing did, key or sig");
    }
    JsonNode alg = compact.get("alg");
    if (alg != null && !Js.isNonEmptyString(alg)) {
      return SignatureEnvelopeResult.refuse("signature envelope alg must be a string");
    }
    return new SignatureEnvelopeResult(true, null, new ApprovalWitness(
        did.textValue(),
        key.textValue(),
        sig.textValue(),
        alg == null ? "ES256" : alg.textValue(),
        null,
        null));
  }

  // ---------------------------------------------------------------------------------------------
  // Signing as an approver
  // ---------------------------------------------------------------------------------------------

  /** Loads the signing key lazily, so key problems are reported after the challenge checks. */
  @FunctionalInterface
  private interface KeyLoader {
    PrivateKey load() throws P256.KeyRefusal;
  }

  /**
   * Sign a {@code DIV1:} challenge as an approver — the library half of {@code intyga sign}.
   *
   * <p>Decodes first, so only a canonical {@code div-offline-intent} is ever signed; refuses an
   * unreadable or past {@code expiresAt}, a {@code signerDid} that is not a DID, and any key that is
   * not a P-256 private key. Signs ES256 over the canonical payload's UTF-8 bytes (IEEE P1363) and
   * returns a {@code SIG1:} envelope carrying the signer's SPKI. It SHOWS nothing: the caller MUST
   * have shown the decoded challenge to the approver and had them confirm the verification code with
   * the operator first (DIV §5a.8) — an approver who signs an opaque blob has approved nothing.
   *
   * <p>The SPKI is derived from the private key itself (a bare PKCS#8 key need not carry its public
   * half), using the provider's ECDH rather than hand-rolled point arithmetic on the secret. Use the
   * {@link KeyPair} overload for a key whose provider cannot do ECDH (some HSMs).
   *
   * @param asOf overrides "now" for the expiry check; null means the current instant
   */
  public static SignResult signChallengeEnvelope(String envelope, PrivateKey privateKey, String signerDid, Instant asOf) {
    return sign(envelope, () -> privateKey, null, signerDid, asOf);
  }

  /** As {@link #signChallengeEnvelope(String, PrivateKey, String, Instant)}, with the public key supplied. */
  public static SignResult signChallengeEnvelope(String envelope, KeyPair keyPair, String signerDid, Instant asOf) {
    return sign(envelope, () -> keyPair == null ? null : keyPair.getPrivate(),
        keyPair == null ? null : keyPair.getPublic(), signerDid, asOf);
  }

  /**
   * As {@link #signChallengeEnvelope(String, PrivateKey, String, Instant)}, from the bytes of a key
   * file: PEM when they contain a PEM header — PKCS#8 {@code PRIVATE KEY} or SEC1 {@code EC PRIVATE
   * KEY}, what {@code openssl ecparam -genkey} writes — otherwise DER PKCS#8, exactly how the
   * reference reads {@code intyga sign}'s key file.
   */
  public static SignResult signChallengeEnvelope(String envelope, byte[] keyFile, String signerDid, Instant asOf) {
    return sign(envelope, () -> P256.parse(keyFile), null, signerDid, asOf);
  }

  /**
   * As {@link #signChallengeEnvelope(String, PrivateKey, String, Instant)}, from a PEM key: PKCS#8
   * {@code PRIVATE KEY} or SEC1 {@code EC PRIVATE KEY}. Encrypted keys are refused.
   */
  public static SignResult signChallengeEnvelope(String envelope, String pemPrivateKey, String signerDid, Instant asOf) {
    return sign(envelope, () -> P256.parsePem(pemPrivateKey), null, signerDid, asOf);
  }

  private static SignResult sign(String envelope, KeyLoader loader, PublicKey suppliedPublic, String signerDid, Instant asOf) {
    DecodedChallengeResult decoded = decodeChallengeEnvelope(envelope);
    if (!decoded.ok()) {
      return SignResult.refuse(decoded.reason());
    }
    DecodedChallenge challenge = decoded.challenge();
    // A timestamp we cannot read is not one we can say is still valid (DIV §6.2).
    Long expiry = JsTime.parseMillis(challenge.expiresAt());
    if (expiry == null) {
      return SignResult.refuse("expiresAt is not a valid RFC3339 timestamp — refusing to sign");
    }
    if (expiry <= JsTime.nowOr(asOf).toEpochMilli()) {
      return SignResult.refuse("this challenge has already expired — ask for a fresh one");
    }
    if (signerDid == null || !signerDid.startsWith("did:")) {
      return SignResult.refuse("signerDid must be a DID");
    }
    PrivateKey key;
    try {
      PrivateKey loaded = loader.load();
      if (loaded == null) {
        return SignResult.refuse("could not read the private key: no key was given");
      }
      key = P256.requireP256(loaded);
    } catch (P256.KeyRefusal e) {
      return SignResult.refuse(e.getMessage().startsWith("the signing key")
          ? e.getMessage()
          : "could not read the private key: " + e.getMessage());
    }

    byte[] payload = challenge.canonicalPayload().getBytes(StandardCharsets.UTF_8);
    byte[] signature;
    try {
      signature = P256.sign(key, payload);
    } catch (GeneralSecurityException e) {
      return SignResult.refuse("could not sign with this key: " + e.getMessage());
    }
    PublicKey publicKey;
    if (suppliedPublic != null) {
      if (!(suppliedPublic instanceof ECPublicKey ec) || !P256.isP256(ec.getParams())
          || !P256.verify(suppliedPublic, payload, signature)) {
        return SignResult.refuse("the key pair's public key does not belong to its private key");
      }
      publicKey = suppliedPublic;
    } else {
      try {
        publicKey = P256.derivePublicKey(key, payload, signature);
      } catch (P256.KeyRefusal e) {
        return SignResult.refuse(e.getMessage());
      }
    }
    return new SignResult(true, null,
        encodeSignatureEnvelope(new ApprovalWitness(signerDid, P256.spkiBase64(publicKey),
            Base64.getEncoder().encodeToString(signature), "ES256", null, null)),
        challenge);
  }

  /**
   * The base64 SPKI of a P-256 private key — what an approver registers as their offline signing
   * key, and what {@link #signChallengeEnvelope} puts in the envelope.
   *
   * @throws IllegalArgumentException when the key is not a P-256 private key
   */
  public static String signingPublicKey(PrivateKey privateKey) {
    try {
      PrivateKey key = P256.requireP256(privateKey);
      byte[] probe = "intyga offline signing key".getBytes(StandardCharsets.UTF_8);
      return P256.spkiBase64(P256.derivePublicKey(key, probe, P256.sign(key, probe)));
    } catch (P256.KeyRefusal | GeneralSecurityException e) {
      throw new IllegalArgumentException(e.getMessage(), e);
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Receipt, redemption, the full ceremony
  // ---------------------------------------------------------------------------------------------

  /** Assemble the collected witnesses into a receipt the ordinary verifier can check. */
  public static ApprovalReceipt assembleOfflineReceipt(OfflineChallenge challenge, List<ApprovalWitness> witnesses) {
    return new ApprovalReceipt(
        challenge.canonicalPayload(),
        challenge.target(),
        challenge.actionType(),
        challenge.display(),
        challenge.params(),
        List.copyOf(witnesses),
        null,
        null,
        null,
        null,
        null,
        null,
        challenge.requester(),
        challenge.verificationCode());
  }

  /**
   * Run a full offline approval: load and verify the bundle, apply a delegation if one applies,
   * build the challenge, collect signatures out of band, recheck freshness, verify, buffer the
   * pending record, THEN redeem the nonce.
   *
   * <p>Verification is the verifier's own with the offline opt-in, so every ordinary control still
   * applies — target isolation, exact parameter binding, the signed quorum held to the bundle rule's
   * floor, four-eyes, the trusted signer set, expiry and the window cap. This widens WHEN an
   * approval may be obtained, never WHAT it authorizes. A proof that verifies but cannot be claimed
   * has already been used here, and is refused.
   */
  public static OfflineApprovalResult useOfflineApproval(OfflineAction expected, OfflineApprovalOptions opts) {
    Consumer<String> warn = opts.warn() != null ? opts.warn() : System.err::println;

    TrustBundleResult loaded = TrustBundle.load(opts.bundleDir(), opts.asOf());
    if (!loaded.ok()) {
      return OfflineApprovalResult.refuse(loaded.reason());
    }
    TrustBundle bundle = loaded.bundle();

    // The tier-3 path: only consulted when a delegation is actually present on disk, and verified
    // against the bundle's ORDINARY approver set — the people entitled to approve this action are
    // the ones who must have signed that entitlement away.
    VerifiedDelegation delegation = null;
    if (opts.delegationDir() != null) {
      FoundDelegation found = findDelegation(opts.delegationDir(), bundle, expected, opts.asOf());
      if (found.reason != null) {
        warn.accept("⚠ OFFLINE APPROVAL: " + found.reason);
      }
      delegation = found.delegation;
    }

    ChallengeResult built = createOfflineChallenge(ChallengeRequest.builder()
        .bundle(bundle)
        .target(expected.target())
        .actionType(expected.actionType())
        .display(expected.display())
        .params(expected.params())
        .requester(new RequesterIdentity(opts.requesterDid(), null))
        .windowMinutes(opts.windowMinutes())
        .asOf(opts.asOf())
        .delegation(delegation)
        .build());
    if (!built.ok()) {
      return OfflineApprovalResult.refuse(built.reason());
    }
    OfflineChallenge challenge = built.challenge();

    List<String> raw = opts.collectSignatures().collect(challenge);
    TrustBundleResult fresh = TrustBundle.checkFreshness(bundle, opts.asOf());
    if (!fresh.ok()) {
      return OfflineApprovalResult.refuse(fresh.reason());
    }
    if (raw == null || raw.isEmpty()) {
      return OfflineApprovalResult.refuse("no signatures were collected — the action is not approved");
    }

    List<ApprovalWitness> witnesses = new ArrayList<>();
    List<String> rejected = new ArrayList<>();
    for (String envelope : raw) {
      SignatureEnvelopeResult decoded = decodeSignatureEnvelope(envelope);
      if (!decoded.ok()) {
        rejected.add(decoded.reason());
        continue;
      }
      witnesses.add(decoded.witness());
    }
    if (witnesses.isEmpty()) {
      return OfflineApprovalResult.refuse("no usable signatures (" + String.join("; ", rejected) + ")");
    }

    ApprovalReceipt receipt = assembleOfflineReceipt(challenge, witnesses);
    // DIV §5 step 3d. The signed requirement is the signers' own statement, so it is held to the
    // bundle's ORDINARY rule, re-resolved here rather than read back from the challenge. Under a
    // delegation that is still the right floor: the delegated quorum was refused if lower.
    ResolvedRequirement ordinary = bundle.requirementFor(expected.actionType(), expected.display()).orElse(null);
    if (ordinary == null) {
      return OfflineApprovalResult.refuse("no unambiguous approval rule applies to this action");
    }
    VerifyOptions.Builder verifyOptions = VerifyOptions.builder().allowOffline(true).asOf(opts.asOf());
    if (delegation != null) {
      verifyOptions.delegation(delegation);
    }
    VerifyResult result = Verify.verifyApprovalReceipt(
        receipt,
        new Expected(
            expected.target(),
            challenge.nonce(),
            expected.actionType(),
            expected.params(),
            // Restricted to the approvers eligible for THIS action, so a valid signature from
            // someone outside the rule does not count. The one place offline keys count: this
            // receipt is a div-offline-intent.
            bundle.approverAnchor(challenge.approverDids(), AnchorPurpose.OFFLINE_INTENT),
            null,
            floorOf(ordinary.requirement())),
        verifyOptions.build());
    if (!result.ok()) {
      String detail = rejected.isEmpty() ? "" : " (also discarded: " + String.join("; ", rejected) + ")";
      return OfflineApprovalResult.refuse(result.reason() + detail);
    }

    RedemptionStore store =
        opts.store() != null ? opts.store() : new FileRedemptionStore(opts.bundleDir().resolve(REDEEMED_DIR));
    // Buffer BEFORE redeeming: a crash between the two must leave a pending record behind. A
    // spurious record reconciles harmlessly; the opposite order could leave a redeemed, executed
    // approval invisible to reconciliation forever.
    bufferForReconciliation(challenge, receipt, delegation, opts, warn);
    if (!store.redeem(challenge.nonce())) {
      clearPendingApproval(challenge.nonce(), opts.bundleDir(), opts.bufferDir());
      return OfflineApprovalResult.refuse("nonce " + challenge.nonce() + " has already been redeemed here");
    }
    warn.accept("⚠ OFFLINE APPROVAL USED — \"" + expected.display() + "\" (" + expected.actionType()
        + " on " + expected.target() + "). Approved out of band by " + String.join(", ", result.signers())
        + " because Intyga was unreachable"
        + (delegation != null ? ", under delegation " + delegation.nonce() : "") + ". Nonce "
        + challenge.nonce() + " is buffered for reconciliation; report it when connectivity returns.");
    return new OfflineApprovalResult(true, null, receipt, challenge.nonce(), List.copyOf(result.signers()),
        delegation != null ? delegation.nonce() : null);
  }

  private record FoundDelegation(VerifiedDelegation delegation, String reason) {}

  /**
   * Find and verify a delegation covering this exact action. A file that does not apply is
   * REPORTED, not silently skipped: a delegation the operator believes they hold but which does not
   * apply is exactly what they need told during an incident. Files are tried in name order.
   */
  private static FoundDelegation findDelegation(Path dir, TrustBundle bundle, OfflineAction expected, Instant asOf) {
    ResolvedRequirement resolved = bundle.requirementFor(expected.actionType(), expected.display()).orElse(null);
    if (resolved == null) {
      return new FoundDelegation(null,
          "no unambiguous ordinary approval rule applies to this delegation — export a fresh trust bundle");
    }
    List<Path> files = new ArrayList<>();
    try (DirectoryStream<Path> entries = Files.newDirectoryStream(dir, "*.json")) {
      for (Path p : entries) {
        files.add(p);
      }
    } catch (IOException | RuntimeException e) {
      return new FoundDelegation(null, null);
    }
    files.sort(BY_NAME);
    List<String> rejected = new ArrayList<>();
    ApprovalRequirement ordinary = resolved.requirement();
    for (Path file : files) {
      String name = String.valueOf(file.getFileName());
      ApprovalReceipt receipt;
      try {
        receipt = ApprovalReceipt.parse(Files.readString(file, StandardCharsets.UTF_8));
      } catch (IOException | RuntimeException e) {
        rejected.add(name + ": unreadable");
        continue;
      }
      DelegationVerification res = Verify.verifyDelegation(
          receipt,
          new Expected(
              expected.target(),
              null,
              expected.actionType(),
              expected.params(),
              // The ORDINARY approver set — not the delegates — and ordinary keys only: an offline
              // signing key must never seal a delegation.
              bundle.approverAnchor(resolved.approverDids(), AnchorPurpose.ORDINARY),
              null,
              // DIV §5 step 3d / §5a.5: the sealing requirement may not be weaker than the rule.
              floorOf(ordinary)),
          VerifyOptions.builder().asOf(asOf).build());
      if (!res.result().ok() || res.delegation() == null) {
        rejected.add(name + ": " + res.result().reason());
        continue;
      }
      // The verification above binds this requirement to the seal's signatures. The floor does not
      // cover allowedAaguids, so that comparison stays here: an eligible person must not seal with
      // a weaker ceremony than the ordinary rule, nor drop a hardware/four-eyes/model restriction.
      JsonNode sealedPayload = Js.parse(receipt.canonicalPayload());
      ApprovalRequirement sealed =
          sealedPayload == null || !sealedPayload.isObject() ? null : requirement(sealedPayload.get("requirement"));
      boolean weakerAaguids = !ordinary.allowedAaguids().isEmpty()
          && (sealed == null || sealed.allowedAaguids().isEmpty()
              || !ordinary.allowedAaguids().containsAll(sealed.allowedAaguids()));
      if (sealed == null
          || sealed.requiredApprovals() < ordinary.requiredApprovals()
          || (ordinary.requireHardwareKey() && !sealed.requireHardwareKey())
          || (ordinary.requesterCannotApprove() && !sealed.requesterCannotApprove())
          || weakerAaguids) {
        rejected.add(name + ": delegation sealing requirement is weaker than the ordinary approval rule");
        continue;
      }
      return new FoundDelegation(res.delegation(), null);
    }
    return new FoundDelegation(null,
        rejected.isEmpty() ? null : "no delegation applies (" + String.join("; ", rejected) + ")");
  }

  /** The DIV §5 step 3d floor a bundle rule imposes on a signed requirement. */
  private static RequirementFloor floorOf(ApprovalRequirement rule) {
    return new RequirementFloor(rule.requiredApprovals(), rule.requesterCannotApprove(), rule.requireHardwareKey());
  }

  // ---------------------------------------------------------------------------------------------
  // Pending records
  // ---------------------------------------------------------------------------------------------

  private static Path bufferDir(Path bundleDir, Path bufferDir) {
    return bufferDir != null ? bufferDir : bundleDir.resolve(PENDING_DIR);
  }

  /**
   * Record the approval so it can be reported when the gateway is reachable again. Best effort by
   * design: a buffering failure must never block the emergency action the operator is mid-incident
   * on. It is warned about loudly instead.
   */
  private static void bufferForReconciliation(OfflineChallenge challenge, ApprovalReceipt receipt,
      VerifiedDelegation delegation, OfflineApprovalOptions opts, Consumer<String> warn) {
    Path dir = bufferDir(opts.bundleDir(), opts.bufferDir());
    ObjectNode record = Js.JSON.createObjectNode();
    record.put("nonce", challenge.nonce());
    record.put("target", challenge.target());
    record.put("actionType", challenge.actionType());
    record.put("display", challenge.display());
    record.put("usedAt", JsTime.iso(JsTime.nowOr(null)));
    record.set("receipt", receiptJson(receipt));
    if (delegation != null && delegation.nonce() != null) {
      record.put("delegationNonce", delegation.nonce());
    }
    try {
      if (!isPathSafeNonce(challenge.nonce())) {
        throw new IOException("nonce is not a safe path segment");
      }
      SecureFiles.ensurePrivateDir(dir);
      SecureFiles.writePrivateFile(dir.resolve(challenge.nonce() + ".json"),
          Js.JSON.writerWithDefaultPrettyPrinter().writeValueAsString(record) + "\n");
    } catch (IOException | RuntimeException e) {
      warn.accept("⚠ OFFLINE APPROVAL: could not buffer " + challenge.nonce() + " for reconciliation ("
          + e.getMessage() + "). Report this manually — an unreported approval is indistinguishable"
          + " from an unauthorized one.");
    }
  }

  /**
   * The offline approvals buffered by {@link #useOfflineApproval} but not yet reported, in file-name
   * order — {@link #readPendingApprovals}' readable records.
   *
   * @param bufferDir null means {@code <bundleDir>/.pending}
   */
  public static List<PendingApproval> pendingApprovals(Path bundleDir, Path bufferDir) {
    return readPendingApprovals(bundleDir, bufferDir).records();
  }

  /**
   * Read the buffered records, and name the files that could not be read (not JSON, or no string
   * {@code nonce}). One unreadable record must not hide the rest — and must not be skipped either:
   * a record nobody can read is still an approval nobody has reported, so reconciliation counts it
   * as a failure.
   *
   * @param bufferDir null means {@code <bundleDir>/.pending}
   */
  public static PendingApprovals readPendingApprovals(Path bundleDir, Path bufferDir) {
    Path dir = bufferDir(bundleDir, bufferDir);
    List<Path> files = new ArrayList<>();
    try (DirectoryStream<Path> entries = Files.newDirectoryStream(dir, "*.json")) {
      for (Path p : entries) {
        files.add(p);
      }
    } catch (IOException | RuntimeException e) {
      return new PendingApprovals(List.of(), List.of());
    }
    files.sort(BY_NAME);
    List<PendingApproval> records = new ArrayList<>();
    List<String> unreadable = new ArrayList<>();
    for (Path file : files) {
      String name = String.valueOf(file.getFileName());
      JsonNode n;
      try {
        n = Js.parse(Files.readString(file, StandardCharsets.UTF_8));
      } catch (IOException | RuntimeException e) {
        n = null;
      }
      if (n == null || !n.isObject() || !Js.isString(n.get("nonce"))) {
        unreadable.add(name);
        continue;
      }
      records.add(new PendingApproval(
          Js.text(n.get("nonce")),
          Js.text(n.get("target")),
          Js.text(n.get("actionType")),
          Js.text(n.get("display")),
          Js.text(n.get("usedAt")),
          n.get("receipt"),
          Js.text(n.get("delegationNonce"))));
    }
    return new PendingApprovals(List.copyOf(records), List.copyOf(unreadable));
  }

  /**
   * Clear a buffered approval — only on a definite acknowledgement from the gateway. Dropping it on
   * a network error would turn a retryable report into a permanently unreported approval. A nonce
   * that is not a safe path segment is ignored: it must never name a path outside the buffer.
   *
   * @param bufferDir null means {@code <bundleDir>/.pending}
   */
  public static void clearPendingApproval(String nonce, Path bundleDir, Path bufferDir) {
    if (!isPathSafeNonce(nonce)) {
      return;
    }
    try {
      Files.deleteIfExists(bufferDir(bundleDir, bufferDir).resolve(nonce + ".json"));
    } catch (IOException | RuntimeException e) {
      // Already gone, or not ours to remove. Nothing to do.
    }
  }

  /**
   * A receipt as the JSON the reference writes and sends: absent fields omitted (as
   * JSON.stringify omits undefined), {@code requester.attestation} kept even when null — it is
   * signed. {@code ApprovalReceipt.parse} reads it back.
   */
  public static ObjectNode receiptJson(ApprovalReceipt receipt) {
    ObjectNode o = Js.JSON.createObjectNode();
    putIfSet(o, "canonicalPayload", receipt.canonicalPayload());
    putIfSet(o, "target", receipt.target());
    putIfSet(o, "actionType", receipt.actionType());
    putIfSet(o, "actionDescription", receipt.actionDescription());
    if (receipt.params() != null) {
      o.set("params", Js.JSON.valueToTree(receipt.params()));
    }
    if (receipt.signatures() != null) {
      ArrayNode sigs = o.putArray("signatures");
      for (ApprovalWitness w : receipt.signatures()) {
        ObjectNode s = sigs.addObject();
        putIfSet(s, "signerDid", w.signerDid());
        putIfSet(s, "signerPublicKey", w.signerPublicKey());
        putIfSet(s, "signature", w.signature());
        putIfSet(s, "sigAlg", w.sigAlg());
        putIfSet(s, "authenticatorData", w.authenticatorData());
        putIfSet(s, "clientDataJSON", w.clientDataJSON());
      }
    }
    putIfSet(o, "signerDid", receipt.signerDid());
    putIfSet(o, "signerPublicKey", receipt.signerPublicKey());
    putIfSet(o, "signature", receipt.signature());
    putIfSet(o, "sigAlg", receipt.sigAlg());
    putIfSet(o, "authenticatorData", receipt.authenticatorData());
    putIfSet(o, "clientDataJSON", receipt.clientDataJSON());
    if (receipt.requester() != null) {
      ObjectNode r = o.putObject("requester");
      r.put("did", receipt.requester().did());
      RequesterAttestation a = receipt.requester().attestation();
      if (a == null) {
        r.putNull("attestation");
      } else {
        ObjectNode an = r.putObject("attestation");
        an.put("method", a.method());
        an.put("issuer", a.issuer());
        an.put("subject", a.subject());
      }
    }
    putIfSet(o, "verificationCode", receipt.verificationCode());
    return o;
  }

  private static void putIfSet(ObjectNode o, String name, String value) {
    if (value != null) {
      o.put(name, value);
    }
  }

  private static byte[] sha256(byte[] bytes) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(bytes);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is unavailable", e);
    }
  }
}
