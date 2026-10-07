package com.intyga.sdk.offline;

import com.fasterxml.jackson.databind.JsonNode;
import com.intyga.verify.ApproverTrustAnchor;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The customer-authored trust-anchor file — the relying party's pinning (DIV §4.4.6): the approver
 * identities that may sign and, for each DID, the public keys that speak for it. Port of {@code
 * packages/sdk/src/trust-anchor.ts}.
 *
 * <p>Unlike the {@link TrustBundle}, which travels through the gateway and is therefore
 * gateway-SIGNED, this file carries no signature: adopting it into your configuration is itself the
 * act of trust, like pinning a CA bundle. Self-certifying entries ({@code did:intyga:key:…}) may list
 * no keys in an online anchor — the DID commits to the key the receipt carries.
 *
 * @param purpose always set after parsing; a file with no {@code purpose} is {@link
 *     TrustAnchorPurpose#ONLINE}
 * @param epoch monotonic export counter; detects an older copy, carries no cryptographic weight
 * @param label what the export was scoped to; display only; may be null
 * @param approvers each approver with every key bound to them at export ({@code offlinePublicKeys}
 *     is always null here)
 * @param webauthn the approval console's origin and RP ID, or null when the file omits them
 * @param exportedAt may be null
 */
public record TrustAnchorFile(
    TrustAnchorPurpose purpose,
    long epoch,
    String label,
    List<BundleApprover> approvers,
    WebAuthnExpectation webauthn,
    String exportedAt) {

  /** The file's {@code type}. */
  public static final String TYPE = "intyga-trust-anchor";

  /** The self-certifying DID prefix; such a DID's key travels in the receipt and is checked by hash. */
  static final String SELF_CERTIFYING_DID_PREFIX = "did:intyga:key:";

  private static final Pattern BASE64ISH = Pattern.compile("[A-Za-z0-9+/_-]+={0,2}");
  private static final Pattern HTTP_ORIGIN = Pattern.compile("^https?://.*", Pattern.DOTALL);
  private static final long MAX_SAFE_INTEGER = 9007199254740991L;

  /** The WebAuthn expectations of the approval console the approvers sign in. */
  public record WebAuthnExpectation(String origin, String rpId) {}

  /** {@link #parse(String, TrustAnchorPurpose)} for an {@link TrustAnchorPurpose#ONLINE} verifier. */
  public static TrustAnchorFile parse(String jsonText) {
    return parse(jsonText, TrustAnchorPurpose.ONLINE);
  }

  /**
   * Parse and validate a trust-anchor file.
   *
   * @param purpose what the CALLER is about to verify; the file must say the same — an offline
   *     anchor handed to an online verifier, or the reverse, is refused rather than trusted
   * @throws InvalidTrustAnchorException naming the single problem found
   */
  public static TrustAnchorFile parse(String jsonText, TrustAnchorPurpose purpose) {
    TrustAnchorPurpose expected = purpose == null ? TrustAnchorPurpose.ONLINE : purpose;
    JsonNode obj = Js.parse(jsonText);
    if (obj == null) {
      throw new InvalidTrustAnchorException("not valid JSON");
    }
    if (!obj.isObject()) {
      throw new InvalidTrustAnchorException("root must be an object");
    }
    if (!TYPE.equals(Js.text(obj.get("type")))) {
      throw new InvalidTrustAnchorException("type must be \"" + TYPE + "\" — a div-trust-bundle JWS"
          + " (offline approval) is a different, gateway-signed artifact and cannot be used here");
    }
    if (!Js.isNumberOne(obj.get("v"))) {
      throw new InvalidTrustAnchorException("unsupported version " + show(obj.get("v")) + " (expected 1)");
    }
    JsonNode rawPurpose = obj.get("purpose");
    TrustAnchorPurpose filePurpose;
    if (rawPurpose == null) {
      filePurpose = TrustAnchorPurpose.ONLINE;
    } else if ("online".equals(Js.text(rawPurpose))) {
      filePurpose = TrustAnchorPurpose.ONLINE;
    } else if ("offline".equals(Js.text(rawPurpose))) {
      filePurpose = TrustAnchorPurpose.OFFLINE;
    } else {
      throw new InvalidTrustAnchorException(
          "purpose must be \"online\" or \"offline\", got " + show(rawPurpose));
    }
    if (filePurpose != expected) {
      throw new InvalidTrustAnchorException("this is an " + filePurpose.wire()
          + " anchor, but it is being loaded to verify " + expected.wire()
          + " approvals — export the " + expected.wire() + " anchor instead");
    }
    JsonNode epoch = obj.get("epoch");
    if (!Js.isInteger(epoch) || epoch.doubleValue() < 0) {
      throw new InvalidTrustAnchorException("epoch must be a non-negative integer");
    }
    // Java holds the counter in a long; JavaScript would keep a larger one as an inexact double.
    if (!Js.isSafeInteger(epoch)) {
      throw new InvalidTrustAnchorException("epoch must be at most " + MAX_SAFE_INTEGER);
    }
    JsonNode label = obj.get("label");
    if (label != null && !label.isTextual()) {
      throw new InvalidTrustAnchorException("label must be a string");
    }
    JsonNode exportedAt = obj.get("exportedAt");
    if (exportedAt != null && !exportedAt.isTextual()) {
      throw new InvalidTrustAnchorException("exportedAt must be a string");
    }

    JsonNode approvers = obj.get("approvers");
    if (approvers == null || !approvers.isArray() || approvers.isEmpty()) {
      throw new InvalidTrustAnchorException(
          "approvers must be a non-empty array — an empty anchor would trust nobody");
    }
    Set<String> seen = new HashSet<>();
    List<BundleApprover> parsed = new ArrayList<>();
    for (JsonNode entry : approvers) {
      if (entry == null || !(entry.isObject() || entry.isArray())) {
        throw new InvalidTrustAnchorException("every approvers[] entry must be an object");
      }
      JsonNode didNode = entry.get("did");
      String did = Js.text(didNode);
      if (did == null || !did.startsWith("did:")) {
        throw new InvalidTrustAnchorException(
            "approver did " + show(didNode) + " must be a string starting with \"did:\"");
      }
      if (!seen.add(did)) {
        throw new InvalidTrustAnchorException("duplicate approver did " + did);
      }
      JsonNode publicKeys = entry.get("publicKeys");
      if (publicKeys == null || !publicKeys.isArray()) {
        throw new InvalidTrustAnchorException("approver " + did + ": publicKeys must be an array");
      }
      List<String> keys = new ArrayList<>();
      for (JsonNode key : publicKeys) {
        if (!key.isTextual() || !isBase64(key.textValue())) {
          throw new InvalidTrustAnchorException(
              "approver " + did + ": every publicKeys[] entry must be a base64 SPKI or COSE key");
        }
        keys.add(key.textValue());
      }
      // A stable DID with no keys can never satisfy verification — refuse at load, where the
      // problem is diagnosable. Self-certifying DIDs are the deliberate exception online; an
      // offline anchor has none: a DID commits to its ONLINE key, not to an offline signing key.
      if (keys.isEmpty() && filePurpose == TrustAnchorPurpose.OFFLINE) {
        throw new InvalidTrustAnchorException(
            "approver " + did + " has no publicKeys — an offline anchor must pin every offline key");
      }
      if (keys.isEmpty() && !did.startsWith(SELF_CERTIFYING_DID_PREFIX)) {
        throw new InvalidTrustAnchorException("approver " + did + " has no publicKeys and is not"
            + " self-certifying (" + SELF_CERTIFYING_DID_PREFIX + "…) — a receipt from them could never verify");
      }
      parsed.add(new BundleApprover(did, List.copyOf(keys), null));
    }

    WebAuthnExpectation webauthn = null;
    JsonNode w = obj.get("webauthn");
    if (w != null) {
      if (!(w.isObject() || w.isArray())) {
        throw new InvalidTrustAnchorException("webauthn must be an object");
      }
      String origin = Js.text(w.get("origin"));
      if (origin == null || !HTTP_ORIGIN.matcher(origin).matches()) {
        throw new InvalidTrustAnchorException("webauthn.origin must be an http(s) origin string");
      }
      String rpId = Js.text(w.get("rpId"));
      if (rpId == null || rpId.isEmpty()) {
        throw new InvalidTrustAnchorException("webauthn.rpId must be a non-empty string");
      }
      webauthn = new WebAuthnExpectation(origin, rpId);
    }

    return new TrustAnchorFile(
        filePurpose,
        epoch.longValue(),
        Js.text(label),
        List.copyOf(parsed),
        webauthn,
        Js.text(exportedAt));
  }

  /**
   * The DID → keys mapping: one identity per approver however many keys they hold. {@code
   * limitToDids} narrows (e.g. to one rule's approvers) without widening — a DID not in the file
   * resolves to nothing. A keyless self-certifying entry resolves to null, as in the reference.
   */
  public ApproverDirectory approverDirectory(List<String> limitToDids) {
    Map<String, List<String>> byDid = new LinkedHashMap<>();
    for (BundleApprover a : approvers) {
      if (limitToDids == null || limitToDids.contains(a.did())) {
        byDid.put(a.did(), a.publicKeys());
      }
    }
    return new ApproverDirectory(byDid);
  }

  /** {@code trustAnchorApprovers(file, limitToDids)}: the verifier's DID-mode anchor. */
  public ApproverTrustAnchor approverAnchor(List<String> limitToDids) {
    return approverDirectory(limitToDids).toTrustAnchor();
  }

  /**
   * The reference's check: base64 or base64url characters with at most two trailing {@code =}, and
   * at least one decoded byte — which, for that alphabet, means at least two significant characters.
   */
  private static boolean isBase64(String s) {
    if (!BASE64ISH.matcher(s).matches()) {
      return false;
    }
    int significant = s.length();
    while (significant > 0 && s.charAt(significant - 1) == '=') {
      significant--;
    }
    return significant >= 2;
  }

  /** {@code JSON.stringify} of a value for a message; {@code undefined} for an absent one. */
  private static String show(JsonNode n) {
    return n == null ? "undefined" : n.toString();
  }
}
