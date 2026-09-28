package com.intyga.verify;

import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/** Offline verification of Sigstore Rekor SET evidence carried by a DEWP anchor. */
public final class Rekor {
  public record Verification(boolean ok, String reason, Long logIndex, String logID, Long integratedTime) {
    static Verification refuse(String r) { return new Verification(false, r, null, null, null); }
  }

  public static String payloadHashFor(Ledger.SignedAnchor anchor) {
    try {
      byte[] digest = java.util.HexFormat.of().parseHex(Ledger.anchorDigestHex(anchor.anchorInput()));
      return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(digest));
    } catch (Exception e) { throw new IllegalStateException(e); }
  }

  public static Verification verifyAnchor(Ledger.SignedAnchor anchor, String rekorPublicKey) {
    return verifyAnchor(anchor, rekorPublicKey, null);
  }

  /**
   * As {@link #verifyAnchor(Ledger.SignedAnchor, String)}, and when {@code submitterKeys} is non-empty
   * the hashedrekord must have been submitted under one of those producer keys with a valid ES256
   * signature over the anchor digest. Rekor logs a submission under ANY key, so without this anyone
   * who can compute the digest (built from public fields) can have it logged.
   */
  public static Verification verifyAnchor(Ledger.SignedAnchor anchor, String rekorPublicKey,
      java.util.List<String> submitterKeys) {
    if (anchor.evidence() == null) return Verification.refuse("rekor anchor carries no evidence");
    JsonNode e;
    try { e = Records.JSON.readTree(Base64.getDecoder().decode(anchor.evidence())); }
    catch (Exception ex) { return Verification.refuse("rekor evidence is not valid base64 JSON"); }
    String body = e.path("body").asText(""); String set = e.path("verification").path("signedEntryTimestamp").asText("");
    if (body.isEmpty()) return Verification.refuse("rekor evidence carries no entry body");
    if (set.isEmpty()) return Verification.refuse("rekor evidence carries no signedEntryTimestamp (SET)");
    if (!e.path("logIndex").canConvertToLong() || !e.path("integratedTime").canConvertToLong())
      return Verification.refuse("rekor evidence is missing logIndex/integratedTime");
    try {
      JsonNode b = Records.JSON.readTree(Base64.getDecoder().decode(body));
      if (!"hashedrekord".equals(b.path("kind").asText()) || !"sha256".equals(b.path("spec").path("data").path("hash").path("algorithm").asText()))
        return Verification.refuse("rekor entry body is not a readable hashedrekord");
      String logged = b.path("spec").path("data").path("hash").path("value").asText().toLowerCase();
      if (!logged.equals(payloadHashFor(anchor))) return Verification.refuse("rekor entry attests a different payload");
      if (submitterKeys != null && !submitterKeys.isEmpty() && !submittedByPinnedKey(b, anchor, submitterKeys))
        return Verification.refuse("rekor entry was not submitted under a pinned producer key with a valid signature over this anchor");
      PublicKey key = Ledger.parseAnchorPublicKey(rekorPublicKey, "ES256");
      if (key == null) return Verification.refuse("rekor public key is not an EC P-256 key");
      Map<String,Object> payload = new LinkedHashMap<>(); payload.put("body", body);
      payload.put("integratedTime", e.path("integratedTime").longValue()); payload.put("logID", e.path("logID").asText());
      payload.put("logIndex", e.path("logIndex").longValue());
      Signature v = Signature.getInstance("SHA256withECDSA"); v.initVerify(key);
      v.update(Canonical.stableStringify(payload).getBytes(StandardCharsets.UTF_8));
      if (!v.verify(Base64.getDecoder().decode(set))) return Verification.refuse("rekor SET does not verify under the supplied log key");
      return new Verification(true, null, e.path("logIndex").longValue(), e.path("logID").asText(), e.path("integratedTime").longValue());
    } catch (Exception ex) { return Verification.refuse("rekor SET verification failed: " + ex.getMessage()); }
  }

  /** hashedrekord {@code publicKey.content} is base64 of the PEM text. */
  private static boolean submittedByPinnedKey(JsonNode body, Ledger.SignedAnchor anchor, java.util.List<String> pinned) {
    try {
      JsonNode sig = body.path("spec").path("signature");
      String pem = new String(Base64.getDecoder().decode(sig.path("publicKey").path("content").asText("")), StandardCharsets.UTF_8);
      PublicKey submitted = Ledger.parseAnchorPublicKey(pem, "ES256");
      if (submitted == null) return false;
      boolean match = false;
      for (String k : pinned) {
        PublicKey p = Ledger.parseAnchorPublicKey(k, "ES256");
        if (p != null && java.util.Arrays.equals(p.getEncoded(), submitted.getEncoded())) { match = true; break; }
      }
      if (!match) return false;
      byte[] digest = java.util.HexFormat.of().parseHex(Ledger.anchorDigestHex(anchor.anchorInput()));
      return Ecdsa.verifySignature(Ecdsa.parseSpkiP256(submitted.getEncoded()), digest,
          Base64.getDecoder().decode(sig.path("content").asText("")));
    } catch (Exception e) { return false; }
  }

  private Rekor() {}
}
