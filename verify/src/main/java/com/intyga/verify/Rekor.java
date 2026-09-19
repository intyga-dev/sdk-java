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

  private Rekor() {}
}
