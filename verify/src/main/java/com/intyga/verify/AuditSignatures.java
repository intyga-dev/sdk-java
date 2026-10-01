package com.intyga.verify;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import java.util.Map;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

/** Signature over committed bytes, not an approval-policy, hardware or quorum verdict. */
public final class AuditSignatures {
  public record Policy(Map<String,List<String>> trustedSigners, String expectedOrigin, String expectedRpId) {}
  public record Check(String status, String reason, boolean trusted) {}
  public record Entry(String seq, String status, String reason, boolean trusted) {}
  static Check unchecked() { return result("not_checked", "Content not verified or unavailable."); }
  private static Check result(String status,String reason) { return new Check(status,reason,false); }
  private static boolean present(String s) { return s!=null && !s.isEmpty(); }
  public static Check verify(Ledger.AuditLeaf c, Policy p) {
    if (c==null) return unchecked();
    String alg=c.sigAlg();
    if (!present(alg) && (present(c.signature()) || present(c.signedPayload()) || present(c.signerPublicKey()))) return result("not_checked", "Signature algorithm is missing.");
    if (!present(alg) || alg.equals("AUTO_APPROVED")) return result("not_applicable", "No human signature is declared.");
    if (!alg.equals("ES256") && !alg.equals("WEBAUTHN")) return result("not_checked", "Unsupported signature algorithm.");
    if (!present(c.signature()) || !present(c.signedPayload())) return result("not_checked", "Signature or signed payload is missing.");
    if (p==null && alg.equals("ES256")) {
      if (!present(c.signerPublicKey())) return result("not_checked", "Signer public key is missing.");
      return Dewp.verifyEmbeddedSignature(c) ? result("verified", "Signature valid under embedded key; signer identity is not established.") : result("invalid", "Signature does not verify.");
    }
    List<String> keys=p!=null && p.trustedSigners()!=null && c.signerDid()!=null ? p.trustedSigners().get(c.signerDid()) : null;
    if (keys==null || keys.isEmpty() || keys.stream().anyMatch(k->!present(k))) return result("not_checked", "No caller-trusted key for this signer.");
    if (alg.equals("WEBAUTHN") && (!present(p.expectedOrigin()) || !present(p.expectedRpId()))) return result("not_checked", "Caller-selected WebAuthn origin and RP ID are required.");
    JsonNode meta=Records.JSON.valueToTree(c.metadata());
    JsonNode w=meta.path("webauthn");
    if (alg.equals("WEBAUTHN") && (!w.path("authenticatorData").isTextual() || !present(w.path("authenticatorData").asText()) || !w.path("clientDataJSON").isTextual() || !present(w.path("clientDataJSON").asText()))) return result("not_checked", "WebAuthn authenticatorData or clientDataJSON is missing.");
    for (String key:keys) try {
      boolean valid;
      if (alg.equals("ES256")) valid=Ecdsa.verifySignature(Ecdsa.parseSpkiP256(Base64.getDecoder().decode(key)), c.signedPayload().getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(c.signature()));
      else {
        var witness=new ApprovalWitness(c.signerDid(),key,c.signature(),alg,w.path("authenticatorData").asText(),w.path("clientDataJSON").asText());
        var receipt=new ApprovalReceipt(c.signedPayload(),null,null,null,null,null,null,null,null,null,null,null,null,null);
        valid=WebAuthnSupport.verifyWitness(witness,key,receipt,VerifyOptions.builder().expectedOrigin(p.expectedOrigin()).expectedRpId(p.expectedRpId()).requireUserVerification(true).build()).isEmpty();
      }
      if (valid) return new Check("verified", "Signature valid under caller-trusted signer key.",true);
    } catch (Exception ignored) { /* malformed keys/assertions never verify */ }
    return result("invalid", "Signature or WebAuthn assertion does not verify under caller trust.");
  }
  private AuditSignatures() {}
}
