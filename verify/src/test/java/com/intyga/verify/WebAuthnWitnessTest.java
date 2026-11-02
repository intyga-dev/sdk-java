package com.intyga.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * {@link Verify#verifyWebAuthnWitness} against the shared golden assertion (webauthn-vector.json),
 * mirroring the reference's tests (packages/verify/src/webauthn-vector.test.ts) and Go's
 * webauthn_witness_test.go.
 */
class WebAuthnWitnessTest {
  private static final JsonNode V = load();
  private static final String ORIGIN = V.get("origin").asText();
  private static final String RP_ID = V.get("rpId").asText();
  private static final String NEED_EXPECTATIONS = "a WebAuthn witness requires expectedOrigin and"
      + " expectedRpId — without them an assertion from any relying party would verify";

  private static JsonNode load() {
    try {
      return Records.JSON.readTree(Files.readString(Path.of("vectors", "webauthn-vector.json")));
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private static WebAuthnWitness golden() {
    JsonNode r = V.get("receipt");
    return new WebAuthnWitness(r.get("canonicalPayload").asText(), r.get("signerPublicKey").asText(),
        r.get("authenticatorData").asText(), r.get("clientDataJSON").asText(), r.get("signature").asText());
  }

  private static WebAuthnWitness with(WebAuthnWitness w, String field, String value) {
    return new WebAuthnWitness(
        field.equals("signedPayload") ? value : w.signedPayload(),
        field.equals("publicKey") ? value : w.publicKey(),
        field.equals("authenticatorData") ? value : w.authenticatorData(),
        field.equals("clientDataJSON") ? value : w.clientDataJSON(),
        field.equals("signature") ? value : w.signature());
  }

  private static final WebAuthnWitnessExpectation EXP = new WebAuthnWitnessExpectation(ORIGIN, RP_ID);

  private static void refused(WebAuthnWitness w, WebAuthnWitnessExpectation e, String want) {
    VerifyResult r = Verify.verifyWebAuthnWitness(w, e);
    assertFalse(r.ok(), "expected refusal: " + want);
    assertEquals(want, r.reason());
  }

  @Test
  void goldenVerifiesUnderCoseOrSpkiAndAnOriginList() throws Exception {
    VerifyResult r = Verify.verifyWebAuthnWitness(golden(), EXP);
    assertTrue(r.ok(), r.reason());
    byte[] cose = WebAuthnSupport.decodeNodeBase64(golden().publicKey());
    String spki = Base64.getEncoder().encodeToString(WebAuthnSupport.parseCoseP256Key(cose).getEncoded());
    r = Verify.verifyWebAuthnWitness(with(golden(), "publicKey", spki), EXP);
    assertTrue(r.ok(), "same key as SPKI: " + r.reason());
    r = Verify.verifyWebAuthnWitness(golden(),
        new WebAuthnWitnessExpectation(List.of("https://other.example", ORIGIN), RP_ID));
    assertTrue(r.ok(), "origin list: " + r.reason());
    r = Verify.verifyWebAuthnWitness(golden(), new WebAuthnWitnessExpectation(List.of(ORIGIN), RP_ID, null, true));
    assertTrue(r.ok(), "allowCrossOrigin must not refuse a same-origin assertion: " + r.reason());
  }

  @Test
  void bindsPayloadKeyOriginRpAndSignature() throws Exception {
    refused(with(golden(), "signedPayload", golden().signedPayload() + " "), EXP,
        "clientDataJSON challenge does not match canonical payload");

    KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
    ec.initialize(new ECGenParameterSpec("secp256r1"));
    String other = Base64.getEncoder().encodeToString(ec.generateKeyPair().getPublic().getEncoded());
    refused(with(golden(), "publicKey", other), EXP,
        "WebAuthn signature does not verify against the trusted signer key");

    KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
    rsa.initialize(2048);
    String rsaKey = Base64.getEncoder().encodeToString(rsa.generateKeyPair().getPublic().getEncoded());
    refused(with(golden(), "publicKey", rsaKey), EXP, "WebAuthn verification failed: public key is not a P-256 key");

    refused(golden(), new WebAuthnWitnessExpectation("https://evil.example.com", RP_ID),
        "assertion origin does not match expectedOrigin");
    refused(golden(), new WebAuthnWitnessExpectation(ORIGIN, "evil.example.com"),
        "authenticatorData rpIdHash does not match expectedRpId");

    byte[] sig = WebAuthnSupport.decodeNodeBase64(golden().signature());
    sig[sig.length - 1] ^= 0x01;
    assertFalse(Verify.verifyWebAuthnWitness(
        with(golden(), "signature", Base64.getEncoder().encodeToString(sig)), EXP).ok());
  }

  @Test
  void failsClosedAndNeverThrows() {
    for (WebAuthnWitnessExpectation e : List.of(
        new WebAuthnWitnessExpectation(List.of(""), RP_ID),
        new WebAuthnWitnessExpectation(List.of(), RP_ID),
        new WebAuthnWitnessExpectation(ORIGIN, ""),
        new WebAuthnWitnessExpectation((List<String>) null, null))) {
      refused(golden(), e, NEED_EXPECTATIONS);
    }
    refused(golden(), null, NEED_EXPECTATIONS);
    for (String field : List.of("signedPayload", "publicKey", "authenticatorData", "clientDataJSON", "signature")) {
      refused(with(golden(), field, ""), EXP, "WebAuthn witness missing " + field);
      refused(with(golden(), field, null), EXP, "WebAuthn witness missing " + field);
    }
    refused(null, EXP, "WebAuthn witness missing signedPayload");
    WebAuthnWitness garbage = new WebAuthnWitness(golden().signedPayload(), "AAAA", "AAAA", "e30=", golden().signature());
    assertFalse(Verify.verifyWebAuthnWitness(garbage, EXP).ok());
    for (String junk : List.of("!!!!", "bnVsbA", "WzFd", "eyJ0eXBlIjo1fQ", "\u0000")) {
      assertFalse(Verify.verifyWebAuthnWitness(with(golden(), "clientDataJSON", junk), EXP).ok(), junk);
      assertFalse(Verify.verifyWebAuthnWitness(with(golden(), "authenticatorData", junk), EXP).ok(), junk);
      assertFalse(Verify.verifyWebAuthnWitness(with(golden(), "publicKey", junk), EXP).ok(), junk);
    }
  }

  /** The golden signature re-encoded as raw r‖s is refused on the standalone and the receipt path. */
  @Test
  void webAuthnSignatureIsDerOnly() throws Exception {
    byte[] der = WebAuthnSupport.decodeNodeBase64(golden().signature());
    // SEQUENCE { INTEGER r, INTEGER s }, short-form lengths for P-256.
    int rLen = der[3];
    BigInteger r = new BigInteger(1, Arrays.copyOfRange(der, 4, 4 + rLen));
    int sLen = der[5 + rLen];
    BigInteger s = new BigInteger(1, Arrays.copyOfRange(der, 6 + rLen, 6 + rLen + sLen));
    byte[] raw = new byte[64];
    byte[] rb = r.toByteArray(), sb = s.toByteArray();
    System.arraycopy(rb, Math.max(0, rb.length - 32), raw, 32 - Math.min(32, rb.length), Math.min(32, rb.length));
    System.arraycopy(sb, Math.max(0, sb.length - 32), raw, 64 - Math.min(32, sb.length), Math.min(32, sb.length));
    String rawB64 = Base64.getEncoder().encodeToString(raw);
    String want = "WebAuthn signature does not verify against the trusted signer key";
    refused(with(golden(), "signature", rawB64), EXP, want);

    com.fasterxml.jackson.databind.node.ObjectNode receiptJson = V.get("receipt").deepCopy();
    receiptJson.put("signature", rawB64);
    ApprovalReceipt receipt = Records.JSON.convertValue(receiptJson, ApprovalReceipt.class);
    JsonNode exp = V.get("expected");
    Expected expected = new Expected(exp.get("target").asText(), exp.get("nonce").asText(),
        exp.get("actionType").asText(),
        Records.JSON.convertValue(exp.get("params"),
            new com.fasterxml.jackson.core.type.TypeReference<java.util.Map<String, Object>>() {}),
        ApproverTrustAnchor.ofPublicKeys(List.of(receipt.signerPublicKey())));
    VerifyResult res = Verify.verifyApprovalReceipt(receipt, expected,
        VerifyOptions.builder().expectedOrigin(ORIGIN).expectedRpId(RP_ID).build());
    assertFalse(res.ok());
    assertEquals("quorum not met: 0 of 1 required approver signatures verified (" + want + ")", res.reason());
  }
}
