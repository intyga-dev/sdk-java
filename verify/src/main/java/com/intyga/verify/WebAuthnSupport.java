package com.intyga.verify;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * WebAuthn witness verification, including a minimal CBOR reader for COSE_Key only: just enough
 * CBOR to walk a COSE_Key map — ints, byte/text strings, arrays, maps. Deliberately NOT a general
 * decoder; anything outside that subset is rejected rather than guessed. Mirrors the reader in
 * {@code @intyga/verify} so all languages parse identical bytes.
 */
final class WebAuthnSupport {

  // WebAuthn authenticatorData flag bits (WebAuthn L3 §6.1).
  private static final int FLAG_UP = 0x01; // User Present
  private static final int FLAG_UV = 0x04; // User Verified
  private static final int FLAG_BE = 0x08; // Backup Eligible — the credential may be synced
  private static final int FLAG_BS = 0x10; // Backup State — the credential is currently backed up

  /**
   * Under a signed requireHardwareKey, a WEBAUTHN witness whose authenticatorData carries the Backup
   * Eligible or Backup State flag cannot count (DIV §4.4.5 rule 6). The flags are covered by the
   * assertion signature, so a relying party can catch an issuer that let a synced passkey sign a
   * hardware-pinned action. BE=0 is the authenticator's own claim, not attestation. Called only for
   * a witness that already verified, so authenticatorData decodes to at least 37 bytes.
   *
   * @return the refusal reason, or null when the flags say device-bound (or the witness is not WebAuthn)
   */
  static String backupFlagsProblem(ApprovalWitness w) {
    if (!"WEBAUTHN".equals(w.sigAlg()) || w.authenticatorData() == null) return null;
    byte[] authData = decodeNodeBase64(w.authenticatorData());
    if (authData.length < 37) return "authenticatorData is unreadable";
    if ((authData[32] & (FLAG_BE | FLAG_BS)) == 0) return null;
    return "signer " + w.signerDid() + " used a backup-eligible (synced) passkey — authenticatorData"
        + " BE/BS flag set — but the signed policy requires a hardware-backed WebAuthn credential";
  }

  private static final class CborReader {
    private final byte[] buf;
    private int pos;

    CborReader(byte[] buf) {
      this.buf = buf;
    }

    private void require(long n) throws Ecdsa.Refusal {
      // long, not int: a 4-byte CBOR length above Integer.MAX_VALUE would cast negative, sail
      // through this check, and then blow up as NegativeArraySizeException — which is not an
      // Ecdsa.Refusal, so it would escape every catch here and out of verifyApprovalReceipt,
      // whose contract is to RETURN a VerifyResult rather than throw. Go's reader uses a
      // 64-bit int for the same reason (verify-go/webauthn.go:83-85).
      if (n < 0 || pos + n > buf.length) {
        throw new Ecdsa.Refusal("truncated CBOR item");
      }
    }

    private long[] readHead() throws Ecdsa.Refusal {
      require(1);
      int initial = buf[pos] & 0xff;
      pos++;
      int major = initial >> 5;
      int info = initial & 0x1f;
      long value;
      if (info < 24) {
        value = info;
      } else if (info == 24) {
        require(1);
        value = buf[pos] & 0xff;
        pos++;
      } else if (info == 25) {
        require(2);
        value = ((long) (buf[pos] & 0xff) << 8) | (buf[pos + 1] & 0xff);
        pos += 2;
      } else if (info == 26) {
        require(4);
        value =
            ((long) (buf[pos] & 0xff) << 24)
                | ((long) (buf[pos + 1] & 0xff) << 16)
                | ((long) (buf[pos + 2] & 0xff) << 8)
                | (buf[pos + 3] & 0xff);
        pos += 4;
      } else {
        // 27 = 64-bit, 28-30 reserved, 31 = indefinite. No COSE_Key needs any of them.
        throw new Ecdsa.Refusal("unsupported CBOR length encoding");
      }
      return new long[] {major, value};
    }

    Object decodeItem() throws Ecdsa.Refusal {
      long[] head = readHead();
      int major = (int) head[0];
      long value = head[1];
      switch (major) {
        case 0: // unsigned int
          return value;
        case 1: // negative int — COSE labels like -1 (crv), -2 (x), -3 (y)
          return -1 - value;
        case 2: { // byte string
          require(value);
          byte[] b = new byte[(int) value];
          System.arraycopy(buf, pos, b, 0, (int) value);
          pos += (int) value;
          return b;
        }
        case 3: { // text string
          require(value);
          String s = new String(buf, pos, (int) value, StandardCharsets.UTF_8);
          pos += (int) value;
          return s;
        }
        case 4: { // array
          // Do not pre-size from an attacker-supplied count: a 4-byte length would allocate
          // gigabytes before the first element is even read. It grows as items actually arrive,
          // and decodeItem's own require() bounds them against the buffer.
          List<Object> items = new ArrayList<>();
          for (long i = 0; i < value; i++) {
            items.add(decodeItem());
          }
          return items;
        }
        case 5: { // map
          // Keys of any decoded type, as in the reference's Map: COSE_Key labels are integers, and a
          // non-integer key simply never matches one (byte-string keys compare by identity there).
          Map<Object, Object> m = new HashMap<>();
          for (long i = 0; i < value; i++) {
            Object key = decodeItem();
            Object val = decodeItem();
            m.put(key instanceof byte[] ? new Object() : key, val);
          }
          return m;
        }
        default:
          throw new Ecdsa.Refusal("unsupported CBOR major type " + major);
      }
    }
  }

  /**
   * Extracts the P-256 public key from a WebAuthn COSE_Key. Pins kty EC2 (2), crv P-256 (1) and,
   * if present, alg ES256 (-7), so a key for another curve can never be reinterpreted as P-256.
   * Trailing bytes after the leading map are tolerated.
   */
  static ECPublicKey parseCoseP256Key(byte[] coseBuf) throws Ecdsa.Refusal {
    Object item;
    try {
      item = new CborReader(coseBuf).decodeItem();
    } catch (Ecdsa.Refusal e) {
      throw new Ecdsa.Refusal("Invalid COSE public key format: " + e.getMessage());
    }
    if (!(item instanceof Map<?, ?> m)) {
      throw new Ecdsa.Refusal("Invalid COSE public key format: expected a CBOR map");
    }
    // The reference's texts, with the offending value rendered as JavaScript's String() would.
    Object kty = m.get(1L);
    if (!(kty instanceof Long k) || k != 2) {
      throw new Ecdsa.Refusal("Invalid COSE public key format: expected kty EC2 (2), got " + jsString(kty));
    }
    Object crv = m.get(-1L);
    if (!(crv instanceof Long c) || c != 1) {
      throw new Ecdsa.Refusal("Invalid COSE public key format: expected crv P-256 (1), got " + jsString(crv));
    }
    Object alg = m.get(3L);
    if (alg != null && (!(alg instanceof Long a) || a != -7)) {
      throw new Ecdsa.Refusal("Invalid COSE public key format: expected alg ES256 (-7), got " + jsString(alg));
    }
    byte[] x = coordinate(m, -2L, "x");
    byte[] y = coordinate(m, -3L, "y");
    return Ecdsa.publicKeyFromCoordinates(new BigInteger(1, x), new BigInteger(1, y));
  }

  /** JavaScript's String() of a decoded CBOR value, for refusal texts. */
  private static String jsString(Object v) {
    if (v == null) return "undefined";
    if (v instanceof byte[] b) return new String(b, StandardCharsets.UTF_8);
    if (v instanceof List<?> l) {
      StringBuilder out = new StringBuilder();
      for (int i = 0; i < l.size(); i++) {
        if (i > 0) out.append(',');
        out.append(jsString(l.get(i)));
      }
      return out.toString();
    }
    if (v instanceof Map<?, ?>) return "[object Map]";
    return String.valueOf(v);
  }

  private static byte[] coordinate(Map<?, ?> m, long label, String name) throws Ecdsa.Refusal {
    if (!(m.get(label) instanceof byte[] raw)) {
      throw new Ecdsa.Refusal("Invalid COSE public key format: missing " + name + " coordinate");
    }
    if (raw.length != 32) {
      throw new Ecdsa.Refusal(
          "Invalid COSE public key format: " + name + " coordinate must be 32 bytes, got " + raw.length);
    }
    return raw;
  }

  /** Supplies the credential key only after the cheaper checks, as the reference's keyOf() does. */
  @FunctionalInterface
  interface KeySupplier {
    ECPublicKey get() throws Ecdsa.Refusal;
  }

  /**
   * Verifies one WEBAUTHN witness against an already-TRUSTED key (from the caller's trust anchor,
   * never the receipt). Fail closed without an expected origin and RP ID, then the shared assertion
   * check ({@link #assertionProblem}). The COSE key is parsed from the TRUSTED key, not the
   * receipt's copy. Returns "" on success.
   */
  static String verifyWitness(
      ApprovalWitness w, String trustedKey, ApprovalReceipt receipt, VerifyOptions opts) {
    if (w.authenticatorData() == null || w.clientDataJSON() == null) {
      return "WebAuthn receipt missing authenticatorData or clientDataJSON";
    }
    // FAIL CLOSED: without an expected origin and RP ID there is nothing to pin the assertion to.
    if (isEmpty(opts.expectedOrigin()) || isEmpty(opts.expectedRpId())) {
      return "WebAuthn receipts require expectedOrigin and expectedRpId — without them an assertion from any relying party would verify";
    }
    return assertionProblem(w.authenticatorData(), w.clientDataJSON(), w.signature(),
        () -> parseCoseP256Key(decodeNodeBase64(trustedKey)), receipt.canonicalPayload(),
        List.of(opts.expectedOrigin()), opts.expectedRpId(),
        opts.requireUserVerification() == null || opts.requireUserVerification(),
        opts.allowCrossOrigin());
  }

  /**
   * The standalone witness check ({@code verifyWebAuthnWitness} in the reference): expectations,
   * then each field in order, then the same assertion check the receipt path runs. Never throws.
   */
  static String verifyStandaloneWitness(WebAuthnWitness witness, WebAuthnWitnessExpectation expectation) {
    List<String> origins = expectation == null || expectation.expectedOrigin() == null
        ? List.of() : expectation.expectedOrigin();
    boolean originsOk = !origins.isEmpty();
    for (String o : origins) originsOk &= o != null && !o.isEmpty();
    if (!originsOk || expectation.expectedRpId() == null || expectation.expectedRpId().isEmpty()) {
      return "a WebAuthn witness requires expectedOrigin and expectedRpId — without them an assertion"
          + " from any relying party would verify";
    }
    String[][] fields = {
        {"signedPayload", witness == null ? null : witness.signedPayload()},
        {"publicKey", witness == null ? null : witness.publicKey()},
        {"authenticatorData", witness == null ? null : witness.authenticatorData()},
        {"clientDataJSON", witness == null ? null : witness.clientDataJSON()},
        {"signature", witness == null ? null : witness.signature()}};
    for (String[] f : fields) {
      if (isEmpty(f[1])) return "WebAuthn witness missing " + f[0];
    }
    return assertionProblem(witness.authenticatorData(), witness.clientDataJSON(), witness.signature(),
        () -> callerPublicKey(decodeNodeBase64(witness.publicKey())), witness.signedPayload(),
        List.copyOf(origins), expectation.expectedRpId(),
        expectation.requireUserVerification() == null || expectation.requireUserVerification(),
        expectation.allowCrossOrigin());
  }

  /**
   * A caller-supplied P-256 credential key: DER SPKI (a SEQUENCE, 0x30) or a COSE_Key (a CBOR map).
   * A well-formed SPKI for any other key type is "public key is not a P-256 key", as in the reference.
   */
  private static ECPublicKey callerPublicKey(byte[] der) throws Ecdsa.Refusal {
    if (der.length == 0 || der[0] != 0x30) return parseCoseP256Key(der);
    try {
      java.security.PublicKey pub = java.security.KeyFactory.getInstance("EC")
          .generatePublic(new java.security.spec.X509EncodedKeySpec(der));
      if (pub instanceof ECPublicKey ec) {
        try {
          return Ecdsa.parseSpkiP256(der);
        } catch (Ecdsa.Refusal notP256) {
          throw new Ecdsa.Refusal("public key is not a P-256 key");
        }
      }
    } catch (java.security.GeneralSecurityException | IllegalArgumentException notEc) {
      // fall through: maybe another algorithm's SPKI
    }
    for (String alg : new String[] {"RSA", "Ed25519", "Ed448", "X25519", "X448", "DSA", "EC"}) {
      try {
        java.security.KeyFactory.getInstance(alg).generatePublic(new java.security.spec.X509EncodedKeySpec(der));
        throw new Ecdsa.Refusal("public key is not a P-256 key");
      } catch (java.security.GeneralSecurityException | IllegalArgumentException ignored) {
        // not this algorithm
      }
    }
    throw new Ecdsa.Refusal("failed to parse SPKI public key");
  }

  /**
   * The DIV §4.4.5 checks on one assertion — ceremony type, origin, cross-origin flag, challenge
   * binding, RP ID hash, UP/UV flags and the DER ECDSA signature over authenticatorData ‖
   * SHA-256(clientDataJSON) — in the reference's order (verifyWebAuthnAssertion). Shared by the
   * receipt path and the standalone verifier, so there is one implementation. A failure the
   * reference reports through its catch-all reads "WebAuthn verification failed: <detail>". Returns
   * "" on success; never throws.
   */
  static String assertionProblem(String authenticatorDataB64, String clientDataB64, String signatureB64,
      KeySupplier keyOf, String signedPayload, List<String> expectedOrigins, String expectedRpId,
      boolean requireUserVerification, boolean allowCrossOrigin) {
    try {
      byte[] clientDataBuf = decodeNodeBase64(clientDataB64);
      com.fasterxml.jackson.databind.JsonNode clientData;
      try {
        clientData = Records.JSON.readTree(new String(clientDataBuf, StandardCharsets.UTF_8));
      } catch (Exception e) {
        return "WebAuthn verification failed: clientDataJSON is not valid JSON";
      }
      if (clientData == null || !clientData.isObject()) {
        return "WebAuthn verification failed: clientDataJSON is not a JSON object";
      }
      // An assertion, not a registration: webauthn.create signs a different ceremony over the same
      // challenge bytes and must never be accepted as approval.
      com.fasterxml.jackson.databind.JsonNode type = clientData.get("type");
      if (type == null || !type.isTextual() || !"webauthn.get".equals(type.textValue())) {
        return "clientDataJSON is not a webauthn.get assertion";
      }
      com.fasterxml.jackson.databind.JsonNode origin = clientData.get("origin");
      if (origin == null || !origin.isTextual() || !expectedOrigins.contains(origin.textValue())) {
        return "assertion origin does not match expectedOrigin";
      }
      // crossOrigin is the only signal that separates "approved on our page" from "approved inside
      // someone else's page": an embedded RP frame reports the RP's OWN origin and its rpIdHash
      // matches too (W3C WebAuthn L3 §7.2 step 9).
      com.fasterxml.jackson.databind.JsonNode crossOrigin = clientData.get("crossOrigin");
      if (crossOrigin != null && crossOrigin.isBoolean() && crossOrigin.booleanValue() && !allowCrossOrigin) {
        return "assertion was produced in a cross-origin frame (crossOrigin=true)";
      }
      // A topOrigin (present, even as null) that differs from origin is the same embedding reported
      // another way, refused exactly like crossOrigin=true (DIV §4.4.5 rule 5).
      com.fasterxml.jackson.databind.JsonNode topOrigin = clientData.get("topOrigin");
      if (topOrigin != null && !(topOrigin.isTextual() && topOrigin.textValue().equals(origin.textValue()))
          && !allowCrossOrigin) {
        return "assertion was produced in a frame embedded by another origin (topOrigin differs from origin)";
      }
      com.fasterxml.jackson.databind.JsonNode challenge = clientData.get("challenge");
      if (challenge == null || !challenge.isTextual()) {
        return "WebAuthn verification failed: clientDataJSON challenge is not a string";
      }
      String expectedChallenge = Base64.getUrlEncoder().withoutPadding()
          .encodeToString(signedPayload.getBytes(StandardCharsets.UTF_8));
      String presentedChallenge = challenge.textValue().replace('+', '-').replace('/', '_').replace("=", "");
      if (!expectedChallenge.equals(presentedChallenge)) {
        return "clientDataJSON challenge does not match canonical payload";
      }

      byte[] authData = decodeNodeBase64(authenticatorDataB64);
      if (authData.length < 37) {
        return "authenticatorData is too short";
      }
      byte[] rpIdHash = sha256(expectedRpId.getBytes(StandardCharsets.UTF_8));
      byte[] presented = new byte[32];
      System.arraycopy(authData, 0, presented, 0, 32);
      if (!MessageDigest.isEqual(presented, rpIdHash)) {
        return "authenticatorData rpIdHash does not match expectedRpId";
      }
      int flags = authData[32] & 0xff;
      if ((flags & FLAG_UP) == 0) {
        return "authenticatorData user-present flag is not set";
      }
      if (requireUserVerification && (flags & FLAG_UV) == 0) {
        return "authenticatorData user-verified flag is not set";
      }

      ECPublicKey pub;
      try {
        pub = keyOf.get();
      } catch (Ecdsa.Refusal e) {
        return "WebAuthn verification failed: " + e.getMessage();
      }
      byte[] sigBytes = decodeNodeBase64(signatureB64 == null ? "" : signatureB64);
      byte[] clientDataHash = sha256(clientDataBuf);
      byte[] signedData = new byte[authData.length + clientDataHash.length];
      System.arraycopy(authData, 0, signedData, 0, authData.length);
      System.arraycopy(clientDataHash, 0, signedData, authData.length, clientDataHash.length);
      // DER only, as the reference's dsaEncoding: "der" — a raw r‖s signature does not verify.
      if (!Ecdsa.verifyDerSignature(pub, signedData, sigBytes)) {
        return "WebAuthn signature does not verify against the trusted signer key";
      }
      return "";
    } catch (RuntimeException e) {
      return "WebAuthn verification failed: " + e.getClass().getSimpleName();
    }
  }

  /**
   * Node's {@code Buffer.from(s, "base64")}, which every reference read on this path uses: either
   * alphabet, characters outside it skipped, decoding stops at padding, a dangling sixth-bit
   * character dropped. Never throws, so a malformed encoding reaches the same check as in the
   * reference (a short authenticatorData, a non-JSON clientDataJSON, a signature that does not
   * verify) instead of a decoder error of its own.
   */
  static byte[] decodeNodeBase64(String s) {
    if (s == null) return new byte[0];
    StringBuilder b = new StringBuilder(s.length());
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if (c == '=') break;
      if (c == '-') c = '+';
      else if (c == '_') c = '/';
      if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/') {
        b.append(c);
      }
    }
    if (b.length() % 4 == 1) b.setLength(b.length() - 1);
    int rem = b.length() % 4;
    if (rem != 0) b.append("==".substring(0, 4 - rem));
    return Base64.getDecoder().decode(b.toString());
  }

  static byte[] sha256(byte[] data) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(data);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  private static boolean isEmpty(String s) {
    return s == null || s.isEmpty();
  }

  private WebAuthnSupport() {}
}
