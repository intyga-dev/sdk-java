package com.intyga.verify;

import com.fasterxml.jackson.annotation.JsonProperty;
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
          Map<Long, Object> m = new HashMap<>();
          for (long i = 0; i < value; i++) {
            Object key = decodeItem();
            Object val = decodeItem();
            // COSE_Key labels are all integers; non-integer keys are outside the accepted subset.
            if (!(key instanceof Long ik)) {
              throw new Ecdsa.Refusal("expected integer COSE label");
            }
            m.put(ik, val);
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
      throw new Ecdsa.Refusal("invalid COSE public key format: " + e.getMessage());
    }
    if (!(item instanceof Map<?, ?> m)) {
      throw new Ecdsa.Refusal("invalid COSE public key format: expected a CBOR map");
    }
    if (!(m.get(1L) instanceof Long kty) || kty != 2) {
      throw new Ecdsa.Refusal("invalid COSE public key format: expected kty EC2 (2)");
    }
    if (!(m.get(-1L) instanceof Long crv) || crv != 1) {
      throw new Ecdsa.Refusal("invalid COSE public key format: expected crv P-256 (1)");
    }
    Object alg = m.get(3L);
    if (alg != null && (!(alg instanceof Long a) || a != -7)) {
      throw new Ecdsa.Refusal("invalid COSE public key format: expected alg ES256 (-7)");
    }
    byte[] x = coordinate(m, -2L, "x");
    byte[] y = coordinate(m, -3L, "y");
    return Ecdsa.publicKeyFromCoordinates(new BigInteger(1, x), new BigInteger(1, y));
  }

  private static byte[] coordinate(Map<?, ?> m, long label, String name) throws Ecdsa.Refusal {
    if (!(m.get(label) instanceof byte[] raw)) {
      throw new Ecdsa.Refusal("invalid COSE public key format: missing " + name + " coordinate");
    }
    if (raw.length != 32) {
      throw new Ecdsa.Refusal(
          "invalid COSE public key format: " + name + " coordinate must be 32 bytes, got " + raw.length);
    }
    return raw;
  }

  private record ClientData(
      String type,
      String challenge,
      String origin,
      // crossOrigin is the only signal that separates "approved on our page" from "approved inside
      // someone else's page": an embedded RP frame reports the RP's OWN origin and its rpIdHash
      // matches too (W3C WebAuthn L3 §7.2 step 9).
      @JsonProperty("crossOrigin") boolean crossOrigin) {}

  /**
   * Verifies one WEBAUTHN witness against an already-TRUSTED key (from the caller's trust anchor,
   * never the receipt): pins the assertion to the expected origin and RP ID, confirms user
   * presence/verification, checks the challenge equals base64url(canonicalPayload), and verifies
   * the ES256 signature over authenticatorData ‖ SHA-256(clientDataJSON). Returns "" on success.
   */
  static String verifyWitness(
      ApprovalWitness w, String trustedKey, ApprovalReceipt receipt, VerifyOptions opts) {
    if (w.authenticatorData() == null || w.clientDataJSON() == null) {
      return "WebAuthn receipt missing authenticatorData or clientDataJSON";
    }
    // FAIL CLOSED: without an expected origin and RP ID there is nothing to pin the assertion to.
    if (isEmpty(opts.expectedOrigin()) || isEmpty(opts.expectedRpId())) {
      return "WebAuthn receipts require ExpectedOrigin and ExpectedRpID — without them an assertion from any relying party would verify";
    }

    byte[] clientDataBuf;
    try {
      clientDataBuf = Base64.getDecoder().decode(w.clientDataJSON());
    } catch (IllegalArgumentException e) {
      return "invalid clientDataJSON base64";
    }
    ClientData clientData;
    try {
      clientData = Records.JSON.readValue(clientDataBuf, ClientData.class);
    } catch (Exception e) {
      return "clientDataJSON is not valid JSON";
    }

    // An assertion, not a registration: webauthn.create signs a different ceremony over the same
    // challenge bytes and must never be accepted as approval.
    if (!"webauthn.get".equals(clientData.type())) {
      return "clientDataJSON is not a webauthn.get assertion";
    }
    if (!opts.expectedOrigin().equals(clientData.origin())) {
      return "assertion origin does not match ExpectedOrigin";
    }
    if (clientData.crossOrigin() && !opts.allowCrossOrigin()) {
      return "assertion was produced in a cross-origin frame (crossOrigin=true)";
    }
    String expectedChallenge =
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(receipt.canonicalPayload().getBytes(StandardCharsets.UTF_8));
    if (!expectedChallenge.equals(stripBase64Padding(clientData.challenge()))) {
      return "clientDataJSON challenge does not match canonical payload";
    }

    byte[] authData;
    try {
      authData = Base64.getDecoder().decode(w.authenticatorData());
    } catch (IllegalArgumentException e) {
      return "invalid authenticatorData base64";
    }
    if (authData.length < 37) {
      return "authenticatorData is too short";
    }
    byte[] rpIdHash = sha256(opts.expectedRpId().getBytes(StandardCharsets.UTF_8));
    byte[] presented = new byte[32];
    System.arraycopy(authData, 0, presented, 0, 32);
    if (!MessageDigest.isEqual(presented, rpIdHash)) {
      return "authenticatorData rpIdHash does not match ExpectedRpID";
    }
    int flags = authData[32] & 0xff;
    if ((flags & FLAG_UP) == 0) {
      return "authenticatorData user-present flag is not set";
    }
    boolean requireUv =
        opts.requireUserVerification() == null || opts.requireUserVerification();
    if (requireUv && (flags & FLAG_UV) == 0) {
      return "authenticatorData user-verified flag is not set";
    }

    // The COSE key is parsed from the TRUSTED key, not the receipt's copy.
    byte[] coseBuf;
    try {
      coseBuf = Base64.getDecoder().decode(trustedKey);
    } catch (IllegalArgumentException e) {
      return "invalid trusted key base64";
    }
    ECPublicKey pub;
    try {
      pub = parseCoseP256Key(coseBuf);
    } catch (Ecdsa.Refusal e) {
      return e.getMessage();
    }
    byte[] sigBytes;
    try {
      sigBytes = Base64.getDecoder().decode(w.signature());
    } catch (IllegalArgumentException e) {
      return "invalid signature base64";
    }

    byte[] clientDataHash = sha256(clientDataBuf);
    byte[] signedData = new byte[authData.length + clientDataHash.length];
    System.arraycopy(authData, 0, signedData, 0, authData.length);
    System.arraycopy(clientDataHash, 0, signedData, authData.length, clientDataHash.length);
    if (!Ecdsa.verifySignature(pub, signedData, sigBytes)) {
      return "WebAuthn signature does not verify against the trusted signer key";
    }
    return "";
  }

  static byte[] sha256(byte[] data) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(data);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  /** Removes trailing '=' so a padded challenge compares equal to the unpadded form. */
  private static String stripBase64Padding(String s) {
    int end = s == null ? 0 : s.length();
    if (s == null) {
      return "";
    }
    while (end > 0 && s.charAt(end - 1) == '=') {
      end--;
    }
    return s.substring(0, end);
  }

  private static boolean isEmpty(String s) {
    return s == null || s.isEmpty();
  }

  private WebAuthnSupport() {}
}
