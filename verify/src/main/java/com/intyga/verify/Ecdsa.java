package com.intyga.verify;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/** ES256 (P-256 + SHA-256) primitives on the JDK's own providers — no crypto dependency. */
final class Ecdsa {

  /** A named refusal, carried as the reason string the verifier reports. */
  static final class Refusal extends Exception {
    Refusal(String reason) {
      super(reason);
    }
  }

  static final ECParameterSpec P256;

  static {
    try {
      AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
      params.init(new ECGenParameterSpec("secp256r1"));
      P256 = params.getParameterSpec(ECParameterSpec.class);
    } catch (GeneralSecurityException e) {
      throw new ExceptionInInitializerError(e);
    }
  }

  /** Parses a DER SPKI public key and pins the curve: an ES256 label must not be honoured by a key on some other curve. */
  static ECPublicKey parseSpkiP256(byte[] der) throws Refusal {
    PublicKey pub;
    try {
      pub = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));
    } catch (GeneralSecurityException | IllegalArgumentException e) {
      throw new Refusal("failed to parse SPKI public key");
    }
    if (!(pub instanceof ECPublicKey ec)) {
      throw new Refusal("signerPublicKey is not an ECDSA key");
    }
    if (!isP256(ec.getParams())) {
      throw new Refusal("signerPublicKey is not a P-256 key");
    }
    return ec;
  }

  private static boolean isP256(ECParameterSpec spec) {
    if (!(spec.getCurve().getField() instanceof ECFieldFp field)
        || !(P256.getCurve().getField() instanceof ECFieldFp p256Field)) {
      return false;
    }
    return field.getP().equals(p256Field.getP())
        && spec.getCurve().getA().equals(P256.getCurve().getA())
        && spec.getCurve().getB().equals(P256.getCurve().getB())
        && spec.getGenerator().equals(P256.getGenerator())
        && spec.getOrder().equals(P256.getOrder());
  }

  /**
   * Builds a P-256 public key from raw affine coordinates, validating point-on-curve first —
   * KeyFactory does not reliably do that, and an off-curve point enables invalid-curve attacks.
   */
  static ECPublicKey publicKeyFromCoordinates(BigInteger x, BigInteger y) throws Refusal {
    BigInteger p = ((ECFieldFp) P256.getCurve().getField()).getP();
    BigInteger a = P256.getCurve().getA();
    BigInteger b = P256.getCurve().getB();
    BigInteger lhs = y.modPow(BigInteger.TWO, p);
    BigInteger rhs = x.modPow(BigInteger.valueOf(3), p).add(a.multiply(x)).add(b).mod(p);
    if (x.signum() < 0 || x.compareTo(p) >= 0 || y.signum() < 0 || y.compareTo(p) >= 0
        || !lhs.equals(rhs)) {
      throw new Refusal("invalid COSE public key format: point is not on the P-256 curve");
    }
    try {
      PublicKey pub =
          KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), P256));
      return (ECPublicKey) pub;
    } catch (GeneralSecurityException e) {
      throw new Refusal("invalid COSE public key format: " + e.getMessage());
    }
  }

  /**
   * Verifies an ES256 signature over {@code message}, accepting either ASN.1/DER or raw
   * IEEE-P1363 (r‖s) encodings — matching every other port.
   */
  static boolean verifySignature(ECPublicKey pub, byte[] message, byte[] sig) {
    // Range-check r and s HERE rather than trusting the platform provider to do it. On JDK 15-18
    // before 17.0.3 (CVE-2022-21449) an all-zero ECDSA signature verifies under ANY key, and this
    // library is the thing that refuses unapproved actions — a relying party's patch level is not
    // ours to control, and this port targets release 17. Go's ecdsa.VerifyASN1 and Rust's p256 crate
    // reject zero scalars in-library; this is the same guarantee, stated. Pre-filter only: it can
    // remove acceptances, never add one.
    if (!scalarsInRange(sig)) {
      return false;
    }
    try {
      Signature verifier = Signature.getInstance("SHA256withECDSA");
      verifier.initVerify(pub);
      verifier.update(message);
      if (verifier.verify(sig)) {
        return true;
      }
    } catch (SignatureException e) {
      // Malformed DER — fall through to the P1363 attempt below.
    } catch (GeneralSecurityException e) {
      return false;
    }
    if (sig.length == 64) {
      try {
        Signature verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
        verifier.initVerify(pub);
        verifier.update(message);
        return verifier.verify(sig);
      } catch (GeneralSecurityException e) {
        return false;
      }
    }
    return false;
  }

  /**
   * Whether both scalars of {@code sig} lie in [1, n-1], under either encoding this verifier
   * accepts. A signature whose bytes are neither a well-formed DER SEQUENCE of two INTEGERs nor a
   * 64-byte r‖s pair is rejected — the platform verifier would reject it too, so nothing valid is
   * lost.
   */
  private static boolean scalarsInRange(byte[] sig) {
    BigInteger[] der = derScalars(sig);
    if (der != null && inRange(der[0]) && inRange(der[1])) {
      return true;
    }
    if (sig.length == 64) {
      return inRange(new BigInteger(1, Arrays.copyOfRange(sig, 0, 32)))
          && inRange(new BigInteger(1, Arrays.copyOfRange(sig, 32, 64)));
    }
    return false;
  }

  private static boolean inRange(BigInteger v) {
    return v.signum() > 0 && v.compareTo(P256.getOrder()) < 0;
  }

  /**
   * Reads (r, s) out of an ASN.1 DER {@code SEQUENCE { INTEGER, INTEGER }}, short-form lengths only
   * — a P-256 signature is at most 72 bytes, so it never needs the long form. Returns null when the
   * bytes are not exactly that shape.
   */
  private static BigInteger[] derScalars(byte[] der) {
    if (der.length < 8 || der.length > 72 || (der[0] & 0xff) != 0x30) {
      return null;
    }
    int seqLen = der[1] & 0xff;
    if (seqLen > 0x7f || seqLen != der.length - 2) {
      return null;
    }
    BigInteger[] out = new BigInteger[2];
    int i = 2;
    for (int k = 0; k < 2; k++) {
      if (i + 2 > der.length || (der[i] & 0xff) != 0x02) {
        return null;
      }
      int len = der[i + 1] & 0xff;
      if (len == 0 || len > 0x7f || i + 2 + len > der.length) {
        return null;
      }
      // DER INTEGERs are signed two's complement, which is exactly how this constructor reads them,
      // so a negative encoding falls out of range below instead of being silently made positive.
      out[k] = new BigInteger(Arrays.copyOfRange(der, i + 2, i + 2 + len));
      i += 2 + len;
    }
    return i == der.length ? out : null;
  }

  private Ecdsa() {}
}
