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

  private Ecdsa() {}
}
