package com.intyga.sdk.offline;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.KeyAgreement;

/** ES256 signing on the JDK's own providers — no crypto dependency. */
final class P256 {

  static final ECParameterSpec SPEC;

  static {
    try {
      AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
      params.init(new ECGenParameterSpec("secp256r1"));
      SPEC = params.getParameterSpec(ECParameterSpec.class);
    } catch (GeneralSecurityException e) {
      throw new ExceptionInInitializerError(e);
    }
  }

  private static final Pattern PEM =
      Pattern.compile("-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----([\\s\\S]*?)-----END \\1-----");

  private P256() {}

  /** A refusal carrying the reason the signing call reports. */
  static final class KeyRefusal extends Exception {
    KeyRefusal(String reason) {
      super(reason);
    }
  }

  static boolean isP256(ECParameterSpec spec) {
    if (spec == null
        || !(spec.getCurve().getField() instanceof ECFieldFp field)
        || !(SPEC.getCurve().getField() instanceof ECFieldFp p256Field)) {
      return false;
    }
    return field.getP().equals(p256Field.getP())
        && spec.getCurve().getA().equals(SPEC.getCurve().getA())
        && spec.getCurve().getB().equals(SPEC.getCurve().getB())
        && spec.getGenerator().equals(SPEC.getGenerator())
        && spec.getOrder().equals(SPEC.getOrder());
  }

  /** Bytes as the reference reads a key file: PEM when it contains a PEM header, else DER PKCS#8. */
  static PrivateKey parse(byte[] keyBytes) throws KeyRefusal {
    String asText = new String(keyBytes, StandardCharsets.ISO_8859_1);
    if (asText.contains("-----BEGIN")) {
      return parsePem(asText);
    }
    return parsePkcs8(keyBytes);
  }

  /**
   * A PEM private key: {@code PRIVATE KEY} (PKCS#8) or {@code EC PRIVATE KEY} (SEC1 / RFC 5915 —
   * what {@code openssl ecparam -genkey} writes, after an {@code EC PARAMETERS} block). Encrypted
   * keys of either kind are refused: decrypt them first.
   */
  static PrivateKey parsePem(String pem) throws KeyRefusal {
    Matcher m = PEM.matcher(pem);
    if (!m.find()) {
      throw new KeyRefusal("no PEM private key block found");
    }
    String type = m.group(1);
    String body = m.group(2);
    if (!type.equals("PRIVATE KEY") && !type.equals("EC PRIVATE KEY")) {
      throw new KeyRefusal("unsupported PEM type \"" + type
          + "\" (expected an unencrypted PKCS#8 PRIVATE KEY or SEC1 EC PRIVATE KEY)");
    }
    // A legacy encrypted SEC1 block carries RFC 1421 headers ("Proc-Type: 4,ENCRYPTED").
    if (body.indexOf(':') >= 0) {
      throw new KeyRefusal("encrypted PEM keys are not supported — decrypt the key first");
    }
    byte[] der;
    try {
      der = Base64.getMimeDecoder().decode(body.trim());
    } catch (IllegalArgumentException e) {
      throw new KeyRefusal("PEM body is not valid base64");
    }
    return type.equals("PRIVATE KEY") ? parsePkcs8(der) : parseSec1(der);
  }

  // id prime256v1 (1.2.840.10045.3.1.7), the OID's content octets.
  private static final byte[] PRIME256V1 = {0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x03, 0x01, 0x07};

  /**
   * An RFC 5915 {@code ECPrivateKey}: {@code SEQUENCE { INTEGER 1, OCTET STRING privateKey,
   * [0] ECParameters OPTIONAL, [1] BIT STRING publicKey OPTIONAL }}. The parameters, when present,
   * must name prime256v1 (explicit curve parameters are refused); absent, P-256 is the only curve
   * this signer accepts anyway. An embedded public key is skipped, never trusted: the envelope's
   * SPKI is always derived from the scalar itself.
   */
  static PrivateKey parseSec1(byte[] der) throws KeyRefusal {
    byte[] scalar = null;
    try {
      Der outer = new Der(der);
      Der seq = outer.enter(0x30);
      if (!outer.atEnd()) {
        throw new KeyRefusal("not a SEC1 EC private key");
      }
      byte[] version = seq.content(0x02);
      if (version.length != 1 || version[0] != 1) {
        throw new KeyRefusal("not a SEC1 EC private key (version must be 1)");
      }
      scalar = seq.content(0x04);
      if (!seq.atEnd() && seq.peek() == 0xA0) {
        Der params = seq.enter(0xA0);
        if (params.peek() != 0x06) {
          throw new KeyRefusal("the signing key must be a P-256 (prime256v1) private key");
        }
        byte[] oid = params.content(0x06);
        if (!params.atEnd() || !Arrays.equals(oid, PRIME256V1)) {
          throw new KeyRefusal("the signing key must be a P-256 (prime256v1) private key");
        }
      }
      if (!seq.atEnd() && seq.peek() == 0xA1) {
        seq.enter(0xA1);
      }
      if (!seq.atEnd()) {
        throw new KeyRefusal("not a SEC1 EC private key");
      }
      BigInteger d = new BigInteger(1, scalar);
      if (scalar.length > 32 || d.signum() == 0 || d.compareTo(SPEC.getOrder()) >= 0) {
        throw new KeyRefusal("the signing key must be a P-256 (prime256v1) private key");
      }
      return KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(d, SPEC));
    } catch (GeneralSecurityException | IllegalArgumentException e) {
      throw new KeyRefusal("not a SEC1 EC private key");
    } finally {
      if (scalar != null) {
        Arrays.fill(scalar, (byte) 0);
      }
    }
  }

  /** Just enough DER to walk an RFC 5915 structure: definite lengths only, bounds-checked. */
  private static final class Der {
    private final byte[] buf;
    private int pos;
    private final int end;

    Der(byte[] buf) {
      this(buf, 0, buf.length);
    }

    private Der(byte[] buf, int start, int end) {
      this.buf = buf;
      this.pos = start;
      this.end = end;
    }

    boolean atEnd() {
      return pos >= end;
    }

    int peek() throws KeyRefusal {
      if (atEnd()) {
        throw new KeyRefusal("not a SEC1 EC private key (truncated)");
      }
      return buf[pos] & 0xFF;
    }

    /** The element with {@code tag}: its content as a nested reader. */
    Der enter(int tag) throws KeyRefusal {
      int[] span = element(tag);
      return new Der(buf, span[0], span[1]);
    }

    /** The content octets of the element with {@code tag}. */
    byte[] content(int tag) throws KeyRefusal {
      int[] span = element(tag);
      return Arrays.copyOfRange(buf, span[0], span[1]);
    }

    private int[] element(int tag) throws KeyRefusal {
      if (peek() != tag) {
        throw new KeyRefusal("not a SEC1 EC private key (unexpected DER tag)");
      }
      pos++;
      if (atEnd()) {
        throw new KeyRefusal("not a SEC1 EC private key (truncated)");
      }
      int first = buf[pos++] & 0xFF;
      int length;
      if (first < 0x80) {
        length = first;
      } else {
        int octets = first & 0x7F;
        if (octets == 0 || octets > 3 || end - pos < octets) {
          throw new KeyRefusal("not a SEC1 EC private key (bad DER length)");
        }
        length = 0;
        for (int i = 0; i < octets; i++) {
          length = (length << 8) | (buf[pos++] & 0xFF);
        }
      }
      if (length > end - pos) {
        throw new KeyRefusal("not a SEC1 EC private key (truncated)");
      }
      int start = pos;
      pos += length;
      return new int[] {start, pos};
    }
  }

  static PrivateKey parsePkcs8(byte[] der) throws KeyRefusal {
    try {
      return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(der));
    } catch (GeneralSecurityException | IllegalArgumentException e) {
      throw new KeyRefusal("not a PKCS#8 EC private key");
    }
  }

  /** The key, if it is a P-256 EC private key; otherwise the refusal the reference gives. */
  static PrivateKey requireP256(PrivateKey key) throws KeyRefusal {
    if (!(key instanceof ECKey ec) || !"EC".equals(key.getAlgorithm()) || !isP256(ec.getParams())) {
      throw new KeyRefusal("the signing key must be a P-256 (prime256v1) private key");
    }
    return key;
  }

  /** ES256 over {@code message}, IEEE P1363 (r||s, 64 bytes) — the form every verifier expects. */
  static byte[] sign(PrivateKey key, byte[] message) throws GeneralSecurityException {
    Signature s = Signature.getInstance("SHA256withECDSAinP1363Format");
    s.initSign(key);
    s.update(message);
    return s.sign();
  }

  static boolean verify(PublicKey key, byte[] message, byte[] p1363) {
    try {
      Signature v = Signature.getInstance("SHA256withECDSAinP1363Format");
      v.initVerify(key);
      v.update(message);
      return v.verify(p1363);
    } catch (GeneralSecurityException | IllegalArgumentException e) {
      return false;
    }
  }

  /**
   * The public key of a bare P-256 private key — needed because the {@code SIG1:} envelope carries
   * the signer's SPKI and a PKCS#8 key need not contain it (the JDK's own encoding never does).
   *
   * <p>The JDK has no "public from private" operation, and hand-rolled scalar multiplication on the
   * secret would be a timing side channel. So the multiplication is delegated to the provider's
   * own constant-time ECDH: agreeing with the GENERATOR as the peer yields x(d·G), the public x
   * coordinate. y follows from the curve equation up to sign (p ≡ 3 mod 4, so one modPow — on
   * public data only), and the two candidates are told apart by checking which one verifies a
   * signature made with the key. Exactly one must.
   *
   * @param message a message {@code signature} was made over with {@code key}
   */
  static ECPublicKey derivePublicKey(PrivateKey key, byte[] message, byte[] signature)
      throws KeyRefusal {
    ECParameterSpec spec = ((ECKey) key).getParams();
    try {
      KeyFactory kf = KeyFactory.getInstance("EC");
      PublicKey generator = kf.generatePublic(new ECPublicKeySpec(spec.getGenerator(), spec));
      KeyAgreement ka = KeyAgreement.getInstance("ECDH");
      ka.init(key);
      ka.doPhase(generator, true);
      BigInteger x = new BigInteger(1, ka.generateSecret());
      EllipticCurve curve = spec.getCurve();
      BigInteger p = ((ECFieldFp) curve.getField()).getP();
      BigInteger rhs = x.pow(3).add(curve.getA().multiply(x)).add(curve.getB()).mod(p);
      BigInteger y = rhs.modPow(p.add(BigInteger.ONE).shiftRight(2), p);
      if (!y.multiply(y).mod(p).equals(rhs)) {
        throw new KeyRefusal("could not derive the public key from this private key");
      }
      ECPublicKey match = null;
      for (BigInteger candidateY : new BigInteger[] {y, p.subtract(y).mod(p)}) {
        ECPublicKey candidate =
            (ECPublicKey) kf.generatePublic(new ECPublicKeySpec(new ECPoint(x, candidateY), spec));
        if (verify(candidate, message, signature)) {
          if (match != null) {
            throw new KeyRefusal("could not derive the public key from this private key");
          }
          match = candidate;
        }
      }
      if (match == null) {
        throw new KeyRefusal("could not derive the public key from this private key");
      }
      return match;
    } catch (GeneralSecurityException | ClassCastException e) {
      throw new KeyRefusal(
          "could not derive the public key from this private key (" + e.getMessage()
              + ") — pass the key pair instead");
    }
  }

  /** Standard-alphabet base64 of the X.509 SubjectPublicKeyInfo, as every bundle lists keys. */
  static String spkiBase64(PublicKey key) {
    return Base64.getEncoder().encodeToString(key.getEncoded());
  }
}
