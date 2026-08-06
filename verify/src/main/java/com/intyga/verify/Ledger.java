package com.intyga.verify;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

/**
 * DEWP audit-ledger verification (docs/DEWP.md) — Java port, Core Profile. Byte-identical to
 * {@code @intyga/verify} (ledger-*.ts) and the Go/Rust/Python ports, locked by
 * {@code packages/mcp-schemas/vectors/ledger-vectors.json}.
 *
 * <p>Domain separation: 0x00 leaf, 0x01 node, 0x02 empty root, 0x03 anchor. Node children are
 * hex-decoded to raw bytes before hashing; the leaf {@code metadata} element is a JCS (sorted-key)
 * string.
 */
public final class Ledger {

  private static final HexFormat HEX = HexFormat.of();

  /** Lowercase hex SHA-256 of the UTF-8 bytes. */
  public static String sha256Hex(String data) {
    return HEX.formatHex(WebAuthnSupport.sha256(data.getBytes(StandardCharsets.UTF_8)));
  }

  private static String sha256Hex(byte[] data) {
    return HEX.formatHex(WebAuthnSupport.sha256(data));
  }

  /** sha256(0x00 || UTF8(preimage)). */
  public static String hashLeaf(String preimage) {
    byte[] utf8 = preimage.getBytes(StandardCharsets.UTF_8);
    byte[] buf = new byte[1 + utf8.length];
    buf[0] = 0x00;
    System.arraycopy(utf8, 0, buf, 1, utf8.length);
    return sha256Hex(buf);
  }

  /** sha256(0x01 || rawBytes(left) || rawBytes(right)). Order encodes position. */
  public static String hashPair(String leftHex, String rightHex) {
    byte[] left = HEX.parseHex(leftHex);
    byte[] right = HEX.parseHex(rightHex);
    byte[] buf = new byte[1 + left.length + right.length];
    buf[0] = 0x01;
    System.arraycopy(left, 0, buf, 1, left.length);
    System.arraycopy(right, 0, buf, 1 + left.length, right.length);
    return sha256Hex(buf);
  }

  /** sha256(0x02) (DEWP §5.1.1). */
  public static String emptyRoot() {
    return sha256Hex(new byte[] {0x02});
  }

  /** Merkle root over ordered leaves (duplicate-last on odd levels). Empty ⇒ {@link #emptyRoot()}. */
  public static String merkleRoot(List<String> leaves) {
    if (leaves.isEmpty()) {
      return emptyRoot();
    }
    List<String> level = leaves;
    while (level.size() > 1) {
      List<String> next = new ArrayList<>((level.size() + 1) / 2);
      for (int i = 0; i < level.size(); i += 2) {
        String left = level.get(i);
        String right = i + 1 < level.size() ? level.get(i + 1) : left; // duplicate-last
        next.add(hashPair(left, right));
      }
      level = next;
    }
    return level.get(0);
  }

  /** One leaf→root Merkle path step (DEWP §5.1.6). {@code siblingPosition} is "LEFT" or "RIGHT". */
  public record LedgerProofStep(String siblingHash, String siblingPosition) {}

  /**
   * The leaf's position and its tree's leaf count. REQUIRED, per DEWP §3 invariant 3 ("The bounds
   * are REQUIRED, not advisory") and §11.1: they turn "is there SOME path from this leaf to this
   * root" into "is this leaf at this position".
   */
  public record ProofBounds(int index, int leafCount) {}

  /**
   * Audit-path length for a duplicate-last tree of {@code leafCount} leaves: ceil(log2(n)), or 0
   * when n &lt;= 1 (DEWP §11.1 check 2).
   */
  public static int expectedPathLength(int leafCount) {
    if (leafCount <= 1) {
      return 0;
    }
    int n = 0;
    for (int size = leafCount; size > 1; size = (size + 1) / 2) {
      n++;
    }
    return n;
  }

  /** Whether s is exactly 64 lowercase hex characters (DEWP §4.4). */
  private static boolean isHash64(String s) {
    if (s == null || s.length() != 64) {
      return false;
    }
    for (int i = 0; i < 64; i++) {
      char c = s.charAt(i);
      if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
        return false;
      }
    }
    return true;
  }

  /**
   * Recomputes the root from a leaf + its leaf→root proof, bounded by the leaf's position (DEWP
   * §11.2 reference implementation).
   *
   * <p>Bounds are what make this a proof of MEMBERSHIP rather than a proof that A path exists:
   * this tree pads an unpaired trailing node by hashing it against ITSELF, so a path built for a
   * nonexistent index recomputes the real root exactly. DEWP §11.1 states outright that an
   * implementation stopping at root recomputation is non-conformant.
   */
  public static boolean verifyMerkleProof(
      String leaf, List<LedgerProofStep> proof, String root, ProofBounds bounds) {
    if (!isHash64(leaf) || !isHash64(root)) {
      return false;
    }
    if (bounds.leafCount() < 1 || bounds.index() < 0 || bounds.index() >= bounds.leafCount()) {
      return false;
    }
    if (proof.size() != expectedPathLength(bounds.leafCount())) {
      return false;
    }
    int idx = bounds.index();
    int levelSize = bounds.leafCount();
    String node = leaf;
    for (LedgerProofStep step : proof) {
      if (!isHash64(step.siblingHash())) {
        return false;
      }
      // The side follows from the index; a prover-chosen side would restore the flexibility the
      // length check just removed.
      String expectedSide = idx % 2 == 1 ? "LEFT" : "RIGHT";
      if (!expectedSide.equals(step.siblingPosition())) {
        return false;
      }
      // Self-pairing is legitimate ONLY at the unpaired end of an odd-sized level. Anywhere else
      // it is the signature of an index pointing into padding — this is the check that actually
      // closes the forgery, because leafCount arrives inside the proof and a prover can inflate it.
      boolean selfPaired = step.siblingHash().equals(node);
      boolean legitimatelyUnpaired = idx == levelSize - 1 && levelSize % 2 == 1;
      if (selfPaired && !legitimatelyUnpaired) {
        return false;
      }
      node = "LEFT".equals(step.siblingPosition())
          ? hashPair(step.siblingHash(), node)
          : hashPair(node, step.siblingHash());
      idx /= 2;
      levelSize = (levelSize + 1) / 2;
    }
    return node.equals(root);
  }

  /** The DEWP intyga.v1 profile row (18 fields, tenantSeq last). Nulls are significant and signed. */
  public record AuditLeaf(
      String seq,
      String tenantSeq,
      String createdAt,
      String event,
      String outcome,
      String detail,
      Object metadata,
      String signerDid,
      String signerPublicKey,
      String signedPayload,
      String signature,
      String sigAlg,
      boolean isBillable,
      String tenantId,
      String actorNodeId,
      String subjectNodeId,
      String edgeId,
      String challengeId) {}

  /**
   * The 18-element JCS array; {@code metadata} is embedded as its own JCS string. Throws
   * {@link Canonical.NonPortableValueException} when metadata carries a number the ports
   * canonicalize differently (DEWP §4.3.1) — a conformant producer never commits such a value, so
   * this is reachable only for a foreign or legacy leaf. This port refuses, like Go, surfacing "I
   * cannot canonicalize this" instead of a hash the TS/Rust/Python verifiers would compute
   * differently.
   */
  public static String canonicalPreimage(AuditLeaf row) {
    String metadataStr =
        row.metadata() == null ? "null" : Canonical.stableStringify(row.metadata());
    List<Object> arr = Arrays.asList(
        row.seq(),
        row.createdAt(),
        row.event(),
        row.outcome(),
        row.detail(),
        metadataStr,
        row.signerDid(),
        row.signerPublicKey(),
        row.signedPayload(),
        row.signature(),
        row.sigAlg(),
        row.isBillable(),
        row.tenantId(),
        row.actorNodeId(),
        row.subjectNodeId(),
        row.edgeId(),
        row.challengeId(),
        row.tenantSeq());
    return Canonical.stableStringify(arr);
  }

  /** Leaf hash over the full row content. Throws only when {@link #canonicalPreimage} does. */
  public static String leafHash(AuditLeaf row) {
    return hashLeaf(canonicalPreimage(row));
  }

  /**
   * A two-hop DEWP proof. The four position fields are REQUIRED by the normative inclusion-proof
   * JSON Schema and by DEWP §3 invariant 3; a proof that cannot say where its leaf sits does not
   * establish inclusion.
   */
  public record InclusionProof(
      String leaf,
      String blockRoot,
      List<LedgerProofStep> blockProof,
      int leafIndex,
      int blockLeafCount,
      List<LedgerProofStep> checkpointProof,
      int checkpointLeafIndex,
      int checkpointLeafCount,
      String checkpointRoot) {}

  /**
   * Leaf → block root, then hashLeaf(block root) → daily root, each hop bounded by its position
   * (DEWP §3 invariant 3, steps 1 and 2).
   */
  public static boolean verifyInclusionProof(InclusionProof proof, String dailyRoot) {
    if (!verifyMerkleProof(
        proof.leaf(),
        proof.blockProof(),
        proof.blockRoot(),
        new ProofBounds(proof.leafIndex(), proof.blockLeafCount()))) {
      return false;
    }
    return verifyMerkleProof(
        hashLeaf(proof.blockRoot()),
        proof.checkpointProof(),
        dailyRoot,
        new ProofBounds(proof.checkpointLeafIndex(), proof.checkpointLeafCount()));
  }

  /** The signable part of an anchor (DEWP §5.2). */
  public record AnchorInput(String dailyRoot, String timestamp, String issuer, String algorithm) {}

  /** JCS of [dailyRoot, timestamp, issuer, algorithm]. */
  public static String anchorPreimage(AnchorInput a) {
    // `issuer` is a URL and can carry a query string, so it needs JS-compatible string escaping
    // too. All four elements are strings, so the non-portable-number refusal is unreachable here.
    return Canonical.stableStringify(
        Arrays.asList(nz(a.dailyRoot()), nz(a.timestamp()), nz(a.issuer()), nz(a.algorithm())));
  }

  /**
   * The RAW 32-byte anchor digest, sha256(0x03 || UTF8(anchorPreimage)). These bytes — never their
   * hex text — are the message an anchor issuer signs (DEWP §5.2).
   */
  private static byte[] anchorDigest(AnchorInput a) {
    byte[] preimage = anchorPreimage(a).getBytes(StandardCharsets.UTF_8);
    byte[] buf = new byte[1 + preimage.length];
    buf[0] = 0x03;
    System.arraycopy(preimage, 0, buf, 1, preimage.length);
    return WebAuthnSupport.sha256(buf);
  }

  /** sha256(0x03 || UTF8(anchorPreimage)) as lowercase hex. */
  public static String anchorDigestHex(AnchorInput a) {
    return HEX.formatHex(anchorDigest(a));
  }

  /** An anchor plus its issuer's base64 ECDSA signature over the raw anchor digest (DEWP §5.2). */
  public record SignedAnchor(
      String dailyRoot,
      String timestamp,
      String issuer,
      String algorithm,
      String keyId,
      String signature) {

    public AnchorInput anchorInput() {
      return new AnchorInput(dailyRoot, timestamp, issuer, algorithm);
    }
  }

  /**
   * Verifies one anchor's ES256 signature against a base64 SPKI P-256 public key the CALLER
   * resolved from its own trust policy. Core Profile scope, deliberately: single anchor, ES256
   * only — no Ed25519/RSA-PSS, and no §5.3 quorum or issuer-trust evaluation, so
   * {@code anchorVerified} still cannot be established by this port alone.
   *
   * <p>The signed MESSAGE is the raw 32-byte digest, never its 64-character hex text; ES256 then
   * applies its own SHA-256 internally. An implementation that signs the hex matches every digest
   * vector and still fails to interoperate — the §5.2 trap the shared signedAnchor vectors catch.
   * Both DER and raw P1363 signatures are accepted, matching the receipt path.
   */
  public static boolean verifyAnchorSignature(SignedAnchor anchor, String spkiB64) {
    if (!"ES256".equals(anchor.algorithm())) {
      return false;
    }
    byte[] keyDer;
    byte[] sig;
    try {
      keyDer = Base64.getDecoder().decode(spkiB64);
      sig = Base64.getDecoder().decode(anchor.signature());
    } catch (IllegalArgumentException e) {
      return false;
    }
    ECPublicKey pub;
    try {
      pub = Ecdsa.parseSpkiP256(keyDer);
    } catch (Ecdsa.Refusal e) {
      return false;
    }
    return Ecdsa.verifySignature(pub, anchorDigest(anchor.anchorInput()), sig);
  }

  private static String nz(String s) {
    return s == null ? "" : s;
  }

  private Ledger() {}
}
