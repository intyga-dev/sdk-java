package com.intyga.verify;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.LinkedHashSet;
import java.util.function.Function;

/**
 * DEWP audit-ledger verification (docs/DEWP.md) — Java port. Its portable canonical primitives match
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
    // A total boolean predicate, like the TS reference: this package is the trust anchor a relying
    // party calls, and a missing bounds/proof must refuse rather than throw out of a method whose
    // whole contract is "true or false".
    if (bounds == null || proof == null) {
      return false;
    }
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
      if (step == null || !isHash64(step.siblingHash())) {
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
      String checkpointRoot, String seq, String anchorRef, Boolean anchored,
      Boolean externallyAnchored, Integer externallyAnchoredRequired) {
    public InclusionProof(String leaf, String blockRoot, List<LedgerProofStep> blockProof,
        int leafIndex, int blockLeafCount, List<LedgerProofStep> checkpointProof,
        int checkpointLeafIndex, int checkpointLeafCount, String checkpointRoot) {
      this(leaf, blockRoot, blockProof, leafIndex, blockLeafCount, checkpointProof,
          checkpointLeafIndex, checkpointLeafCount, checkpointRoot, null, null, null, null, null);
    }
  }

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
      String signature,
      String kind,
      String evidence) {

    /** Source-compatible Core constructor retained for sdk-java and existing consumers. */
    public SignedAnchor(String dailyRoot, String timestamp, String issuer, String algorithm,
        String keyId, String signature) {
      this(dailyRoot, timestamp, issuer, algorithm, keyId, signature, null, null);
    }

    public AnchorInput anchorInput() {
      return new AnchorInput(dailyRoot, timestamp, issuer, algorithm);
    }
  }

  public record AnchorPolicy(int requiredAnchors, List<String> trustedIssuers, String quorum) {}
  public record AnchorQuorumResult(boolean ok, List<String> verifiedIssuers, boolean divergence,
      String reason, String note) {}

  /** Full §5.2 verifier for ES256, Ed25519 and RSA-PSS. Unknown algorithms fail closed. */
  public static boolean verifyAnchorSignature(SignedAnchor anchor, PublicKey key) {
    try {
      byte[] sig = Base64.getDecoder().decode(anchor.signature());
      Signature verifier;
      switch (anchor.algorithm()) {
        case "ES256" -> {
          ECPublicKey ec = Ecdsa.parseSpkiP256(key.getEncoded());
          return Ecdsa.verifySignature(ec, anchorDigest(anchor.anchorInput()), sig);
        }
        case "Ed25519" -> verifier = Signature.getInstance("Ed25519");
        case "RSA-PSS" -> {
          if (!(key instanceof java.security.interfaces.RSAPublicKey rsa)) return false;
          int saltLength = pssSaltLength(rsa, sig);
          if (saltLength < 0) return false;
          verifier = Signature.getInstance("RSASSA-PSS");
          verifier.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, saltLength, 1));
        }
        default -> { return false; }
      }
      verifier.initVerify(key); verifier.update(anchorDigest(anchor.anchorInput())); return verifier.verify(sig);
    } catch (Exception e) { return false; }
  }

  /**
   * Recover only the PSS salt length so the JDK can verify with the same AUTO-salt semantics as
   * Node/OpenSSL. This is not an acceptance check: Signature.verify still verifies the entire
   * encoding and message. RFC 8017 section 9.1.2, SHA-256/MGF1-SHA256.
   */
  private static int pssSaltLength(java.security.interfaces.RSAPublicKey key, byte[] signature)
      throws java.security.GeneralSecurityException {
    int bits = key.getModulus().bitLength() - 1;
    int length = (bits + 7) / 8;
    if (length < 34 || signature.length != (key.getModulus().bitLength() + 7) / 8) return -1;
    var value = new java.math.BigInteger(1, signature);
    if (value.compareTo(key.getModulus()) >= 0) return -1;
    byte[] recovered = value.modPow(key.getPublicExponent(), key.getModulus()).toByteArray();
    int offset = recovered.length > 1 && recovered[0] == 0 ? 1 : 0;
    if (recovered.length - offset > length) return -1;
    byte[] em = new byte[length];
    System.arraycopy(recovered, offset, em, length - recovered.length + offset, recovered.length - offset);
    if ((em[length - 1] & 255) != 0xbc) return -1;
    int dbLength = length - 33;
    byte[] h = Arrays.copyOfRange(em, dbLength, length - 1);
    byte[] db = Arrays.copyOf(em, dbLength);
    var hash = java.security.MessageDigest.getInstance("SHA-256");
    for (int i = 0, pos = 0; pos < dbLength; i++) {
      hash.update(h);
      byte[] mask = hash.digest(java.nio.ByteBuffer.allocate(4).putInt(i).array());
      for (int j = 0; j < mask.length && pos < dbLength; j++, pos++) db[pos] ^= mask[j];
    }
    db[0] &= (byte) (0xff >>> (8 * length - bits));
    int delimiter = 0;
    while (delimiter < dbLength && db[delimiter] == 0) delimiter++;
    return delimiter < dbLength && db[delimiter] == 1 ? dbLength - delimiter - 1 : -1;
  }

  /** Parses a PEM or base64 SPKI public key for the declared anchor algorithm. */
  public static PublicKey parseAnchorPublicKey(String encoded, String algorithm) {
    try {
      String clean = encoded.replaceAll("-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\\s", "");
      byte[] der = Base64.getDecoder().decode(clean);
      String kf = switch (algorithm) { case "ES256" -> "EC"; case "Ed25519" -> "Ed25519"; case "RSA-PSS" -> "RSA"; default -> throw new IllegalArgumentException(); };
      return "ES256".equals(algorithm) ? Ecdsa.parseSpkiP256(der)
          : KeyFactory.getInstance(kf).generatePublic(new X509EncodedKeySpec(der));
    } catch (Exception e) { return null; }
  }

  /** Evaluate distinct trusted issuers over one root, including independently pinned Rekor evidence. */
  public static AnchorQuorumResult verifyAnchorQuorum(
      List<SignedAnchor> anchors, String dailyRoot, AnchorPolicy policy,
      Function<SignedAnchor, PublicKey> resolver, List<SignedAnchor> divergenceAnchors,
      String rekorPublicKey) {
    try {
      return verifyAnchorQuorumChecked(anchors, dailyRoot, policy, resolver, divergenceAnchors, rekorPublicKey);
    } catch (RuntimeException e) {
      return new AnchorQuorumResult(false, List.of(), false, "malformed anchor quorum input", null);
    }
  }

  private static AnchorQuorumResult verifyAnchorQuorumChecked(
      List<SignedAnchor> anchors, String dailyRoot, AnchorPolicy policy,
      Function<SignedAnchor, PublicKey> resolver, List<SignedAnchor> divergenceAnchors,
      String rekorPublicKey) {
    if (policy == null || policy.requiredAnchors() < 1 || policy.trustedIssuers() == null
        || !("ALL_MUST_AGREE".equals(policy.quorum()) || "N_OF_M".equals(policy.quorum())))
      return new AnchorQuorumResult(false, List.of(), false, "requiredAnchors must be at least 1", null);
    Set<String> trusted = Set.copyOf(policy.trustedIssuers());
    if (divergenceAnchors != null) for (SignedAnchor a : divergenceAnchors) {
      if (!trusted.contains(a.issuer()) || dailyRoot.equals(a.dailyRoot())) continue;
      PublicKey k = resolver == null ? null : resolver.apply(a);
      if (k != null && verifyAnchorSignature(a, k)) return new AnchorQuorumResult(false, List.of(), true,
          "anchor divergence: issuer " + a.issuer() + " signed a different root for this checkpoint", null);
    }
    Set<String> verified = new LinkedHashSet<>(); boolean tsa = false;
    for (SignedAnchor a : anchors == null ? List.<SignedAnchor>of() : anchors) {
      if (!dailyRoot.equals(a.dailyRoot()) || !trusted.contains(a.issuer()) || verified.contains(a.issuer())) continue;
      String kind = a.kind() == null ? "SELF" : a.kind(); boolean ok = false;
      if ("SELF".equals(kind)) { PublicKey k = resolver == null ? null : resolver.apply(a); ok = k != null && verifyAnchorSignature(a, k); }
      else if ("REKOR".equals(kind) && rekorPublicKey != null) ok = Rekor.verifyAnchor(a, rekorPublicKey).ok();
      else if ("RFC3161".equals(kind)) tsa = true;
      if (ok) verified.add(a.issuer());
    }
    List<String> issuers = new ArrayList<>(verified); issuers.sort(String::compareTo);
    long present = (anchors == null ? List.<SignedAnchor>of() : anchors).stream()
        .filter(a -> dailyRoot.equals(a.dailyRoot()) && trusted.contains(a.issuer()))
        .map(SignedAnchor::issuer).distinct().count();
    long need = "ALL_MUST_AGREE".equals(policy.quorum())
        ? Math.max(policy.requiredAnchors(), present) : policy.requiredAnchors();
    boolean ok = issuers.size() >= need;
    return new AnchorQuorumResult(ok, issuers, false, ok ? null : "anchor quorum not met (" + issuers.size() + "/" + need + ")",
        tsa ? "RFC 3161 evidence is present but this zero-dependency verifier cannot evaluate CMS TimeStampTokens" : null);
  }

  public static final int CHAIN_TAG = 0x04;
  public record RootsChainEntry(String seqStart, String seqEnd, int entryCount, String root,
      String anchoredAt, String prevChainHash, String chainHash) {}
  public record ChainVerification(boolean ok, int verifiedCount, int brokenAt, String reason,
      boolean unchained) {}

  public static String chainPreimage(String prevChainHash, String root, String seqStart,
      String seqEnd, int entryCount, String anchoredAt) {
    return Canonical.stableStringify(Arrays.asList(prevChainHash, root, seqStart, seqEnd,
        String.valueOf(entryCount), anchoredAt));
  }

  public static String chainHash(String prevChainHash, String root, String seqStart,
      String seqEnd, int entryCount, String anchoredAt) {
    byte[] p = chainPreimage(prevChainHash, root, seqStart, seqEnd, entryCount, anchoredAt).getBytes(StandardCharsets.UTF_8);
    byte[] b = new byte[p.length + 1]; b[0] = (byte) CHAIN_TAG; System.arraycopy(p, 0, b, 1, p.length);
    return sha256Hex(b);
  }

  public static ChainVerification verifyRootsChain(List<RootsChainEntry> entries) {
    if (entries == null || entries.isEmpty()) return new ChainVerification(true, 0, -1, null, false);
    boolean allMissing = entries.stream().allMatch(e -> e.chainHash() == null);
    if (allMissing) return new ChainVerification(false, 0, -1, "roots file carries no chain hashes (pre-DEWP-5.4 v1 file); continuity cannot be checked", true);
    // A partially chained file means old and new lines were spliced together; refuse to guess which
    // half is authentic. Decided BEFORE the loop, reporting the first unchained index and a count of
    // zero, because nothing in a spliced file has been established — the other four ports all do
    // this, while Java used to fall into the loop and credit the entries preceding the splice.
    for (int i = 0; i < entries.size(); i++) {
      if (entries.get(i).chainHash() == null) {
        return new ChainVerification(false, 0, i, "roots file mixes chained and unchained entries", false);
      }
    }
    String prev = "";
    java.math.BigInteger prevEnd = null;
    for (int i = 0; i < entries.size(); i++) {
      RootsChainEntry e = entries.get(i);
      if (!nz(e.prevChainHash()).equals(prev)) return new ChainVerification(false, i, i, "prevChainHash does not match preceding entry", false);
      String expected = chainHash(nz(e.prevChainHash()), e.root(), e.seqStart(), e.seqEnd(), e.entryCount(), e.anchoredAt());
      if (!expected.equals(e.chainHash())) return new ChainVerification(false, i, i, "chainHash does not match entry content", false);
      // The entry's OWN range is checked unconditionally: a non-integer or self-inverted range is
      // malformed wherever it sits, and gating it on i > 0 left the FIRST entry unchecked, so a
      // single-entry roots file was never range-checked. Only the overlap check is relational.
      java.math.BigInteger start;
      java.math.BigInteger end;
      try {
        start = new java.math.BigInteger(e.seqStart());
        end = new java.math.BigInteger(e.seqEnd());
      } catch (NumberFormatException ex) { return new ChainVerification(false, i, i, "non-integer seq range", false); }
      if (end.compareTo(start) < 0) return new ChainVerification(false, i, i, "seq range inverted", false);
      if (prevEnd != null && start.compareTo(prevEnd) <= 0) return new ChainVerification(false, i, i, "seq ranges overlap or regress", false);
      prev = e.chainHash();
      prevEnd = end;
    }
    return new ChainVerification(true, entries.size(), -1, null, false);
  }

  /** Verify one anchor under a caller-pinned PEM or base64 SPKI public key. */
  public static boolean verifyAnchorSignature(SignedAnchor anchor, String spkiB64) {
    if (anchor == null) return false;
    PublicKey key = parseAnchorPublicKey(spkiB64, anchor.algorithm());
    return key != null && verifyAnchorSignature(anchor, key);
  }

  private static String nz(String s) {
    return s == null ? "" : s;
  }

  private Ledger() {}
}
