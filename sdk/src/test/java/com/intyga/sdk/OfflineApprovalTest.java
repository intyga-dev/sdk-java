package com.intyga.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.intyga.sdk.offline.AnchorPurpose;
import com.intyga.sdk.offline.ApprovalPolicy;
import com.intyga.sdk.offline.ApprovalPolicyConflict;
import com.intyga.sdk.offline.BundlePolicy;
import com.intyga.sdk.offline.ChallengeRequest;
import com.intyga.sdk.offline.ChallengeResult;
import com.intyga.sdk.offline.FileRedemptionStore;
import com.intyga.sdk.offline.OfflineAction;
import com.intyga.sdk.offline.OfflineApproval;
import com.intyga.sdk.offline.OfflineApprovalOptions;
import com.intyga.sdk.offline.OfflineApprovalResult;
import com.intyga.sdk.offline.PendingApproval;
import com.intyga.sdk.offline.SignResult;
import com.intyga.sdk.offline.TrustBundle;
import com.intyga.sdk.offline.TrustBundleResult;
import com.intyga.verify.ApprovalReceipt;
import com.intyga.verify.ApprovalRequirement;
import com.intyga.verify.ApprovalWitness;
import com.intyga.verify.Canonical;
import com.intyga.verify.Expected;
import com.intyga.verify.RequesterIdentity;
import com.intyga.verify.Verify;
import com.intyga.verify.VerifyOptions;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * What the shared vectors do not reach: single use under a race, the pending-record lifecycle, path
 * safety, the key forms an approver's tool accepts, file modes, and the JS-identical timestamps.
 */
class OfflineApprovalTest {

  private static final ObjectMapper JSON = new ObjectMapper();
  private static final boolean POSIX = FileSystems.getDefault().supportedFileAttributeViews().contains("posix");

  static final JsonNode V = load();
  static final Instant AS_OF = Instant.parse("2026-10-06T12:00:00.123Z");
  static final String TARGET = "prod-db-cluster-01";
  static final Map<String, Object> PARAMS = Map.of("cluster", "primary", "replicas", List.of(1, 2));

  @TempDir Path tmp;

  static JsonNode load() {
    try {
      return JSON.readTree(Files.readString(Path.of("vectors/offline-approval-vectors.json")));
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  /** A bundle directory holding the vectors' signed bundle and pinned key. */
  static Path bundleDir(Path parent) throws IOException {
    Path dir = Files.createTempDirectory(parent, "bundle-");
    TrustBundle.save(dir, V.get("bundleJws").textValue(), V.get("gatewayJwk"));
    return dir;
  }

  /** Alice's and Bob's offline signatures over whatever challenge arrives. */
  static List<String> aliceAndBob(String canonicalPayload) {
    List<String> out = new ArrayList<>();
    for (String who : List.of("alice", "bob")) {
      out.add(OfflineApproval.encodeSignatureEnvelope(new ApprovalWitness(
          OfflineApprovalVectorsTest.person(who).get("did").textValue(),
          OfflineApprovalVectorsTest.keyOf(who, "offline").get("spki").textValue(),
          OfflineApprovalVectorsTest.sign(who, "offline", canonicalPayload),
          "ES256",
          null,
          null)));
    }
    return out;
  }

  static OfflineAction restart() {
    return new OfflineAction(TARGET, "db.restart", "Restart the primary database", PARAMS);
  }

  static PrivateKey aliceOffline() {
    return OfflineApprovalVectorsTest.keyFromSeed(
        OfflineApprovalVectorsTest.keyOf("alice", "offline").get("seed").textValue());
  }

  static String validChallengeEnvelope() {
    for (JsonNode c : V.get("challengeEnvelope")) {
      if ("valid".equals(c.get("name").textValue())) {
        return c.get("envelope").textValue();
      }
    }
    throw new IllegalStateException("no valid challenge envelope vector");
  }

  // --- single use ---------------------------------------------------------------------------------

  @Test
  void redemptionIsSingleUseAcrossStoreInstances() throws IOException {
    Path dir = tmp.resolve(".redeemed");
    FileRedemptionStore store = new FileRedemptionStore(dir);
    assertTrue(store.redeem("off_one"));
    assertFalse(store.redeem("off_one"), "a second claim must fail");
    assertFalse(new FileRedemptionStore(dir).redeem("off_one"), "another store over the same dir too");
    assertTrue(store.redeem("off_two"));
    assertTrue(Files.isRegularFile(dir.resolve("off_one.used")));
    assertTrue(Files.readString(dir.resolve("off_one.used")).matches("\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\d\\.\\d{3}Z"));
    if (POSIX) {
      assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(dir)));
      assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(dir.resolve("off_one.used"))));
    }
  }

  @Test
  void unsafeNonceIsNeverRedeemedOrUsedAsAPath() {
    FileRedemptionStore store = new FileRedemptionStore(tmp.resolve("store"));
    for (String bad : List.of("../escape", "a/b", "", "x".repeat(201), "nul\u0000l", "spa ce")) {
      assertFalse(store.redeem(bad), bad);
    }
    assertFalse(Files.exists(tmp.resolve("escape.used")));
  }

  @Test
  void concurrentRedemptionHasExactlyOneWinner() throws Exception {
    Path dir = tmp.resolve("race");
    int threads = 16;
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    try {
      CountDownLatch start = new CountDownLatch(1);
      List<Future<Boolean>> results = new ArrayList<>();
      for (int i = 0; i < threads; i++) {
        // A store per thread, as separate processes would have.
        Callable<Boolean> claim = () -> {
          start.await();
          return new FileRedemptionStore(dir).redeem("off_race");
        };
        results.add(pool.submit(claim));
      }
      start.countDown();
      int winners = 0;
      for (Future<Boolean> f : results) {
        winners += f.get() ? 1 : 0;
      }
      assertEquals(1, winners);
    } finally {
      pool.shutdownNow();
    }
  }

  @Test
  void storeRefusesASymlinkedDirectory() throws IOException {
    Path real = Files.createDirectory(tmp.resolve("real"));
    Path link = tmp.resolve("link");
    try {
      Files.createSymbolicLink(link, real);
    } catch (UnsupportedOperationException | IOException e) {
      return; // platform without symlinks
    }
    assertThrows(java.io.UncheckedIOException.class, () -> new FileRedemptionStore(link));
  }

  // --- the pending record lifecycle ----------------------------------------------------------------

  @Test
  void approvalIsBufferedRedeemedAndClearable() throws IOException {
    Path dir = bundleDir(tmp);
    List<String> warnings = new ArrayList<>();
    OfflineApprovalResult r = OfflineApproval.useOfflineApproval(restart(), OfflineApprovalOptions.builder()
        .bundleDir(dir)
        .requesterDid("did:intyga:service:oncall")
        .asOf(AS_OF)
        .warn(warnings::add)
        .collectSignatures(ch -> aliceAndBob(ch.canonicalPayload()))
        .build());
    assertTrue(r.ok(), r.reason());
    assertTrue(r.nonce().startsWith("off_"), r.nonce());
    assertEquals(List.of("did:intyga:alice", "did:intyga:bob"), r.signers());
    assertNull(r.viaDelegation());
    assertTrue(warnings.get(warnings.size() - 1).startsWith("⚠ OFFLINE APPROVAL USED"), warnings.toString());
    assertTrue(Files.exists(dir.resolve(".redeemed").resolve(r.nonce() + ".used")));

    List<PendingApproval> pending = OfflineApproval.pendingApprovals(dir, null);
    assertEquals(1, pending.size());
    PendingApproval p = pending.get(0);
    assertEquals(r.nonce(), p.nonce());
    assertEquals(TARGET, p.target());
    assertEquals("db.restart", p.actionType());
    assertEquals("Restart the primary database", p.display());
    assertNotNull(p.usedAt());
    assertNull(p.delegationNonce());
    assertFalse(p.receipt().has("delegationNonce"));
    assertTrue(p.receipt().get("requester").has("attestation"), "the signed null attestation is kept");
    Path file = dir.resolve(".pending").resolve(r.nonce() + ".json");
    if (POSIX) {
      assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(file)));
      assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(file.getParent())));
    }

    // What is buffered is exactly what verifies: the stored receipt re-verifies on its own.
    ApprovalReceipt stored = ApprovalReceipt.parse(p.receipt());
    TrustBundle bundle = TrustBundle.load(dir, AS_OF).bundle();
    var check = Verify.verifyApprovalReceipt(stored,
        new Expected(TARGET, r.nonce(), "db.restart", PARAMS,
            bundle.approverAnchor(List.of("did:intyga:alice", "did:intyga:bob"), AnchorPurpose.OFFLINE_INTENT)),
        VerifyOptions.builder().allowOffline(true).asOf(AS_OF).build());
    assertTrue(check.ok(), check.reason());

    OfflineApproval.clearPendingApproval(r.nonce(), dir, null);
    assertEquals(List.of(), OfflineApproval.pendingApprovals(dir, null));
  }

  @Test
  void aNonceThatCannotBeClaimedLeavesNoPendingRecord() throws IOException {
    Path dir = bundleDir(tmp);
    OfflineApprovalResult r = OfflineApproval.useOfflineApproval(restart(), OfflineApprovalOptions.builder()
        .bundleDir(dir)
        .requesterDid("did:intyga:service:oncall")
        .asOf(AS_OF)
        .warn(m -> {})
        .store(nonce -> false)
        .collectSignatures(ch -> aliceAndBob(ch.canonicalPayload()))
        .build());
    assertFalse(r.ok());
    assertTrue(r.reason().contains("already been redeemed"), r.reason());
    assertEquals(List.of(), OfflineApproval.pendingApprovals(dir, null));
  }

  @Test
  void clearNeverNamesAPathOutsideTheBuffer() throws IOException {
    Path outside = Files.writeString(tmp.resolve("outside.json"), "{}");
    Path buffer = Files.createDirectory(tmp.resolve("buffer"));
    OfflineApproval.clearPendingApproval("../outside", tmp, buffer);
    assertTrue(Files.exists(outside));
  }

  @Test
  void aCorruptPendingRecordDoesNotHideTheOthers() throws IOException {
    Path buffer = Files.createDirectory(tmp.resolve("pending"));
    Files.writeString(buffer.resolve("a.json"), "{not json");
    Files.writeString(buffer.resolve("b.json"), "{\"nonce\":\"b\",\"receipt\":{}}");
    Files.writeString(buffer.resolve("c.txt"), "{\"nonce\":\"c\"}");
    Files.writeString(buffer.resolve("d.json"), "{\"nonce\":7}");
    List<PendingApproval> pending = OfflineApproval.pendingApprovals(tmp, buffer);
    assertEquals(1, pending.size());
    assertEquals("b", pending.get(0).nonce());
    assertEquals(List.of("a.json", "d.json"), OfflineApproval.readPendingApprovals(tmp, buffer).unreadable());
  }

  // --- challenge details ---------------------------------------------------------------------------

  @Test
  void timestampsAreToIsoStringExactly() {
    TrustBundle bundle = TrustBundle.parseUnverified(V.get("bundle"));
    for (var c : List.of(
        new String[] {"2026-10-06T12:00:00Z", "2026-10-06T12:00:00.000Z", "2026-10-06T12:15:00.000Z"},
        new String[] {"2026-10-06T12:00:00.123456789Z", "2026-10-06T12:00:00.123Z", "2026-10-06T12:15:00.123Z"},
        new String[] {"2026-10-06T23:59:59.999Z", "2026-10-06T23:59:59.999Z", "2026-10-07T00:14:59.999Z"})) {
      ChallengeResult r = OfflineApproval.createOfflineChallenge(ChallengeRequest.builder()
          .bundle(bundle).target(TARGET).actionType("db.restart").display("d").params(PARAMS)
          .requester(new RequesterIdentity("did:intyga:service:oncall", null))
          .asOf(Instant.parse(c[0])).nonce("off_time").build());
      assertTrue(r.ok(), r.reason());
      assertEquals(c[1], r.challenge().challengedAt(), c[0]);
      assertEquals(c[2], r.challenge().expiresAt(), c[0]);
    }
  }

  @Test
  void defaultNonceIsOffPlusUuidAndBlankTargetIsRefused() {
    TrustBundle bundle = TrustBundle.parseUnverified(V.get("bundle"));
    ChallengeRequest.Builder base = ChallengeRequest.builder()
        .bundle(bundle).actionType("db.restart").display("d").params(PARAMS)
        .requester(new RequesterIdentity("did:intyga:service:oncall", null)).asOf(AS_OF);
    ChallengeResult r = OfflineApproval.createOfflineChallenge(base.target(TARGET).build());
    assertTrue(r.challenge().nonce().matches("off_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"));
    assertFalse(OfflineApproval.createOfflineChallenge(base.target("  ").build()).ok());
    assertFalse(OfflineApproval.createOfflineChallenge(base.target(null).build()).ok());
  }

  // --- signing as an approver ------------------------------------------------------------------------

  @Test
  void signsFromEveryAcceptedKeyForm() throws Exception {
    String envelope = validChallengeEnvelope();
    String expectedKey = OfflineApprovalVectorsTest.keyOf("alice", "offline").get("spki").textValue();
    PrivateKey key = aliceOffline();
    byte[] der = key.getEncoded();
    String pem = "-----BEGIN PRIVATE KEY-----\n"
        + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der)
        + "\n-----END PRIVATE KEY-----\n";
    PublicKey pub = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(expectedKey)));
    List<SignResult> results = List.of(
        OfflineApproval.signChallengeEnvelope(envelope, key, "did:intyga:alice", AS_OF),
        OfflineApproval.signChallengeEnvelope(envelope, der, "did:intyga:alice", AS_OF),
        OfflineApproval.signChallengeEnvelope(envelope, pem.getBytes(StandardCharsets.US_ASCII), "did:intyga:alice", AS_OF),
        OfflineApproval.signChallengeEnvelope(envelope, pem, "did:intyga:alice", AS_OF),
        OfflineApproval.signChallengeEnvelope(envelope, new KeyPair(pub, key), "did:intyga:alice", AS_OF));
    for (SignResult r : results) {
      assertTrue(r.ok(), r.reason());
      ApprovalWitness w = OfflineApproval.decodeSignatureEnvelope(r.envelope()).witness();
      assertEquals(expectedKey, w.signerPublicKey());
      assertEquals("ES256", w.sigAlg());
      assertEquals(64, Base64.getDecoder().decode(w.signature()).length, "IEEE P1363 r||s");
      assertTrue(OfflineApprovalVectorsTest.verifyWithSpki(expectedKey, r.challenge().canonicalPayload(), w.signature()));
    }
  }

  @Test
  void refusesWrongKeysDidsAndUnreadableExpiry() throws Exception {
    String envelope = validChallengeEnvelope();
    KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
    gen.initialize(new ECGenParameterSpec("secp384r1"));
    KeyPair p384 = gen.generateKeyPair();
    SignResult wrongCurve = OfflineApproval.signChallengeEnvelope(envelope, p384.getPrivate(), "did:intyga:alice", AS_OF);
    assertFalse(wrongCurve.ok());
    assertTrue(wrongCurve.reason().contains("P-256"), wrongCurve.reason());

    KeyPair rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    assertFalse(OfflineApproval.signChallengeEnvelope(envelope, rsa.getPrivate(), "did:intyga:alice", AS_OF).ok());

    assertFalse(OfflineApproval.signChallengeEnvelope(envelope, "not a key", "did:intyga:alice", AS_OF).ok());
    assertFalse(OfflineApproval.signChallengeEnvelope(envelope, new byte[] {1, 2, 3}, "did:intyga:alice", AS_OF).ok());

    SignResult notADid = OfflineApproval.signChallengeEnvelope(envelope, aliceOffline(), "alice", AS_OF);
    assertEquals("signerDid must be a DID", notADid.reason());

    // A mismatched pair is caught: the supplied public key must verify the signature just made.
    KeyPairGenerator p256 = KeyPairGenerator.getInstance("EC");
    p256.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair other = p256.generateKeyPair();
    assertFalse(OfflineApproval.signChallengeEnvelope(envelope, new KeyPair(other.getPublic(), aliceOffline()),
        "did:intyga:alice", AS_OF).ok());

    String canonical = Canonical.canonicalOfflineIntentPayload(TARGET, "db.restart", "d", PARAMS,
        new RequesterIdentity("did:intyga:service:oncall", null),
        new ApprovalRequirement(1, false, List.of(), false, "human"), "off_x", "2026-10-06T12:00:00.123Z", "soon");
    String unreadable = "DIV1:" + Base64.getUrlEncoder().withoutPadding().encodeToString(canonical.getBytes(StandardCharsets.UTF_8));
    SignResult r = OfflineApproval.signChallengeEnvelope(unreadable, aliceOffline(), "did:intyga:alice", AS_OF);
    assertFalse(r.ok());
    assertTrue(r.reason().contains("expiresAt is not a valid"), r.reason());
  }

  // --- SEC1 ("EC PRIVATE KEY", RFC 5915) — what `openssl ecparam -genkey` writes -------------------

  static final byte[] P256_OID = {0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x03, 0x01, 0x07};
  static final byte[] P384_OID = {0x2B, (byte) 0x81, 0x04, 0x00, 0x22};

  static byte[] tlv(int tag, byte[]... parts) {
    java.io.ByteArrayOutputStream content = new java.io.ByteArrayOutputStream();
    for (byte[] p : parts) {
      content.writeBytes(p);
    }
    int n = content.size();
    java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
    out.write(tag);
    if (n < 0x80) {
      out.write(n);
    } else {
      out.write(0x81);
      out.write(n);
    }
    out.writeBytes(content.toByteArray());
    return out.toByteArray();
  }

  /** An RFC 5915 ECPrivateKey; {@code params} is the [0] content (null to omit), {@code point} the [1] key. */
  static byte[] sec1(int version, byte[] scalar, byte[] params, byte[] point) {
    List<byte[]> parts = new ArrayList<>(List.of(tlv(0x02, new byte[] {(byte) version}), tlv(0x04, scalar)));
    if (params != null) {
      parts.add(tlv(0xA0, params));
    }
    if (point != null) {
      parts.add(tlv(0xA1, tlv(0x03, new byte[] {0}, point)));
    }
    return tlv(0x30, parts.toArray(new byte[0][]));
  }

  /** PEM armor composed at run time: no private-key block literal in source (secret scanning). */
  static String armor(String label, byte[] der) {
    return "-----BEGIN " + label + "-----\n"
        + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der)
        + "\n-----END " + label + "-----\n";
  }

  static byte[] aliceScalar() {
    byte[] s = ((java.security.interfaces.ECPrivateKey) aliceOffline()).getS().toByteArray();
    byte[] out = new byte[32];
    int copy = Math.min(32, s.length);
    System.arraycopy(s, s.length - copy, out, 32 - copy, copy);
    return out;
  }

  static byte[] alicePoint() {
    byte[] spki = Base64.getDecoder().decode(OfflineApprovalVectorsTest.keyOf("alice", "offline").get("spki").textValue());
    return java.util.Arrays.copyOfRange(spki, spki.length - 65, spki.length);
  }

  @Test
  void signsFromASec1Pem() {
    String envelope = validChallengeEnvelope();
    String expectedKey = OfflineApprovalVectorsTest.keyOf("alice", "offline").get("spki").textValue();
    byte[] oid = tlv(0x06, P256_OID);
    List<String> accepted = List.of(
        // openssl ecparam -name prime256v1 -genkey: an EC PARAMETERS block, then the key with both.
        armor("EC PARAMETERS", oid) + armor("EC PRIVATE KEY", sec1(1, aliceScalar(), oid, alicePoint())),
        armor("EC PRIVATE KEY", sec1(1, aliceScalar(), oid, null)),
        armor("EC PRIVATE KEY", sec1(1, aliceScalar(), null, alicePoint())),
        armor("EC PRIVATE KEY", sec1(1, aliceScalar(), null, null)));
    for (String pem : accepted) {
      for (SignResult r : List.of(
          OfflineApproval.signChallengeEnvelope(envelope, pem, "did:intyga:alice", AS_OF),
          OfflineApproval.signChallengeEnvelope(envelope, pem.getBytes(StandardCharsets.US_ASCII), "did:intyga:alice", AS_OF))) {
        assertTrue(r.ok(), r.reason());
        ApprovalWitness w = OfflineApproval.decodeSignatureEnvelope(r.envelope()).witness();
        assertEquals(expectedKey, w.signerPublicKey());
        assertTrue(OfflineApprovalVectorsTest.verifyWithSpki(expectedKey, r.challenge().canonicalPayload(), w.signature()));
      }
    }
    // The embedded public key is never trusted: the SPKI is derived from the scalar.
    byte[] otherPoint = Base64.getDecoder().decode(OfflineApprovalVectorsTest.keyOf("bob", "offline").get("spki").textValue());
    otherPoint = java.util.Arrays.copyOfRange(otherPoint, otherPoint.length - 65, otherPoint.length);
    SignResult lying = OfflineApproval.signChallengeEnvelope(envelope,
        armor("EC PRIVATE KEY", sec1(1, aliceScalar(), oid, otherPoint)), "did:intyga:alice", AS_OF);
    assertTrue(lying.ok(), lying.reason());
    assertEquals(expectedKey, OfflineApproval.decodeSignatureEnvelope(lying.envelope()).witness().signerPublicKey());
  }

  @Test
  void refusesSec1KeysThatAreNotP256OrNotWellFormed() {
    String envelope = validChallengeEnvelope();
    byte[] order = P256_ORDER();
    byte[] explicit = tlv(0x30, tlv(0x02, new byte[] {1}));
    Map<String, String> refused = new java.util.LinkedHashMap<>();
    refused.put("P-384 named curve", armor("EC PRIVATE KEY", sec1(1, new byte[48], tlv(0x06, P384_OID), null)));
    refused.put("explicit curve parameters", armor("EC PRIVATE KEY", sec1(1, aliceScalar(), explicit, null)));
    refused.put("version 2", armor("EC PRIVATE KEY", sec1(2, aliceScalar(), tlv(0x06, P256_OID), null)));
    refused.put("zero scalar", armor("EC PRIVATE KEY", sec1(1, new byte[32], null, null)));
    refused.put("scalar = n", armor("EC PRIVATE KEY", sec1(1, order, null, null)));
    refused.put("33-byte scalar", armor("EC PRIVATE KEY", sec1(1, new byte[33], null, null)));
    byte[] der = sec1(1, aliceScalar(), tlv(0x06, P256_OID), alicePoint());
    refused.put("truncated", armor("EC PRIVATE KEY", java.util.Arrays.copyOf(der, der.length - 10)));
    refused.put("trailing data", armor("EC PRIVATE KEY", java.util.Arrays.copyOf(der, der.length + 2)));
    refused.put("legacy encrypted", armor("EC PRIVATE KEY", der)
        .replaceFirst("KEY-----\n", "KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\n"));
    refused.put("encrypted PKCS#8", armor("ENCRYPTED PRIVATE KEY", der));
    for (Map.Entry<String, String> e : refused.entrySet()) {
      SignResult r = OfflineApproval.signChallengeEnvelope(envelope, e.getValue(), "did:intyga:alice", AS_OF);
      assertFalse(r.ok(), e.getKey());
      assertNull(r.envelope(), e.getKey());
    }
  }

  static byte[] P256_ORDER() {
    byte[] n = new java.math.BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16).toByteArray();
    return java.util.Arrays.copyOfRange(n, n.length - 32, n.length);
  }

  @Test
  void signatureEnvelopeOfJsonNullIsARefusalNotAnException() {
    for (String body : List.of("null", "5", "[]", "\"x\"", "{\"did\":5,\"key\":\"k\",\"sig\":\"s\"}")) {
      String envelope = "SIG1:" + Base64.getUrlEncoder().withoutPadding().encodeToString(body.getBytes(StandardCharsets.UTF_8));
      assertFalse(OfflineApproval.decodeSignatureEnvelope(envelope).ok(), body);
    }
    for (String body : List.of("{\"did\":\"d\",\"key\":\"k\",\"sig\":\"s\",\"alg\":null}",
        "{\"did\":\"d\",\"key\":\"k\",\"sig\":\"s\",\"alg\":\"\"}",
        "{\"did\":\"d\",\"key\":\"k\",\"sig\":\"s\",\"alg\":7}")) {
      String envelope = "SIG1:" + Base64.getUrlEncoder().withoutPadding().encodeToString(body.getBytes(StandardCharsets.UTF_8));
      assertFalse(OfflineApproval.decodeSignatureEnvelope(envelope).ok(), body);
    }
    // Strict base64url: stray characters inside a paste are refused, not skipped.
    String good = OfflineApproval.encodeSignatureEnvelope(new ApprovalWitness("did:intyga:a", "k", "s", "ES256", null, null));
    assertTrue(OfflineApproval.decodeSignatureEnvelope("  " + good + "\n").ok(), "surrounding whitespace is trimmed");
    assertFalse(OfflineApproval.decodeSignatureEnvelope(good.substring(0, 12) + "\n" + good.substring(12)).ok());
    assertFalse(OfflineApproval.decodeSignatureEnvelope(good.substring(0, 12) + "+" + good.substring(12)).ok());
    String trailing = "SIG1:" + Base64.getUrlEncoder().withoutPadding().encodeToString(
        "{\"did\":\"d\",\"key\":\"k\",\"sig\":\"s\"} trailing".getBytes(StandardCharsets.UTF_8));
    assertFalse(OfflineApproval.decodeSignatureEnvelope(trailing).ok(), "JSON.parse refuses trailing text");
    assertFalse(OfflineApproval.decodeChallengeEnvelope("DIV1:" + Base64.getUrlEncoder().encodeToString("null".getBytes(StandardCharsets.UTF_8))).ok());
  }

  // --- the bundle on disk ----------------------------------------------------------------------------

  @Test
  void bundleSaveAndLoadRoundTripPrivately() throws IOException {
    Path dir = tmp.resolve("bundle");
    TrustBundle.save(dir, V.get("bundleJws").textValue(), V.get("gatewayJwk"));
    TrustBundleResult loaded = TrustBundle.load(dir, AS_OF);
    assertTrue(loaded.ok(), loaded.reason());
    assertEquals(4, loaded.bundle().approvers().size());
    assertEquals(V.get("gatewayJwk"), JSON.readTree(Files.readString(dir.resolve("gateway-key.jwk.json"))));
    if (POSIX) {
      assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(dir)));
      for (String f : List.of("trust-bundle.jws", "gateway-key.jwk.json")) {
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(dir.resolve(f))), f);
      }
    }
    // A BOM and surrounding whitespace, as a Windows editor leaves them, are trimmed like JS trim().
    Files.writeString(dir.resolve("trust-bundle.jws"), "\uFEFF  " + V.get("bundleJws").textValue() + "\r\n");
    assertTrue(TrustBundle.load(dir, AS_OF).ok());

    TrustBundleResult missing = TrustBundle.load(tmp.resolve("nowhere"), AS_OF);
    assertFalse(missing.ok());
    assertTrue(missing.reason().contains("intyga trust-bundle export"), missing.reason());
    // Freshness is checked at load: the same files are refused a day after expiry.
    assertFalse(TrustBundle.load(dir, Instant.parse("2026-11-05T12:00:00Z")).ok());
  }

  // --- policy resolution specifics ------------------------------------------------------------------

  static List<BundlePolicy> policy(String json) throws IOException {
    List<BundlePolicy> out = new ArrayList<>();
    for (JsonNode n : JSON.readTree(json)) {
      out.add(BundlePolicy.fromJson(n));
    }
    return out;
  }

  static String rule(String pattern, int quorum, String dids) {
    return "{\"signerClass\":\"human\",\"actionPattern\":\"" + pattern + "\",\"requiredApprovals\":" + quorum
        + ",\"requireHardwareKey\":false,\"allowedAaguids\":[],\"requesterCannotApprove\":false,"
        + "\"requireAttestedRequester\":false,\"allowedIssuers\":[],\"escalationApproverDids\":[],"
        + "\"escalateAfterSeconds\":null,\"autoApproveRequesterDid\":null,\"autoApproveDayOfWeek\":null,"
        + "\"autoApproveWindowStart\":null,\"autoApproveWindowEnd\":null,\"approverDids\":" + dids + "}";
  }

  @Test
  void exactPolicyConflictsCarryTheReferenceFieldNames() throws IOException {
    List<BundlePolicy> ok = policy("[" + rule("*", 1, "[\"a\",\"b\"]") + "," + rule("db.restart", 2, "[\"a\",\"b\"]") + "]");
    assertTrue(ok.stream().allMatch(BundlePolicy::complete));
    assertEquals("db.restart", ApprovalPolicy.selectExactApprovalRule(ok, "db.restart", "DENY").orElseThrow().actionPattern());
    assertTrue(ApprovalPolicy.selectExactApprovalRule(ok, "cache.flush", "DENY").isEmpty());
    assertEquals("*", ApprovalPolicy.selectExactApprovalRule(ok, "cache.flush", "BASELINE").orElseThrow().actionPattern());

    assertEquals(List.of("actionIdCaseMismatch"),
        assertThrows(ApprovalPolicyConflict.class, () -> ApprovalPolicy.selectExactApprovalRule(ok, "DB.Restart", "BASELINE")).fields());
    assertEquals(List.of("invalidFallback"),
        assertThrows(ApprovalPolicyConflict.class, () -> ApprovalPolicy.selectExactApprovalRule(ok, "db.restart", "OWNER_APPROVAL")).fields());
    List<BundlePolicy> dup = policy("[" + rule("*", 1, "[\"a\"]") + "," + rule("db.restart", 1, "[\"a\"]") + "," + rule("DB.RESTART", 1, "[\"a\"]") + "]");
    assertEquals(List.of("invalidOrDuplicateActionId"),
        assertThrows(ApprovalPolicyConflict.class, () -> ApprovalPolicy.validateExactApprovalPolicy(dup)).fields());
    List<BundlePolicy> noBaseline = policy("[" + rule("db.restart", 1, "[\"a\"]") + "]");
    assertEquals(List.of("missingBaseline"),
        assertThrows(ApprovalPolicyConflict.class, () -> ApprovalPolicy.validateExactApprovalPolicy(noBaseline)).fields());
    List<BundlePolicy> widened = policy("[" + rule("*", 2, "[\"a\"]") + "," + rule("db.restart", 1, "[\"a\",\"z\"]") + "]");
    assertEquals(List.of("requiredApprovals", "approverDids"),
        assertThrows(ApprovalPolicyConflict.class, () -> ApprovalPolicy.validateExactApprovalPolicy(widened)).fields());

    // A missing nullable field is an incomplete export, not a default.
    JsonNode missing = JSON.readTree(rule("*", 1, "[\"a\"]"));
    ((com.fasterxml.jackson.databind.node.ObjectNode) missing).remove("escalateAfterSeconds");
    assertFalse(BundlePolicy.fromJson(missing).complete());
  }
}
