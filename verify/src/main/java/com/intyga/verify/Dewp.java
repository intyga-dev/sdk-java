package com.intyga.verify;

import com.fasterxml.jackson.databind.JsonNode;
import java.security.PublicKey;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Function;

/** Full in-memory DEWP proof/evidence bundle readers and verification. NDJSON is intentionally absent. */
public final class Dewp {
  public static final String BUNDLE_KIND = "dewp.audit.inclusion-proof";
  public static final String EVIDENCE_BUNDLE_KIND = "dewp.audit.evidence-bundle";
  public static final String AUDIT_PROFILE = "trust.intyga.audit.v1";

  public record Event(String seq, String createdAt, String type, String outcome, String detail,
      String actorDid, String subjectDid, String signerDid, String signature, String sigAlg,
      Ledger.AuditLeaf canonical, String tenantSeq, Boolean redacted, Redaction redaction) {}
  public record Redaction(String mode, List<String> removedFields, String redactedAt, String reason,
      Commitment commitment) {}
  public record Commitment(String leaf, String tenantSeq) {}
  public record LegacyAnchor(String dailyRoot, String anchorRef, boolean anchored) {}
  public record ProofBundle(String protocol, String kind, JsonNode version, String profile, JsonNode algorithmRegistry,
      String exportedAt, Event event, Ledger.InclusionProof proof, Ledger.SignedAnchor anchor,
      List<Ledger.SignedAnchor> anchors, String anchorRef, Boolean anchored,
      Boolean externallyAnchored, Integer externallyAnchoredRequired, LegacyAnchor legacyAnchor) {
    public ProofBundle(String protocol, String kind, JsonNode version, String profile,
        String exportedAt, Event event, Ledger.InclusionProof proof, Ledger.SignedAnchor anchor,
        List<Ledger.SignedAnchor> anchors, String anchorRef, Boolean anchored,
        Boolean externallyAnchored, Integer externallyAnchoredRequired, LegacyAnchor legacyAnchor) {
      this(protocol, kind, version, profile, null, exportedAt, event, proof, anchor, anchors,
          anchorRef, anchored, externallyAnchored, externallyAnchoredRequired, legacyAnchor);
    }
    public static ProofBundle parse(String json) { try { return Records.JSON.readValue(json, ProofBundle.class); }
      catch (Exception e) { throw new IllegalArgumentException("proof bundle is not valid JSON", e); } }
    public static ProofBundle parse(JsonNode json) { return Records.JSON.convertValue(json, ProofBundle.class); }
  }
  public record Check(Boolean pass, String detail) {}
  public record Properties(boolean commitmentVerified, boolean contentVerified,
      boolean signatureVerified, boolean anchorVerified) {}
  /**
   * {@code rootSource} is "caller-supplied", "self-asserted" or "none": a supplied root is never
   * labelled "independent", since the verifier cannot tell one recorded independently from one copied
   * out of the bundle. {@code witnessTimes}: authenticated external witness time per issuer.
   */
  public record BundleVerification(boolean ok, String dailyRoot, String rootSource,
      Properties properties, String verificationLevel, Map<String,Check> checks, List<String> notes,
      Map<String, Long> witnessTimes) {}
  /**
   * {@code trustedCheckpoint}: the caller's record of the proof's checkpoint (its roots-file line). A
   * single proof carries no checkpoint, so without it no EXTERNAL anchor counts — the §5.3 time bound
   * would be measured against the anchor's own producer-chosen timestamp. Its root stands in for
   * {@code trustedRoot} when that is absent and must equal it otherwise; its entry count bounds the
   * proof's leaf counts.
   */
  public record BundleOptions(String trustedRoot, List<Ledger.SignedAnchor> anchors,
      Ledger.AnchorPolicy anchorPolicy, Function<Ledger.SignedAnchor, PublicKey> resolveAnchorKey,
      String rekorPublicKey, Map<String,Rfc3161.Trust> rfc3161Trust, String rekorIssuer,
      List<String> rekorSubmitterKeys, Ledger.TrustedCheckpoint trustedCheckpoint) {
    public BundleOptions(String trustedRoot, List<Ledger.SignedAnchor> anchors, Ledger.AnchorPolicy anchorPolicy,
        Function<Ledger.SignedAnchor, PublicKey> resolveAnchorKey, String rekorPublicKey,
        Map<String,Rfc3161.Trust> rfc3161Trust, String rekorIssuer, List<String> rekorSubmitterKeys) {
      this(trustedRoot, anchors, anchorPolicy, resolveAnchorKey, rekorPublicKey, rfc3161Trust, rekorIssuer,
          rekorSubmitterKeys, null);
    }
    public BundleOptions(String trustedRoot, List<Ledger.SignedAnchor> anchors, Ledger.AnchorPolicy anchorPolicy,
        Function<Ledger.SignedAnchor, PublicKey> resolveAnchorKey, String rekorPublicKey,
        Map<String,Rfc3161.Trust> rfc3161Trust, String rekorIssuer) {
      this(trustedRoot, anchors, anchorPolicy, resolveAnchorKey, rekorPublicKey, rfc3161Trust, rekorIssuer, null);
    }
    public BundleOptions(String trustedRoot, List<Ledger.SignedAnchor> anchors, Ledger.AnchorPolicy anchorPolicy,
        Function<Ledger.SignedAnchor, PublicKey> resolveAnchorKey, String rekorPublicKey) {
      this(trustedRoot, anchors, anchorPolicy, resolveAnchorKey, rekorPublicKey, null, null);
    }
    public BundleOptions(String trustedRoot, List<Ledger.SignedAnchor> anchors, Ledger.AnchorPolicy anchorPolicy,
        Function<Ledger.SignedAnchor, PublicKey> resolveAnchorKey, String rekorPublicKey,
        Map<String,Rfc3161.Trust> rfc3161Trust) {
      this(trustedRoot, anchors, anchorPolicy, resolveAnchorKey, rekorPublicKey, rfc3161Trust, null);
    }
    public static BundleOptions defaults() { return new BundleOptions(null,null,null,null,null,null,null,null,null); } }

  public static boolean verifyEmbeddedSignature(Ledger.AuditLeaf c) {
    if (c == null || !"ES256".equals(c.sigAlg()) || c.signerPublicKey() == null || c.signature() == null || c.signedPayload() == null) return false;
    try {
      var key = Ecdsa.parseSpkiP256(Base64.getDecoder().decode(c.signerPublicKey()));
      return Ecdsa.verifySignature(key, c.signedPayload().getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(c.signature()));
    } catch (Exception e) { return false; }
  }

  public static BundleVerification verifyBundle(ProofBundle b, BundleOptions o) {
    try {
      return verifyBundleChecked(b, o);
    } catch (RuntimeException e) {
      return new BundleVerification(false, null, "none", new Properties(false, false, false, false),
          "INVALID", Map.of(), List.of("Malformed proof bundle or verification input."), Map.of());
    }
  }

  private static BundleVerification verifyBundleChecked(ProofBundle b, BundleOptions o) {
    if (o == null) o = BundleOptions.defaults(); List<String> notes = new ArrayList<>();
    boolean kind = BUNDLE_KIND.equals(b.kind()) && supportedEnvelope(b.protocol(), b.version(), b.algorithmRegistry());
    String self = b.anchor() == null ? null : b.anchor().dailyRoot();
    if (self == null && b.legacyAnchor() != null) self = b.legacyAnchor().dailyRoot();
    if (self == null) self = b.proof().checkpointRoot();
    Ledger.TrustedCheckpoint tc = o.trustedCheckpoint();
    boolean conflict = tc != null && present(o.trustedRoot()) && !o.trustedRoot().equals(tc.root());
    if (conflict) notes.add("The supplied trusted checkpoint names a different root than the trusted root; refusing to pick one.");
    String callerRoot = present(o.trustedRoot()) ? o.trustedRoot() : tc != null && present(tc.root()) ? tc.root() : null;
    String root = callerRoot != null ? callerRoot : present(self) ? self : null;
    String source = callerRoot != null ? "caller-supplied" : root != null ? "self-asserted" : "none";
    if (!"caller-supplied".equals(source)) notes.add("No root supplied; only internal consistency can be checked — use a root obtained earlier or from the published roots file.");
    // DEWP §17.3: the proof's own leaf counts are bound to the trusted checkpoint's entry count.
    String countMismatch = tc != null && Objects.equals(root, tc.root()) ? Ledger.leafCountMismatch(b.proof(), tc.entryCount()) : null;
    if (countMismatch != null) notes.add(countMismatch);
    boolean inclusion = root != null && countMismatch == null && Ledger.verifyInclusionProof(b.proof(), root);
    boolean rootConsistent = root != null && Objects.equals(root, b.proof().checkpointRoot());
    boolean unknownProfile = b.profile() != null && !AUDIT_PROFILE.equals(b.profile());
    boolean leaf = !unknownProfile && b.event().canonical() != null && Ledger.leafHash(b.event().canonical()).equals(b.proof().leaf());
    boolean header = b.event().canonical() == null ||
        (displayMatches(b.event(), b.event().canonical(), false) && eq(b.proof().seq(), b.event().canonical().seq()));
    boolean commitment = inclusion && rootConsistent;
    boolean content = commitment && leaf && header;
    boolean signature = content && verifyEmbeddedSignature(b.event().canonical());
    boolean anchorVerified = false; boolean divergence = false; Map<String, Long> witnessTimes = Map.of();
    boolean externalCheck = o.rekorPublicKey() != null || o.rfc3161Trust() != null && !o.rfc3161Trust().isEmpty();
    if (o.anchorPolicy() != null && (o.resolveAnchorKey() != null || externalCheck) && root != null) {
      List<Ledger.SignedAnchor> candidates = o.anchors() != null ? o.anchors() : merge(b.anchors(), b.anchor());
      // The caller's record is the only position and time an anchor over a single proof can be held
      // to; an empty expectation keeps external witnesses from counting without one.
      var expected = tc == null ? new Ledger.ExpectedCheckpoint(null, null, null, null)
          : new Ledger.ExpectedCheckpoint(tc.seqStart(), tc.seqEnd(), tc.chainHash(), tc.anchoredAt());
      Ledger.AnchorQuorumResult q = Ledger.verifyAnchorQuorum(candidates, root, o.anchorPolicy(), o.resolveAnchorKey(),
          o.anchors() == null ? List.of() : o.anchors(), o.rekorPublicKey(), o.rfc3161Trust(), o.rekorIssuer(),
          o.rekorSubmitterKeys(), expected);
      anchorVerified = commitment && q.ok(); divergence = q.divergence(); witnessTimes = q.witnessTimes();
      if (q.reason() != null) notes.add(q.reason()); if (q.note() != null) notes.add(q.note());
    } else if (o.anchorPolicy() != null) notes.add("Anchor quorum could not be evaluated: root and caller trust are required.");
    Map<String,Check> checks = new LinkedHashMap<>();
    checks.put("inclusion", new Check(inclusion, inclusion ? "Event leaf recomputes to daily root." : "Inclusion proof invalid."));
    checks.put("rootConsistency", new Check(rootConsistent, "Proof checkpoint root must equal verified root."));
    checks.put("leafBinding", new Check(b.event().canonical() == null || unknownProfile ? null : leaf, unknownProfile ? "Unknown canonical profile." : "Canonical content binding."));
    checks.put("headerBinding", new Check(b.event().canonical() == null ? null : header, "Displayed fields match committed fields."));
    Boolean claimed = b.externallyAnchored() != null ? b.externallyAnchored() : b.proof().externallyAnchored();
    checks.put("anchored", new Check(claimed, "Producer claim only; anchorVerified evaluates the caller's policy."));
    if (unknownProfile) notes.add("Unknown canonical profile; content cannot be bound to its leaf.");
    boolean ok = kind && !conflict && "caller-supplied".equals(source) && commitment && header && (b.event().canonical() == null || leaf)
        && !divergence && (o.anchorPolicy() == null || anchorVerified);
    Properties p = new Properties(commitment, content, signature, anchorVerified);
    String level = !kind || divergence || !commitment ? "INVALID" : !content ? "COMMITMENT_VERIFIED"
        : anchorVerified && (signature || !(present(b.event().canonical().signature()) && present(b.event().canonical().signerPublicKey()))) ? "FULLY_VERIFIED"
        : signature ? "SIGNATURE_VERIFIED" : "CONTENT_VERIFIED";
    return new BundleVerification(ok, root, source, p, level, checks, notes, witnessTimes);
  }

  // DEWP §7/§12. Revisions 1 and 2 without a protocol is the supported legacy export.
  private static boolean supportedEnvelope(String protocol, JsonNode version, JsonNode a) {
    if (protocol != null && !"DEWP".equals(protocol)) return false;
    if (version == null || !(version.isTextual() && "1.0".equals(version.textValue()))
        && !(protocol == null && version.isNumber() && (version.decimalValue().compareTo(java.math.BigDecimal.ONE) == 0 || version.decimalValue().compareTo(java.math.BigDecimal.valueOf(2)) == 0))) return false;
    return a == null || a.isObject() && "SHA-256".equals(a.path("hashAlgorithm").asText())
        && "RFC8785-JCS".equals(a.path("serialization").asText()) && a.path("merkleVersion").isNumber()
        && a.path("merkleVersion").decimalValue().compareTo(java.math.BigDecimal.ONE) == 0;
  }

  private static boolean present(String value) { return value != null && !value.isEmpty(); }
  private static boolean displayMatches(Event e, Ledger.AuditLeaf c, boolean evidence) {
    return eq(e.seq(), c.seq()) && eq(e.createdAt(), c.createdAt()) && eq(e.type(), c.event())
        && eq(e.outcome(), c.outcome()) && eq(e.signerDid(), c.signerDid()) && eq(e.sigAlg(), c.sigAlg())
        && (evidence ? eq(e.tenantSeq(), c.tenantSeq()) : eq(e.detail(), c.detail()) && eq(e.signature(), c.signature()));
  }
  private static boolean eq(Object shown,Object committed) { return shown == null || Objects.equals(String.valueOf(shown),String.valueOf(committed)); }
  private static List<Ledger.SignedAnchor> merge(List<Ledger.SignedAnchor> a, Ledger.SignedAnchor one) {
    List<Ledger.SignedAnchor> out = new ArrayList<>(); if (a != null) out.addAll(a); if (one != null) out.add(one); return out;
  }

  public record Tenant(String id, String name) {}
  public record SequenceCommitment(String tenantId, String firstTenantSeq, String lastTenantSeq) {}
  public record EvidenceEntry(Event event, Ledger.InclusionProof proof) {}
  /** {@code entryCount}/{@code prevChainHash}/{@code chainHash}: the §5.4 fields every anchor binds. */
  public record Checkpoint(String id, String root, String anchorRef, String anchoredAt, String seqStart,
      String seqEnd, List<Ledger.SignedAnchor> anchors, Boolean externallyAnchored,
      Integer externallyAnchoredRequired, Integer entryCount, String prevChainHash, String chainHash) {
    public Checkpoint(String id, String root, String anchorRef, String anchoredAt, String seqStart,
        String seqEnd, List<Ledger.SignedAnchor> anchors, Boolean externallyAnchored,
        Integer externallyAnchoredRequired) {
      this(id, root, anchorRef, anchoredAt, seqStart, seqEnd, anchors, externallyAnchored,
          externallyAnchoredRequired, null, null, null);
    }
  }
  public record EvidenceBundle(String protocol, String kind, JsonNode version, String profile, JsonNode algorithmRegistry,
      String exportedAt, Tenant tenant, JsonNode range, SequenceCommitment tenantSequenceCommitment,
      List<EvidenceEntry> entries, List<Checkpoint> checkpoints) {
    public EvidenceBundle(String protocol, String kind, JsonNode version, String profile,
        String exportedAt, Tenant tenant, JsonNode range, SequenceCommitment tenantSequenceCommitment,
        List<EvidenceEntry> entries, List<Checkpoint> checkpoints) {
      this(protocol, kind, version, profile, null, exportedAt, tenant, range,
          tenantSequenceCommitment, entries, checkpoints);
    }
    public static EvidenceBundle parse(String json) { try { return Records.JSON.readValue(json,EvidenceBundle.class); }
      catch(Exception e) { throw new IllegalArgumentException("evidence bundle is not valid JSON",e); } }
    public static EvidenceBundle parse(JsonNode json) { return Records.JSON.convertValue(json,EvidenceBundle.class); }
  }
  public record Failure(String seq,String reason) {}
  public record RootResult(String root,String anchorRef,Boolean anchorVerified,List<String> verifiedIssuers,
      Map<String, Long> witnessTimes) {}
  public record SignatureSummary(int verified,List<String> invalid,int notCheckable) {}
  public record EvidenceVerification(boolean ok,int total,int contentVerified,int commitmentOnly,
      List<Failure> failed,List<RootResult> roots,SignatureSummary signatures,List<String> notes) {}
  /**
   * {@code trustedCheckpoints}: checkpoint records YOU hold (chain-verified roots-file lines, DEWP
   * §5.4.1). Their roots are trusted roots; a bundle checkpoint over one must agree with it on every
   * field both state, and anchors are held to the record's range, chain hash and time (§5.3).
   */
  public record EvidenceOptions(Set<String> trustedRoots, Map<String,List<Ledger.SignedAnchor>> anchors,
      Ledger.AnchorPolicy anchorPolicy, Function<Ledger.SignedAnchor,PublicKey> resolveAnchorKey,
      String rekorPublicKey, List<Ledger.SignedAnchor> flatAnchors, Map<String,Rfc3161.Trust> rfc3161Trust,
      String rekorIssuer, List<String> rekorSubmitterKeys, List<Ledger.TrustedCheckpoint> trustedCheckpoints) {
    public EvidenceOptions(Set<String> trustedRoots, Map<String,List<Ledger.SignedAnchor>> anchors,
        Ledger.AnchorPolicy anchorPolicy, Function<Ledger.SignedAnchor,PublicKey> resolveAnchorKey,
        String rekorPublicKey, List<Ledger.SignedAnchor> flatAnchors, Map<String,Rfc3161.Trust> rfc3161Trust,
        String rekorIssuer, List<String> rekorSubmitterKeys) {
      this(trustedRoots, anchors, anchorPolicy, resolveAnchorKey, rekorPublicKey, flatAnchors, rfc3161Trust,
          rekorIssuer, rekorSubmitterKeys, null);
    }
    public EvidenceOptions(Set<String> trustedRoots, Map<String,List<Ledger.SignedAnchor>> anchors,
        Ledger.AnchorPolicy anchorPolicy, Function<Ledger.SignedAnchor,PublicKey> resolveAnchorKey,
        String rekorPublicKey, List<Ledger.SignedAnchor> flatAnchors, Map<String,Rfc3161.Trust> rfc3161Trust,
        String rekorIssuer) {
      this(trustedRoots, anchors, anchorPolicy, resolveAnchorKey, rekorPublicKey, flatAnchors, rfc3161Trust, rekorIssuer, null);
    }
    public EvidenceOptions(Set<String> trustedRoots, Map<String,List<Ledger.SignedAnchor>> anchors,
        Ledger.AnchorPolicy anchorPolicy, Function<Ledger.SignedAnchor,PublicKey> resolveAnchorKey,
        String rekorPublicKey) {
      this(trustedRoots, anchors, anchorPolicy, resolveAnchorKey, rekorPublicKey, null, null, null);
    }
    public EvidenceOptions(Set<String> trustedRoots, Map<String,List<Ledger.SignedAnchor>> anchors,
        Ledger.AnchorPolicy anchorPolicy, Function<Ledger.SignedAnchor,PublicKey> resolveAnchorKey,
        String rekorPublicKey, List<Ledger.SignedAnchor> flatAnchors) {
      this(trustedRoots, anchors, anchorPolicy, resolveAnchorKey, rekorPublicKey, flatAnchors, null, null);
    }
    public EvidenceOptions(Set<String> trustedRoots, Map<String,List<Ledger.SignedAnchor>> anchors,
        Ledger.AnchorPolicy anchorPolicy, Function<Ledger.SignedAnchor,PublicKey> resolveAnchorKey,
        String rekorPublicKey, List<Ledger.SignedAnchor> flatAnchors, Map<String,Rfc3161.Trust> rfc3161Trust) {
      this(trustedRoots, anchors, anchorPolicy, resolveAnchorKey, rekorPublicKey, flatAnchors, rfc3161Trust, null);
    }
    public static EvidenceOptions defaults() { return new EvidenceOptions(null,null,null,null,null,null,null,null,null,null); }
  }

  /** Verify entries, committed tenant counters and caller-configured anchor quorum per root. */
  public static EvidenceVerification verifyEvidenceBundle(EvidenceBundle b, EvidenceOptions o) {
    try {
      return verifyEvidenceBundleChecked(b, o == null ? EvidenceOptions.defaults() : o);
    } catch (RuntimeException e) {
      return new EvidenceVerification(false, 0, 0, 0,
          List.of(new Failure("-", "Malformed evidence bundle or verification input.")), List.of(),
          new SignatureSummary(0, List.of(), 0), List.of());
    }
  }

  private static java.math.BigInteger counter(String value) {
    return value != null && value.matches("-?[0-9]{1,20}") ? new java.math.BigInteger(value) : null;
  }

  private static EvidenceVerification verifyEvidenceBundleChecked(EvidenceBundle b, EvidenceOptions o) {
    List<Failure> failures = new ArrayList<>();
    List<String> notes = new ArrayList<>();
    if (!EVIDENCE_BUNDLE_KIND.equals(b.kind()) || !supportedEnvelope(b.protocol(), b.version(), b.algorithmRegistry())) failures.add(new Failure("-", "refusing wrong evidence bundle kind"));
    boolean unknown = b.profile() != null && !AUDIT_PROFILE.equals(b.profile());
    if (unknown) notes.add("Unknown canonical profile; content cannot be bound to its leaf, so an entry carrying a preimage fails.");
    Map<String, Ledger.TrustedCheckpoint> records = new HashMap<>();
    if (o.trustedCheckpoints() != null) for (var t : o.trustedCheckpoints()) records.putIfAbsent(t.root(), t);
    Set<String> trustedRoots = null;
    if (o.trustedRoots() != null || o.trustedCheckpoints() != null) {
      trustedRoots = new HashSet<>(records.keySet());
      if (o.trustedRoots() != null) trustedRoots.addAll(o.trustedRoots());
    }
    if (trustedRoots == null) notes.add("No roots supplied; only internal consistency can be checked — use roots obtained earlier or from the published roots file.");
    // §5.4 chain fields, where carried: the chain hash every anchor binds must recompute.
    for (Checkpoint cp : b.checkpoints()) {
      if (cp.chainHash() == null) continue;
      if (cp.prevChainHash() == null || cp.anchoredAt() == null || cp.entryCount() == null) {
        failures.add(new Failure("-", "checkpoint " + cp.id() + " chainHash lacks the fields it commits to"));
      } else if (!Ledger.chainHash(cp.prevChainHash(), cp.root(), cp.seqStart(), cp.seqEnd(), cp.entryCount(),
          cp.anchoredAt()).equals(cp.chainHash())) {
        failures.add(new Failure("-", "checkpoint " + cp.id() + " chainHash does not recompute"));
      }
    }
    // A checkpoint the caller holds a record for must agree with it on every field both state: a
    // re-dated anchoredAt with a self-consistent chain over a made-up predecessor recomputes above.
    for (Checkpoint cp : b.checkpoints()) {
      var t = records.get(cp.root());
      if (t == null) continue;
      Object[][] pairs = {{"seqStart", cp.seqStart(), t.seqStart()}, {"seqEnd", cp.seqEnd(), t.seqEnd()},
          {"entryCount", cp.entryCount(), t.entryCount()}, {"anchoredAt", cp.anchoredAt(), t.anchoredAt()},
          {"chainHash", cp.chainHash(), t.chainHash()}};
      for (Object[] p : pairs) {
        if (p[1] != null && p[2] != null && !p[1].equals(p[2]))
          failures.add(new Failure("-", "checkpoint " + cp.id() + " " + p[0] + " contradicts your trusted checkpoint record for its root"));
      }
    }
    int content = 0, commitOnly = 0, sigOk = 0, sigNo = 0, redactedCount = 0;
    List<String> sigBad = new ArrayList<>();
    Map<String, Checkpoint> known = new LinkedHashMap<>();
    Map<String, String> checkpointKeys = new HashMap<>();
    Map<String, List<Ledger.SignedAnchor>> bundled = new HashMap<>();
    for (Checkpoint cp : b.checkpoints()) {
      known.put(cp.root(), cp);
      if (present(cp.id())) checkpointKeys.put(cp.id(), cp.root());
      if (cp.anchors() != null && !cp.anchors().isEmpty()) bundled.put(cp.root(), cp.anchors());
    }
    // A checkpoint ID must never shadow another checkpoint's root.
    for (String root : known.keySet()) checkpointKeys.put(root, root);
    if (o.anchors() != null && o.flatAnchors() != null) throw new IllegalArgumentException("choose keyed or flat anchors");
    List<Ledger.SignedAnchor> caller = new ArrayList<>();
    Map<String, List<Ledger.SignedAnchor>> attributed = new HashMap<>();
    boolean unattributed = false;
    if (o.flatAnchors() != null) caller.addAll(o.flatAnchors());
    if (o.anchors() != null) {
      for (var item : o.anchors().entrySet()) {
        if (item.getValue() == null || item.getValue().isEmpty()) continue;
        caller.addAll(item.getValue());
        String root = checkpointKeys.get(item.getKey());
        if (root == null) unattributed = true;
        else attributed.computeIfAbsent(root, ignored -> new ArrayList<>()).addAll(item.getValue());
      }
    }
    String bundleTenant = b.tenant() == null ? null : b.tenant().id();
    Set<String> seenLeaves = new HashSet<>(), seenSeqs = new HashSet<>();
    Map<String, Integer> blockCounts = new HashMap<>(), checkpointCounts = new HashMap<>();
    for (EvidenceEntry x : b.entries()) {
      Event e = x.event();
      String seq = e.seq(), root = x.proof().checkpointRoot();
      // One committed event appears once; a genuine leaf used twice can otherwise fill two holes.
      if (!seenLeaves.add(x.proof().leaf()) | !seenSeqs.add(String.valueOf(seq))) {
        failures.add(new Failure(seq, "duplicate entry: this leaf or seq already appears in the bundle"));
        continue;
      }
      if (root == null || !known.containsKey(root)
          || (trustedRoots != null && !trustedRoots.contains(root))
          || !Ledger.verifyInclusionProof(x.proof(), root)) {
        failures.add(new Failure(seq, "inclusion proof/root is not trusted"));
        continue;
      }
      // DEWP §17.3: leaf counts are prover-supplied; bind them to each other and to the entry count.
      Integer priorBlock = blockCounts.get(x.proof().blockRoot()), priorCp = checkpointCounts.get(root);
      var record = records.get(root);
      Integer entryCount = record != null && record.entryCount() != null ? record.entryCount() : known.get(root).entryCount();
      String countBad = (priorBlock != null && priorBlock != x.proof().blockLeafCount())
          || (priorCp != null && priorCp != x.proof().checkpointLeafCount())
          ? "proofs into the same block or checkpoint disagree on its leaf count"
          : Ledger.leafCountMismatch(x.proof(), entryCount);
      if (countBad != null) {
        failures.add(new Failure(seq, countBad));
        continue;
      }
      blockCounts.put(x.proof().blockRoot(), x.proof().blockLeafCount());
      checkpointCounts.put(root, x.proof().checkpointLeafCount());
      boolean redacted = e.redaction() != null ? "COMMITMENT_ONLY".equals(e.redaction().mode()) : Boolean.TRUE.equals(e.redacted());
      if (redacted && e.canonical() == null) {
        String retained = e.redaction() != null && e.redaction().commitment() != null ? e.redaction().commitment().leaf() : null;
        if (retained != null && !retained.equals(x.proof().leaf())) {
          failures.add(new Failure(seq, "redaction commitment leaf differs from proof leaf"));
          continue;
        }
        redactedCount++;
        commitOnly++;
      } else if (unknown && e.canonical() != null) {
        // A preimage cannot be bound under a layout this verifier does not implement, and passing it
        // would let the producer switch leaf binding off (DEWP §4.5/§7.2 rule 1).
        failures.add(new Failure(seq, "canonical preimage under an unknown profile cannot be bound to its leaf"));
      } else if (unknown) {
        commitOnly++;
      } else if (e.canonical() == null) {
        failures.add(new Failure(seq, "unredacted entry missing canonical preimage"));
      } else if (!Ledger.leafHash(e.canonical()).equals(x.proof().leaf()) || !displayMatches(e, e.canonical(), true)) {
        failures.add(new Failure(seq, "leaf/header binding failed"));
      } else if (e.redaction() != null && e.redaction().commitment() != null
          && !eq(e.redaction().commitment().tenantSeq(), e.canonical().tenantSeq())) {
        // The redaction record is unsigned and is no counter source where a preimage exists (§7.2).
        failures.add(new Failure(seq, "redaction record tenantSeq does not match the committed value"));
      } else if (e.canonical().tenantId() != null && !e.canonical().tenantId().equals(bundleTenant)) {
        // A bundle naming no tenant has none for a tenant-bound entry to belong to.
        failures.add(new Failure(seq, "entry belongs to another tenant"));
      } else {
        content++;
        if ("ES256".equals(e.canonical().sigAlg()) && present(e.canonical().signature()) && present(e.canonical().signerPublicKey())) {
          if (verifyEmbeddedSignature(e.canonical())) sigOk++;
          else sigBad.add(seq);
        } else sigNo++;
      }
    }
    // Counters are checked for every entry, independently of inclusion results. An entry WITH a
    // preimage reads its counter from it alone — null means no counter (§7.2 rule 5); only an entry
    // without one falls back to the unsigned redaction record and the display copy (rule 2).
    java.math.BigInteger first = null, last = null;
    boolean uncounted = false, unbound = false;
    for (EvidenceEntry x : b.entries()) {
      Event e = x.event();
      String raw;
      if (e.canonical() != null) {
        if (unknown) continue; // not leaf-bound under an unknown profile; that entry already failed
        raw = e.canonical().tenantSeq();
      } else {
        raw = e.redaction() != null && e.redaction().commitment() != null ? e.redaction().commitment().tenantSeq() : null;
        if (raw == null) raw = e.tenantSeq();
        if (raw != null) unbound = true;
      }
      if (raw == null) { uncounted = true; continue; }
      var current = counter(raw);
      if (current == null) { failures.add(new Failure(e.seq(), "tenantSeq is not a valid integer counter")); continue; }
      if (last != null && !current.equals(last.add(java.math.BigInteger.ONE))) {
        failures.add(new Failure(e.seq(), current.compareTo(last) <= 0
            ? "per-tenant sequence is not strictly increasing" : "per-tenant omission detected"));
      }
      if (first == null) first = current;
      last = current;
    }
    if (redactedCount > 0) notes.add("COMMITMENT_ONLY entries prove inclusion; their displayed details cannot be bound without the preimage.");
    if (uncounted) notes.add("Some entries carry no tenantSeq; gapless completeness cannot be checked across them.");
    if (unbound) notes.add("Some entries carry no canonical preimage (COMMITMENT_ONLY), so their tenantSeq was read from the redaction record or display copy and is NOT covered by the Merkle leaf.");
    if (b.tenantSequenceCommitment() != null) {
      var c = b.tenantSequenceCommitment();
      if (first == null || last == null) notes.add("No tenantSeq available to check the claimed range.");
      else {
        var claimedFirst = counter(c.firstTenantSeq());
        var claimedLast = counter(c.lastTenantSeq());
        if (claimedFirst == null || claimedLast == null) failures.add(new Failure("-", "tenant sequence commitment is non-numeric"));
        else {
          if (!first.equals(claimedFirst)) failures.add(new Failure("-", "bundle firstTenantSeq claim differs"));
          if (!last.equals(claimedLast)) failures.add(new Failure("-", "bundle lastTenantSeq claim differs"));
        }
        if (!Objects.equals(c.tenantId(), bundleTenant)) notes.add("Tenant sequence commitment names another tenant.");
      }
    }
    List<RootResult> roots = new ArrayList<>();
    boolean externalCheck = o.rekorPublicKey() != null || o.rfc3161Trust() != null && !o.rfc3161Trust().isEmpty();
    boolean canCheck = o.anchorPolicy() != null && (o.resolveAnchorKey() != null || externalCheck);
    boolean allAnchored = o.anchorPolicy() == null || canCheck;
    for (var item : known.entrySet()) {
      String root = item.getKey();
      Checkpoint cp = item.getValue();
      Boolean av = null;
      List<String> issuers = List.of();
      Map<String, Long> witnessTimes = Map.of();
      if (canCheck) {
        List<Ledger.SignedAnchor> candidates = caller.isEmpty() ? bundled.getOrDefault(root, List.of()) : caller;
        // Only independently fetched, checkpoint-attributed anchors can establish divergence.
        List<Ledger.SignedAnchor> divergence = o.anchors() != null ? attributed.getOrDefault(root, List.of())
            : caller.stream().filter(a -> root.equals(a.dailyRoot()) || !known.containsKey(a.dailyRoot())).toList();
        // Held to the caller's record where it states a field, the bundle's checkpoint otherwise.
        var t = records.get(root);
        var expected = new Ledger.ExpectedCheckpoint(
            t != null && t.seqStart() != null ? t.seqStart() : cp.seqStart(),
            t != null && t.seqEnd() != null ? t.seqEnd() : cp.seqEnd(),
            t != null && t.chainHash() != null ? t.chainHash() : cp.chainHash(),
            t != null && t.anchoredAt() != null ? t.anchoredAt() : cp.anchoredAt());
        // §5.3/§6.3: a checkpoint stating no chain hash or time (and no record supplying them) cannot
        // hold its anchors to anything, so it never counts as anchored. Divergence is still evaluated.
        boolean positionUnknown = expected.chainHash() == null || expected.anchoredAt() == null;
        if (positionUnknown) notes.add("Checkpoint " + cp.id() + " carries no chainHash/anchoredAt and no trusted checkpoint record supplies them; its anchors cannot be held to a position and time (DEWP §5.3), so it is not anchored.");
        var q = Ledger.verifyAnchorQuorum(candidates, root, o.anchorPolicy(), o.resolveAnchorKey(), divergence,
            o.rekorPublicKey(), o.rfc3161Trust(), o.rekorIssuer(), o.rekorSubmitterKeys(), expected);
        av = q.ok() && !positionUnknown; issuers = positionUnknown ? List.of() : q.verifiedIssuers();
        witnessTimes = q.witnessTimes(); allAnchored &= av;
        if (q.divergence()) failures.add(new Failure("-", "ANCHOR DIVERGENCE: " + q.reason()));
        else if (q.reason() != null) notes.add(q.reason());
        if (q.note() != null) notes.add(q.note());
      }
      roots.add(new RootResult(root, cp.anchorRef(), av, issuers, witnessTimes));
    }
    if (canCheck && caller.isEmpty() && !bundled.isEmpty()) notes.add("Bundle-carried anchors count under caller-trusted keys; divergence requires independently fetched anchors.");
    if (canCheck && !caller.isEmpty() && o.anchors() == null && known.size() > 1) notes.add("Flat anchors cannot establish exact checkpoint attribution; key anchors by checkpoint ID or root for divergence checks.");
    if (unattributed) notes.add("Some caller anchor keys identify no checkpoint; those anchors cannot establish divergence.");
    if (!canCheck) notes.add(o.anchorPolicy() == null && o.resolveAnchorKey() == null
        ? "No anchor policy supplied; independent root signatures were not checked."
        : "Anchor policy incomplete; caller trust is required.");
    if (!sigBad.isEmpty()) notes.add("Committed ES256 signatures do not verify for entries: " + String.join(", ", sigBad));
    boolean ok = failures.isEmpty() && !b.entries().isEmpty() && trustedRoots != null && allAnchored;
    return new EvidenceVerification(ok, b.entries().size(), content, commitOnly, failures, roots,
        new SignatureSummary(sigOk, sigBad, sigNo), notes);
  }
  private Dewp() {}
}
