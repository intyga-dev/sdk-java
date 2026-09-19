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
  public record ProofBundle(String protocol, String kind, JsonNode version, String profile,
      String exportedAt, Event event, Ledger.InclusionProof proof, Ledger.SignedAnchor anchor,
      List<Ledger.SignedAnchor> anchors, String anchorRef, Boolean anchored,
      Boolean externallyAnchored, Integer externallyAnchoredRequired, LegacyAnchor legacyAnchor) {
    public static ProofBundle parse(String json) { try { return Records.JSON.readValue(json, ProofBundle.class); }
      catch (Exception e) { throw new IllegalArgumentException("proof bundle is not valid JSON", e); } }
    public static ProofBundle parse(JsonNode json) { return Records.JSON.convertValue(json, ProofBundle.class); }
  }
  public record Check(Boolean pass, String detail) {}
  public record Properties(boolean commitmentVerified, boolean contentVerified,
      boolean signatureVerified, boolean anchorVerified) {}
  public record BundleVerification(boolean ok, String dailyRoot, String rootSource,
      Properties properties, String verificationLevel, Map<String,Check> checks, List<String> notes) {}
  public record BundleOptions(String trustedRoot, List<Ledger.SignedAnchor> anchors,
      Ledger.AnchorPolicy anchorPolicy, Function<Ledger.SignedAnchor, PublicKey> resolveAnchorKey,
      String rekorPublicKey) { public static BundleOptions defaults() { return new BundleOptions(null,null,null,null,null); } }

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
          "INVALID", Map.of(), List.of("Malformed proof bundle or verification input."));
    }
  }

  private static BundleVerification verifyBundleChecked(ProofBundle b, BundleOptions o) {
    if (o == null) o = BundleOptions.defaults(); List<String> notes = new ArrayList<>();
    boolean kind = BUNDLE_KIND.equals(b.kind());
    String self = b.anchor() == null ? null : b.anchor().dailyRoot();
    if (self == null && b.legacyAnchor() != null) self = b.legacyAnchor().dailyRoot();
    if (self == null) self = b.proof().checkpointRoot();
    String root = present(o.trustedRoot()) ? o.trustedRoot() : present(self) ? self : null;
    String source = present(o.trustedRoot()) ? "independent" : root != null ? "self-asserted" : "none";
    if (!"independent".equals(source)) notes.add("No independent root supplied; only internal consistency can be checked.");
    boolean inclusion = root != null && Ledger.verifyInclusionProof(b.proof(), root);
    boolean rootConsistent = root != null && Objects.equals(root, b.proof().checkpointRoot());
    boolean unknownProfile = b.profile() != null && !AUDIT_PROFILE.equals(b.profile());
    boolean leaf = !unknownProfile && b.event().canonical() != null && Ledger.leafHash(b.event().canonical()).equals(b.proof().leaf());
    boolean header = b.event().canonical() == null ||
        (displayMatches(b.event(), b.event().canonical(), false) && eq(b.proof().seq(), b.event().canonical().seq()));
    boolean commitment = inclusion && rootConsistent;
    boolean content = commitment && leaf && header;
    boolean signature = content && verifyEmbeddedSignature(b.event().canonical());
    boolean anchorVerified = false; boolean divergence = false;
    if (o.anchorPolicy() != null && o.resolveAnchorKey() != null && root != null) {
      List<Ledger.SignedAnchor> candidates = o.anchors() != null ? o.anchors() : merge(b.anchors(), b.anchor());
      Ledger.AnchorQuorumResult q = Ledger.verifyAnchorQuorum(candidates, root, o.anchorPolicy(), o.resolveAnchorKey(),
          o.anchors() == null ? List.of() : o.anchors(), o.rekorPublicKey());
      anchorVerified = commitment && q.ok(); divergence = q.divergence();
      if (q.reason() != null) notes.add(q.reason()); if (q.note() != null) notes.add(q.note());
    } else if (o.anchorPolicy() != null) notes.add("Anchor quorum could not be evaluated: root and resolver are required.");
    Map<String,Check> checks = new LinkedHashMap<>();
    checks.put("inclusion", new Check(inclusion, inclusion ? "Event leaf recomputes to daily root." : "Inclusion proof invalid."));
    checks.put("rootConsistency", new Check(rootConsistent, "Proof checkpoint root must equal verified root."));
    checks.put("leafBinding", new Check(b.event().canonical() == null || unknownProfile ? null : leaf, unknownProfile ? "Unknown canonical profile." : "Canonical content binding."));
    checks.put("headerBinding", new Check(b.event().canonical() == null ? null : header, "Displayed fields match committed fields."));
    Boolean claimed = b.externallyAnchored() != null ? b.externallyAnchored() : b.proof().externallyAnchored();
    checks.put("anchored", new Check(claimed, "Producer claim only; anchorVerified evaluates the caller's policy."));
    if (unknownProfile) notes.add("Unknown canonical profile; content cannot be bound to its leaf.");
    boolean ok = kind && "independent".equals(source) && commitment && header && (b.event().canonical() == null || leaf)
        && !divergence && (o.anchorPolicy() == null || anchorVerified);
    Properties p = new Properties(commitment, content, signature, anchorVerified);
    String level = !kind || divergence || !commitment ? "INVALID" : !content ? "COMMITMENT_VERIFIED"
        : anchorVerified && (signature || !(present(b.event().canonical().signature()) && present(b.event().canonical().signerPublicKey()))) ? "FULLY_VERIFIED"
        : signature ? "SIGNATURE_VERIFIED" : "CONTENT_VERIFIED";
    return new BundleVerification(ok, root, source, p, level, checks, notes);
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
  public record Checkpoint(String id, String root, String anchorRef, String anchoredAt, String seqStart,
      String seqEnd, List<Ledger.SignedAnchor> anchors, Boolean externallyAnchored,
      Integer externallyAnchoredRequired) {}
  public record EvidenceBundle(String protocol, String kind, JsonNode version, String profile,
      String exportedAt, Tenant tenant, JsonNode range, SequenceCommitment tenantSequenceCommitment,
      List<EvidenceEntry> entries, List<Checkpoint> checkpoints) {
    public static EvidenceBundle parse(String json) { try { return Records.JSON.readValue(json,EvidenceBundle.class); }
      catch(Exception e) { throw new IllegalArgumentException("evidence bundle is not valid JSON",e); } }
    public static EvidenceBundle parse(JsonNode json) { return Records.JSON.convertValue(json,EvidenceBundle.class); }
  }
  public record Failure(String seq,String reason) {}
  public record RootResult(String root,String anchorRef,Boolean anchorVerified,List<String> verifiedIssuers) {}
  public record SignatureSummary(int verified,List<String> invalid,int notCheckable) {}
  public record EvidenceVerification(boolean ok,int total,int contentVerified,int commitmentOnly,
      List<Failure> failed,List<RootResult> roots,SignatureSummary signatures,List<String> notes) {}
  public record EvidenceOptions(Set<String> trustedRoots, Map<String,List<Ledger.SignedAnchor>> anchors,
      Ledger.AnchorPolicy anchorPolicy, Function<Ledger.SignedAnchor,PublicKey> resolveAnchorKey,
      String rekorPublicKey, List<Ledger.SignedAnchor> flatAnchors) {
    public EvidenceOptions(Set<String> trustedRoots, Map<String,List<Ledger.SignedAnchor>> anchors,
        Ledger.AnchorPolicy anchorPolicy, Function<Ledger.SignedAnchor,PublicKey> resolveAnchorKey,
        String rekorPublicKey) {
      this(trustedRoots, anchors, anchorPolicy, resolveAnchorKey, rekorPublicKey, null);
    }
    public static EvidenceOptions defaults() { return new EvidenceOptions(null,null,null,null,null); }
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
    if (!EVIDENCE_BUNDLE_KIND.equals(b.kind())) failures.add(new Failure("-", "refusing wrong evidence bundle kind"));
    boolean unknown = b.profile() != null && !AUDIT_PROFILE.equals(b.profile());
    if (unknown) notes.add("Unknown canonical profile; content cannot be bound to its leaf.");
    if (o.trustedRoots() == null) notes.add("No independent roots supplied; only internal consistency can be checked.");
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
    for (EvidenceEntry x : b.entries()) {
      Event e = x.event();
      String seq = e.seq(), root = x.proof().checkpointRoot();
      if (root == null || !known.containsKey(root)
          || (o.trustedRoots() != null && !o.trustedRoots().contains(root))
          || !Ledger.verifyInclusionProof(x.proof(), root)) {
        failures.add(new Failure(seq, "inclusion proof/root is not trusted"));
        continue;
      }
      boolean redacted = e.redaction() != null ? "COMMITMENT_ONLY".equals(e.redaction().mode()) : Boolean.TRUE.equals(e.redacted());
      if (redacted && e.canonical() == null) {
        String retained = e.redaction() != null && e.redaction().commitment() != null ? e.redaction().commitment().leaf() : null;
        if (retained != null && !retained.equals(x.proof().leaf())) {
          failures.add(new Failure(seq, "redaction commitment leaf differs from proof leaf"));
          continue;
        }
        redactedCount++;
        commitOnly++;
      } else if (unknown) {
        commitOnly++;
      } else if (e.canonical() == null) {
        failures.add(new Failure(seq, "unredacted entry missing canonical preimage"));
      } else if (!Ledger.leafHash(e.canonical()).equals(x.proof().leaf()) || !displayMatches(e, e.canonical(), true)) {
        failures.add(new Failure(seq, "leaf/header binding failed"));
      } else if (e.canonical().tenantId() != null && b.tenant() != null && b.tenant().id() != null
          && !e.canonical().tenantId().equals(b.tenant().id())) {
        failures.add(new Failure(seq, "entry belongs to another tenant"));
      } else {
        content++;
        if ("ES256".equals(e.canonical().sigAlg()) && present(e.canonical().signature()) && present(e.canonical().signerPublicKey())) {
          if (verifyEmbeddedSignature(e.canonical())) sigOk++;
          else sigBad.add(seq);
        } else sigNo++;
      }
    }
    // Counters are checked for every entry, independently of inclusion results. Prefer committed data.
    java.math.BigInteger first = null, last = null;
    boolean uncounted = false, unbound = false;
    for (EvidenceEntry x : b.entries()) {
      Event e = x.event();
      String bound = e.canonical() == null ? null : e.canonical().tenantSeq();
      String raw = bound;
      if (raw == null && e.redaction() != null && e.redaction().commitment() != null) raw = e.redaction().commitment().tenantSeq();
      if (raw == null) raw = e.tenantSeq();
      if (bound == null && raw != null) unbound = true;
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
    if (unbound) notes.add("Some tenantSeq values are not leaf-bound; gaplessness across them rests on the producer's redaction record.");
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
        if (b.tenant() != null && !Objects.equals(c.tenantId(), b.tenant().id())) notes.add("Tenant sequence commitment names another tenant.");
      }
    }
    List<RootResult> roots = new ArrayList<>();
    boolean canCheck = o.anchorPolicy() != null && o.resolveAnchorKey() != null;
    boolean allAnchored = o.anchorPolicy() == null || canCheck;
    for (var item : known.entrySet()) {
      String root = item.getKey();
      Checkpoint cp = item.getValue();
      Boolean av = null;
      List<String> issuers = List.of();
      if (canCheck) {
        List<Ledger.SignedAnchor> candidates = caller.isEmpty() ? bundled.getOrDefault(root, List.of()) : caller;
        // Only independently fetched, checkpoint-attributed anchors can establish divergence.
        List<Ledger.SignedAnchor> divergence = o.anchors() != null ? attributed.getOrDefault(root, List.of())
            : caller.stream().filter(a -> root.equals(a.dailyRoot()) || !known.containsKey(a.dailyRoot())).toList();
        var q = Ledger.verifyAnchorQuorum(candidates, root, o.anchorPolicy(), o.resolveAnchorKey(), divergence, o.rekorPublicKey());
        av = q.ok(); issuers = q.verifiedIssuers(); allAnchored &= q.ok();
        if (q.divergence()) failures.add(new Failure("-", "ANCHOR DIVERGENCE: " + q.reason()));
        else if (q.reason() != null) notes.add(q.reason());
        if (q.note() != null) notes.add(q.note());
      }
      roots.add(new RootResult(root, cp.anchorRef(), av, issuers));
    }
    if (canCheck && caller.isEmpty() && !bundled.isEmpty()) notes.add("Bundle-carried anchors count under caller-trusted keys; divergence requires independently fetched anchors.");
    if (canCheck && !caller.isEmpty() && o.anchors() == null && known.size() > 1) notes.add("Flat anchors cannot establish exact checkpoint attribution; key anchors by checkpoint ID or root for divergence checks.");
    if (unattributed) notes.add("Some caller anchor keys identify no checkpoint; those anchors cannot establish divergence.");
    if (!canCheck) notes.add(o.anchorPolicy() == null && o.resolveAnchorKey() == null
        ? "No anchor policy supplied; independent root signatures were not checked."
        : "Anchor policy incomplete; both policy and resolver are required.");
    if (!sigBad.isEmpty()) notes.add("Committed ES256 signatures do not verify for entries: " + String.join(", ", sigBad));
    boolean ok = failures.isEmpty() && !b.entries().isEmpty() && o.trustedRoots() != null && allAnchored;
    return new EvidenceVerification(ok, b.entries().size(), content, commitOnly, failures, roots,
        new SignatureSummary(sigOk, sigBad, sigNo), notes);
  }
  private Dewp() {}
}
