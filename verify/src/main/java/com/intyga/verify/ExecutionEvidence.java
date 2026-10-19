package com.intyga.verify;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Function;

/**
 * DEWP §4.7 — execution evidence, mirroring {@code ledger-execution.ts} in @intyga/verify.
 *
 * <p>A Dispatch Record says the executing party sent an approved action; an Evidence Record carries a
 * statement an independent evidence source signed about whether it took effect. The status derived
 * here reports what a CALLER-TRUSTED source observed, never what physically happened (§4.7.6), and it
 * never changes commitment, content, signature or anchor verification.
 *
 * <p>The executing party writes Dispatch Records, so nothing it writes may decide the verdict on its
 * own: a statement binds to ANY Dispatch Record whose hash matches (an early record with another hash
 * is a reported conflict, not a way to unbind a trusted contradiction), the evidence window is bounded
 * by the caller and never by the dispatch alone, every Approval Record's nonce is reported so a silent
 * approval shows as {@code not_reported}, and a trusted {@code contradicted} sampled after the deadline
 * is its own alert rather than a dropped statement.
 */
public final class ExecutionEvidence {
  /** Signed statement {@code type} (DEWP §4.7.2), distinct from every DIV payload type. */
  public static final String TYPE = "dewp-execution-evidence";
  public static final String DISPATCHED = "EXECUTION_DISPATCHED";
  public static final String CONFIRMED = "EXECUTION_CONFIRMED";
  public static final String CONTRADICTED = "EXECUTION_CONTRADICTED";
  public static final String UNCONFIRMED = "EXECUTION_UNCONFIRMED";
  /** DEWP §4.7.2 rule 10. */
  public static final int MAX_STATEMENT_BYTES = 16_384;
  /**
   * DEWP §4.7.3 step 6: the default allowance before the dispatch time, caller-overridable. It covers
   * clock error between the source and the producer and nothing else — it also admits a measurement
   * taken just before dispatch, which for an action with no visible change confirms a no-op — so it
   * is small.
   */
  public static final long DEFAULT_SKEW_SECONDS = 30;
  /**
   * DEWP §4.7.3 step 6: the default maximum evidence window, caller-overridable. The executing party
   * chooses {@code evidenceDeadline}; without this bound a far-out deadline keeps a nonce
   * {@code pending} forever and {@code unconfirmed} never fires.
   */
  public static final long DEFAULT_MAX_WINDOW_SECONDS = 86_400;

  /**
   * The object an evidence source signs (DEWP §4.7.2). {@code sampledAt} is when the measurement
   * behind {@code observation} was taken (rule 11; the window is evaluated on it) and
   * {@code sequence} the source's own gapless per-log counter (rule 12).
   */
  public record Statement(String nonce, String payloadSha256, Map<String, Object> observation,
      String observedAt, String sampledAt, long sequence, String source, String verdict) {}

  /**
   * One caller-trusted key for an evidence source: a base64 SPKI P-256 key, optionally with a
   * validity interval (DEWP §4.7.5) — each bound a §4.3 timestamp, both inclusive, either optional. A
   * bounded key establishes trust only at the record's ANCHORED time.
   */
  public record SourceKey(String key, String notBefore, String notAfter) {
    /** A key valid at any time. */
    public static SourceKey of(String key) { return new SourceKey(key, null, null); }
  }

  /**
   * Caller-owned evidence-source trust: source → keys, separate from approver trust (DEWP §4.7.5).
   * Each key is a bare base64 SPKI string, a {@link SourceKey}, or a map with exactly the members
   * {@code key}, {@code notBefore} and {@code notAfter} (the last two optional — what a parsed JSON
   * policy carries). An entry with no usable string key is dropped: nothing can verify under it. A
   * map entry with any OTHER member, or with a bound that is present but not a string, is kept with
   * its key and verifies a signature but never establishes trust — a misspelt {@code notafter} or a
   * numeric bound fails closed rather than reading as "no bound".
   */
  public record Policy(Map<String, ? extends List<?>> trustedSources) {}

  /**
   * DEWP §4.7.3 result for one Evidence Record. {@code source} and {@code sequence} are the
   * statement's once it parsed; null before that.
   */
  public record Check(String status, String reason, boolean trusted, String nonce, String verdict,
      String source, Long sequence) {}
  public record Entry(String seq, Check check) {}

  /**
   * DEWP §4.7.4 status of one approval nonce. {@code dispatchSeq} is the governing Dispatch Record;
   * {@code evidenceDeadline} its own deadline as written by the executing party and
   * {@code effectiveDeadline} the one the status was evaluated against (cut to the caller's window;
   * {@code windowCapped} says when that happened). {@code dispatchConflict} lists every Dispatch
   * Record for the nonce when they disagree on {@code payloadSha256}, {@code lateContradiction} the
   * trusted, bound {@code contradicted} statements sampled after the effective deadline, and
   * {@code untrustedContradiction} the bound, in-window or late {@code contradicted} statements whose
   * signature verified under a caller-provisioned key that did not establish trust — its validity
   * could not be placed in time, or the record lay outside it (§4.7.4, §4.7.5). They cannot decide
   * the status; they are never silent.
   */
  public record NonceStatus(String status, String dispatchSeq, String evidenceDeadline,
      String effectiveDeadline, boolean windowCapped, List<String> dispatchConflict,
      List<String> lateContradiction, List<String> untrustedContradiction, List<String> evidenceSeqs) {}

  /**
   * DEWP §4.7.3 "Source continuity": what one source's counter shows inside the bundle. {@code gaps}
   * are inclusive {@code [from, to]} ranges between {@code first} and {@code last} that no record
   * carries; {@code divergent} the counter values carried by two or more records whose statement bytes
   * differ.
   */
  public record SourceContinuity(long first, long last, List<List<Long>> gaps, List<Long> divergent) {}

  /**
   * DEWP §4.7 over one evidence bundle. {@code lateContradicted} names the nonces with a late
   * contradiction (the alert that most needs escalation), {@code untrustedContradicted} those with a
   * contradiction under a provisioned key that established no trust, {@code dispatchConflicts} those
   * whose Dispatch Records disagree (§4.7.4); {@code sources} is per-source continuity (§4.7.3).
   */
  public record Verification(List<Entry> checks, Map<String, NonceStatus> byNonce, List<String> confirmed,
      List<String> contradicted, List<String> unconfirmed, List<String> pending, List<String> notReported,
      List<String> lateContradicted, List<String> untrustedContradicted, List<String> dispatchConflicts,
      Map<String, SourceContinuity> sources) {
    static Verification empty() {
      return new Verification(List.of(), Map.of(), List.of(), List.of(), List.of(), List.of(), List.of(),
          List.of(), List.of(), List.of(), Map.of());
    }
  }
  /** A content-verified leaf with its seq. */
  public record Leaf(String seq, Ledger.AuditLeaf leaf) {}

  /**
   * Evaluation inputs. {@code nowMs} is the evaluation time in Unix milliseconds (null: the current
   * time) — an input, so a status is reproducible. {@code skewSeconds} null or negative means
   * {@link #DEFAULT_SKEW_SECONDS}; {@code maxWindowSeconds} null or negative means
   * {@link #DEFAULT_MAX_WINDOW_SECONDS} (a bound that is no bound falls back rather than removing the
   * cap). {@code anchoredTime} maps a record's seq to its anchored time (epoch ms): the earliest
   * external witness time among anchors that counted toward quorum for the checkpoint its own
   * inclusion proof names, or null when none does (DEWP §4.7.5). Only consulted for caller keys that
   * carry a validity interval.
   */
  public record Options(Policy policy, Long nowMs, Long skewSeconds, Long maxWindowSeconds,
      Function<String, Long> anchoredTime) {}

  /** Thrown for a statement DEWP §4.7.2 refuses. */
  public static final class MalformedStatementException extends IllegalArgumentException {
    MalformedStatementException(String message) { super(message); }
  }

  /** DEWP §4.7.7: arrays and objects nest at most this deep, the outermost value counting as 1. */
  public static final int MAX_SIGNED_PAYLOAD_DEPTH = 64;
  /** DEWP §4.7.2 rules 8 and 12: every statement number's magnitude is at most 2^53 − 1. */
  private static final long MAX_STATEMENT_NUMBER = 9_007_199_254_740_991L;
  /** Whole-text parse: Jackson otherwise ignores tokens after the first value. */
  private static final com.fasterxml.jackson.databind.ObjectReader STRICT = Records.JSON.reader()
      .with(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
      .forType(Object.class);
  private static final String HEX64 = "[0-9a-f]{64}";
  private static final List<String> STATEMENT_KEYS = List.of(
      "approval", "observation", "observedAt", "sampledAt", "sequence", "source", "type", "v", "verdict");
  private static final DateTimeFormatter DEWP_TIMESTAMP =
      DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);

  private static boolean present(String s) { return s != null && !s.isEmpty(); }

  /** True when {@code text} nests arrays/objects deeper than {@code limit}, scanned without parsing. */
  private static boolean nestsDeeperThan(String text, int limit) {
    int depth = 0;
    boolean inString = false;
    for (int i = 0; i < text.length(); i++) {
      char c = text.charAt(i);
      if (inString) {
        if (c == '\\') i++;
        else if (c == '"') inString = false;
      } else if (c == '"') inString = true;
      else if (c == '[' || c == '{') {
        if (++depth > limit) return true;
      } else if (c == ']' || c == '}') depth--;
    }
    return false;
  }

  private static boolean everyNumber(Object v, java.util.function.Predicate<Number> ok) {
    if (v instanceof Number n) return ok.test(n);
    if (v instanceof List<?> l) return l.stream().allMatch(e -> everyNumber(e, ok));
    if (v instanceof Map<?, ?> m) return m.values().stream().allMatch(e -> everyNumber(e, ok));
    return true;
  }

  /**
   * DEWP §4.7.7: the one way §4.7 parses a signed payload — the whole text (no trailing tokens), no
   * NaN/Infinity literals (Jackson's default), nesting at most 64 deep (scanned first, below Jackson's
   * own limit), and every number finite as a double. Returns null when the text does not parse.
   */
  public static Object parseSignedPayload(String text) {
    if (text == null || nestsDeeperThan(text, MAX_SIGNED_PAYLOAD_DEPTH)) return null;
    Object value;
    try {
      value = STRICT.readValue(text);
    } catch (Exception e) {
      return null;
    }
    return everyNumber(value, n -> Double.isFinite(n.doubleValue())) ? value : null;
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> asObject(Object v) {
    return v instanceof Map<?, ?> m ? (Map<String, Object>) m : null;
  }

  private static boolean keysAre(Map<String, Object> obj, List<String> expected) {
    return new TreeSet<>(obj.keySet()).equals(new TreeSet<>(expected)) && obj.size() == expected.size();
  }

  /**
   * DEWP §4.7.2 rules 1–3 and 5–12. Rule 4 (source equals the record's signer) needs the record and is
   * checked by the caller.
   */
  public static Statement parseStatement(String bytes) {
    if (bytes == null) throw new MalformedStatementException("statement is missing");
    if (bytes.getBytes(StandardCharsets.UTF_8).length > MAX_STATEMENT_BYTES)
      throw new MalformedStatementException("statement exceeds " + MAX_STATEMENT_BYTES + " bytes");
    Object value = parseSignedPayload(bytes);
    if (value == null) throw new MalformedStatementException("statement does not parse (DEWP §4.7.7)");
    if (!everyNumber(value, n -> n instanceof BigInteger big
        ? big.abs().compareTo(BigInteger.valueOf(MAX_STATEMENT_NUMBER)) <= 0
        : n instanceof Long || n instanceof Integer
            ? Math.abs(n.longValue()) <= MAX_STATEMENT_NUMBER
            : Math.abs(n.doubleValue()) <= (double) MAX_STATEMENT_NUMBER))
      throw new MalformedStatementException("a statement number exceeds 2^53 - 1");
    // Re-serializing must reproduce the bytes: refuses duplicate members, whitespace, non-portable
    // numbers, non-canonical number spellings (418.0) and lone surrogates, so every port reads one
    // statement from one byte string.
    String canonical;
    try {
      canonical = Canonical.stableStringify(value);
    } catch (Canonical.NonPortableValueException e) {
      throw new MalformedStatementException("statement is not canonical: " + e.getMessage());
    }
    if (!canonical.equals(bytes)) throw new MalformedStatementException("statement is not in RFC 8785 canonical form");
    Map<String, Object> obj = asObject(value);
    if (obj == null) throw new MalformedStatementException("statement is not a JSON object");
    if (!keysAre(obj, STATEMENT_KEYS))
      throw new MalformedStatementException(
          "statement must have exactly the members " + String.join(", ", STATEMENT_KEYS));
    if (!TYPE.equals(obj.get("type"))) throw new MalformedStatementException("statement type is not " + TYPE);
    if (!(obj.get("v") instanceof Integer v) || v != 1) throw new MalformedStatementException("statement version v must be 1");
    Map<String, Object> approval = asObject(obj.get("approval"));
    if (approval == null) throw new MalformedStatementException("approval must be an object");
    if (!keysAre(approval, List.of("nonce", "payloadSha256")))
      throw new MalformedStatementException("approval must have exactly the members nonce, payloadSha256");
    if (!(approval.get("nonce") instanceof String nonce) || nonce.isEmpty())
      throw new MalformedStatementException("approval.nonce must be a non-empty string");
    if (!(approval.get("payloadSha256") instanceof String digest) || !digest.matches(HEX64))
      throw new MalformedStatementException("approval.payloadSha256 must be 64 lowercase hex characters");
    if (!(obj.get("source") instanceof String source) || source.isEmpty())
      throw new MalformedStatementException("source must be a non-empty string");
    if (!(obj.get("verdict") instanceof String verdict) || !(verdict.equals("confirmed") || verdict.equals("contradicted")))
      throw new MalformedStatementException("verdict must be confirmed or contradicted");
    Long observedMs = obj.get("observedAt") instanceof String s ? Ledger.parseAnchorTimestampMs(s) : null;
    if (observedMs == null)
      throw new MalformedStatementException("observedAt must be a YYYY-MM-DDTHH:mm:ss.sssZ timestamp");
    String observedAt = (String) obj.get("observedAt");
    Long sampledMs = obj.get("sampledAt") instanceof String s ? Ledger.parseAnchorTimestampMs(s) : null;
    if (sampledMs == null)
      throw new MalformedStatementException("sampledAt must be a YYYY-MM-DDTHH:mm:ss.sssZ timestamp");
    String sampledAt = (String) obj.get("sampledAt");
    if (sampledMs > observedMs) throw new MalformedStatementException("sampledAt must not be later than observedAt");
    // After the canonical-form check an integral value can only be an Integer or a Long: a Double
    // reaching here is non-integral (418.0 re-serializes as 418 and already failed), and a BigInteger
    // is beyond long range and already failed the magnitude check.
    Object seqValue = obj.get("sequence");
    if (!(seqValue instanceof Integer || seqValue instanceof Long) || ((Number) seqValue).longValue() < 1)
      throw new MalformedStatementException("sequence must be an integer from 1 to 2^53 - 1");
    long sequence = ((Number) seqValue).longValue();
    Map<String, Object> observation = asObject(obj.get("observation"));
    if (observation == null) throw new MalformedStatementException("observation must be an object");
    return new Statement(nonce, digest, observation, observedAt, sampledAt, sequence, source, verdict);
  }

  /**
   * Canonical statement bytes an evidence source signs (DEWP §4.7.2). Throws on input the statement
   * rules refuse, so a source never signs bytes a verifier rejects as malformed.
   */
  public static String canonicalStatement(Statement s) {
    Map<String, Object> approval = new LinkedHashMap<>();
    approval.put("nonce", s.nonce());
    approval.put("payloadSha256", s.payloadSha256());
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("approval", approval);
    m.put("observation", s.observation() == null ? Map.of() : s.observation());
    m.put("observedAt", s.observedAt());
    m.put("sampledAt", s.sampledAt());
    m.put("sequence", s.sequence());
    m.put("source", s.source());
    m.put("type", TYPE);
    m.put("v", 1);
    m.put("verdict", s.verdict());
    String bytes = Canonical.stableStringify(m);
    parseStatement(bytes);
    return bytes;
  }

  /** Lowercase hex SHA-256 of a DIV Intent Payload's UTF-8 bytes — the statement's payloadSha256. */
  public static String payloadSha256(String canonicalPayload) {
    try {
      byte[] d = MessageDigest.getInstance("SHA-256").digest(canonicalPayload.getBytes(StandardCharsets.UTF_8));
      StringBuilder sb = new StringBuilder(64);
      for (byte b : d) sb.append(String.format("%02x", b));
      return sb.toString();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  private static Map<String, Object> payloadObject(String signedPayload) {
    return present(signedPayload) ? asObject(parseSignedPayload(signedPayload)) : null;
  }

  /** True when a leaf's signed payload is an Execution Evidence Statement (DEWP §4.7.3). */
  public static boolean isEvidencePayload(String signedPayload) {
    Map<String, Object> obj = payloadObject(signedPayload);
    return obj != null && TYPE.equals(obj.get("type"));
  }

  /**
   * An Evidence Record: its event says so, or its payload is a statement — either suffices, so a record
   * cannot dodge evidence-source trust by mislabelling one side (§4.7.3, §4.7.5).
   */
  public static boolean isEvidenceLeaf(Ledger.AuditLeaf leaf) {
    return leaf != null && (CONFIRMED.equals(leaf.event()) || CONTRADICTED.equals(leaf.event())
        || isEvidencePayload(leaf.signedPayload()));
  }

  private static Ledger.AuditLeaf withKey(Ledger.AuditLeaf c, String key) {
    return new Ledger.AuditLeaf(c.seq(), c.tenantSeq(), c.createdAt(), c.event(), c.outcome(), c.detail(),
        c.metadata(), c.signerDid(), key, c.signedPayload(), c.signature(), c.sigAlg(), c.isBillable(),
        c.tenantId(), c.actorNodeId(), c.subjectNodeId(), c.edgeId(), c.challengeId());
  }

  /**
   * A caller key entry as read: {@code malformed} is why it can verify a signature but never
   * establish trust (DEWP §4.7.5), or null.
   */
  private record NormalizedKey(String key, String notBefore, String notAfter, String malformed) {}

  private static final Set<String> KEY_ENTRY_MEMBERS = Set.of("key", "notBefore", "notAfter");

  /**
   * The caller's keys for a source, normalized. An entry with no usable key is dropped (nothing can
   * verify under it). A map entry with any other member, or a bound that is present but not a
   * string, is kept with its key and marked malformed: a misspelt {@code notafter} or a numeric bound
   * must fail closed, never read as "no bound".
   */
  private static List<NormalizedKey> trustedKeysFor(Policy policy, String source) {
    if (policy == null || policy.trustedSources() == null || source == null) return List.of();
    List<?> raw = policy.trustedSources().get(source);
    if (raw == null) return List.of();
    List<NormalizedKey> out = new ArrayList<>();
    for (Object entry : raw) {
      if (entry instanceof String s) {
        if (!s.isEmpty()) out.add(new NormalizedKey(s, null, null, null));
      } else if (entry instanceof SourceKey k) {
        if (present(k.key())) out.add(new NormalizedKey(k.key(), k.notBefore(), k.notAfter(), null));
      } else if (entry instanceof Map<?, ?> m && m.get("key") instanceof String key && !key.isEmpty()) {
        List<String> unknown = new ArrayList<>();
        for (Object member : m.keySet()) if (!KEY_ENTRY_MEMBERS.contains(String.valueOf(member))) unknown.add(String.valueOf(member));
        String badBound = null;
        for (String bound : List.of("notBefore", "notAfter"))
          if (m.containsKey(bound) && !(m.get(bound) instanceof String)) { badBound = bound; break; }
        out.add(new NormalizedKey(key, m.get("notBefore") instanceof String nb ? nb : null,
            m.get("notAfter") instanceof String na ? na : null,
            !unknown.isEmpty()
                ? "Caller key entry has unexpected member(s) " + String.join(", ", unknown) + "; it does not establish trust."
                : badBound != null
                    ? "Caller key entry's " + badBound + " is not a timestamp string; it does not establish trust."
                    : null));
      }
    }
    return out;
  }

  /**
   * DEWP §4.7.5: a bounded key establishes trust only at the record's anchored time. The statement's
   * own {@code observedAt}/{@code sampledAt} are never used here — a compromised key could place a
   * statement inside the period when it was still valid; a witness cannot be backdated. Returns the
   * reason the key does not establish trust, or null when it does.
   */
  private static String keyValidAt(NormalizedKey k, Long anchoredTimeMs) {
    if (k.malformed() != null) return k.malformed();
    if (k.notBefore() == null && k.notAfter() == null) return null;
    // Assigned, not a ternary: mixing a long literal with a nullable Long would unbox a malformed
    // bound into a NullPointerException instead of the reported refusal below.
    Long from = Long.MIN_VALUE, to = Long.MAX_VALUE;
    if (k.notBefore() != null) from = Ledger.parseAnchorTimestampMs(k.notBefore());
    if (k.notAfter() != null) to = Ledger.parseAnchorTimestampMs(k.notAfter());
    if (from == null || to == null)
      return "Caller key carries a malformed validity interval; it does not establish trust.";
    if (anchoredTimeMs == null)
      return "Caller key carries a validity interval but no counting anchor covers this record, so the key "
          + "cannot be placed in time (DEWP §4.7.5); it does not establish trust.";
    if (anchoredTimeMs < from || anchoredTimeMs > to)
      return "Caller key was not valid at this record's anchored time (DEWP §4.7.5); it does not establish trust.";
    return null;
  }

  /** As {@link #verifySignature(Ledger.AuditLeaf, Policy, Long)} with no anchored time. */
  public static AuditSignatures.Check verifySignature(Ledger.AuditLeaf leaf, Policy policy) {
    return verifySignature(leaf, policy, null);
  }

  /**
   * ES256 under caller-provisioned keys for the statement's source (evidence-source trust only: an
   * approver key never verifies a statement, and an evidence key never verifies an approval, §4.7.5).
   * A key with a validity interval verifies the signature but establishes trust only at the record's
   * anchored time ({@code anchoredTimeMs}, null when no counting anchor covers the record).
   */
  public static AuditSignatures.Check verifySignature(Ledger.AuditLeaf leaf, Policy policy, Long anchoredTimeMs) {
    if (policy == null) {
      return Dewp.verifyEmbeddedSignature(leaf)
          ? new AuditSignatures.Check("verified", "Signature valid under embedded key; source identity is not established.", false)
          : new AuditSignatures.Check("invalid", "Statement signature does not verify.", false);
    }
    List<NormalizedKey> keys = trustedKeysFor(policy, leaf.signerDid());
    if (keys.isEmpty())
      return new AuditSignatures.Check("not_checked", "No caller-trusted key for this evidence source.", false);
    String untrustedReason = null;
    for (NormalizedKey k : keys) {
      if (!Dewp.verifyEmbeddedSignature(withKey(leaf, k.key()))) continue;
      String refused = keyValidAt(k, anchoredTimeMs);
      if (refused == null)
        return new AuditSignatures.Check("verified", "Statement valid under caller-trusted source key.", true);
      if (untrustedReason == null) untrustedReason = refused;
    }
    if (untrustedReason != null) return new AuditSignatures.Check("verified", untrustedReason, false);
    return new AuditSignatures.Check("invalid", "Statement signature does not verify under caller trust.", false);
  }

  private static Check check(String status, String reason, Statement s, boolean trusted) {
    return new Check(status, reason, trusted, s == null ? null : s.nonce(), s == null ? null : s.verdict(),
        s == null ? null : s.source(), s == null ? null : s.sequence());
  }

  private static String withNote(String reason, String note) { return note == null ? reason : reason + " " + note; }

  /**
   * Result of steps 1–4: either a decided check, or the statement, its trust and — under a policy
   * whose key verified but did not establish trust — the reason why.
   */
  private record Partial(Check decided, Statement statement, boolean trusted, String note) {}

  private static Partial checkLeafSteps(Ledger.AuditLeaf leaf, Policy policy, Long anchoredTimeMs) {
    if (!"ES256".equals(leaf.sigAlg()) || !present(leaf.signature()) || !present(leaf.signerPublicKey())
        || !present(leaf.signedPayload()))
      return new Partial(check("invalid", "Evidence Records must carry an ES256 signature, public key and statement.", null, false), null, false, null);
    Statement s;
    try {
      s = parseStatement(leaf.signedPayload());
    } catch (MalformedStatementException e) {
      return new Partial(check("invalid", "Malformed statement: " + e.getMessage() + ".", null, false), null, false, null);
    }
    if (!s.source().equals(leaf.signerDid()))
      return new Partial(check("invalid", "Statement source does not match the record's signerDid.", s, false), null, false, null);
    boolean confirmed = s.verdict().equals("confirmed");
    if (!(confirmed ? CONFIRMED : CONTRADICTED).equals(leaf.event()) || !(confirmed ? "SUCCESS" : "FAILURE").equals(leaf.outcome()))
      return new Partial(check("invalid", "Record event/outcome do not match the signed verdict.", s, false), null, false, null);
    AuditSignatures.Check sig = verifySignature(leaf, policy, anchoredTimeMs);
    if (!sig.status().equals("verified")) return new Partial(check(sig.status(), sig.reason(), s, false), null, false, null);
    // A verified-but-untrusted signature under a policy carries the reason (a bounded key outside its
    // interval, or no anchored time); the embedded-key case needs no note, the status says it.
    return new Partial(null, s, sig.trusted(), policy != null && !sig.trusted() ? sig.reason() : null);
  }

  /** As {@link #checkLeaf(Ledger.AuditLeaf, Policy, Long)} with no anchored time. */
  public static Check checkLeaf(Ledger.AuditLeaf leaf, Policy policy) { return checkLeaf(leaf, policy, null); }

  /** DEWP §4.7.3 for a leaf seen alone (a single proof): never verified, at best unbound. */
  public static Check checkLeaf(Ledger.AuditLeaf leaf, Policy policy, Long anchoredTimeMs) {
    Partial p = checkLeafSteps(leaf, policy, anchoredTimeMs);
    if (p.decided() != null) return p.decided();
    return check("unbound",
        withNote("A single proof cannot bind a statement to its dispatch and approval records.", p.note()),
        p.statement(), p.trusted());
  }

  private record Dispatch(String nonce, String seq, long createdAtMs, String deadline, long deadlineMs, String payloadSha256) {}

  /** A valid Dispatch Record's governing fields, or null when the record does not qualify. */
  private static Dispatch dispatchOf(Ledger.AuditLeaf leaf) {
    if (!DISPATCHED.equals(leaf.event())) return null;
    Map<String, Object> m = asObject(leaf.metadata());
    if (m == null || !(m.get("nonce") instanceof String nonce) || nonce.isEmpty()) return null;
    if (!(m.get("payloadSha256") instanceof String digest) || !digest.matches(HEX64)) return null;
    if (!(m.get("evidenceDeadline") instanceof String deadline)) return null;
    Long deadlineMs = Ledger.parseAnchorTimestampMs(deadline);
    Long createdMs = Ledger.parseAnchorTimestampMs(leaf.createdAt());
    if (deadlineMs == null || createdMs == null) return null;
    return new Dispatch(nonce, leaf.seq(), createdMs, deadline, deadlineMs, digest);
  }

  /** Numeric seq order; a non-numeric seq (which a verified entry cannot have) sorts last. */
  private static int seqCompare(String a, String b) {
    boolean na = a != null && a.matches("[0-9]+"), nb = b != null && b.matches("[0-9]+");
    if (!na || !nb) return na == nb ? 0 : na ? -1 : 1;
    return new BigInteger(a).compareTo(new BigInteger(b));
  }

  /** The deadline a status is evaluated against: the record's own, cut to the caller's window. */
  private record Deadline(long ms, boolean capped) {}

  private static Deadline effectiveDeadlineOf(Dispatch d, long maxWindowMs) {
    long bound = d.createdAtMs() + maxWindowMs;
    return d.deadlineMs() > bound ? new Deadline(bound, true) : new Deadline(d.deadlineMs(), false);
  }

  private record ContinuityRecord(long sequence, String bytes) {}

  /** DEWP §4.7.3 "Source continuity" over the records that passed step 4. */
  private static Map<String, SourceContinuity> continuity(Map<String, List<ContinuityRecord>> records) {
    Map<String, SourceContinuity> out = new TreeMap<>(); // String order is UTF-16 code-unit order
    for (var item : records.entrySet()) {
      TreeMap<Long, Set<String>> bySequence = new TreeMap<>();
      for (ContinuityRecord r : item.getValue())
        bySequence.computeIfAbsent(r.sequence(), k -> new LinkedHashSet<>()).add(r.bytes());
      List<Long> seen = new ArrayList<>(bySequence.keySet());
      long first = seen.get(0), last = seen.get(seen.size() - 1);
      // Gaps as ranges: a source that signed 1 and 2^53 − 1 must not make the verifier enumerate the
      // numbers in between.
      List<List<Long>> gaps = new ArrayList<>();
      for (int i = 1; i < seen.size(); i++) {
        long prev = seen.get(i - 1), next = seen.get(i);
        if (next - prev > 1) gaps.add(List.of(prev + 1, next - 1));
      }
      List<Long> divergent = new ArrayList<>();
      for (var s : bySequence.entrySet()) if (s.getValue().size() > 1) divergent.add(s.getKey());
      out.put(item.getKey(), new SourceContinuity(first, last, List.copyOf(gaps), List.copyOf(divergent)));
    }
    return out;
  }

  /** A caller allowance in seconds when it is a non-negative number, else the default. */
  private static long seconds(Long value, long fallback) {
    return value != null && value >= 0 ? value : fallback;
  }

  /** As {@link #evaluate(List, Options)} with the default window and no anchored times. */
  public static Verification evaluate(List<Leaf> entries, Policy policy, Long nowMs, Long skewSeconds) {
    return evaluate(entries, new Options(policy, nowMs, skewSeconds, null, null));
  }

  /**
   * DEWP §4.7.3–§4.7.4 over the CONTENT-VERIFIED entries of one evidence bundle; see {@link Options}
   * for the evaluation time, allowances and anchored-time hook.
   */
  public static Verification evaluate(List<Leaf> entries, Options o) {
    if (o == null) o = new Options(null, null, null, null, null);
    long now = o.nowMs() != null ? o.nowMs() : System.currentTimeMillis();
    // A bound that is not a non-negative number is no bound at all; fall back to the default rather
    // than let a negative value remove the window cap or the early-sample limit.
    long skewMs = seconds(o.skewSeconds(), DEFAULT_SKEW_SECONDS) * 1000;
    long maxWindowMs = seconds(o.maxWindowSeconds(), DEFAULT_MAX_WINDOW_SECONDS) * 1000;
    Function<String, Long> anchoredTime = o.anchoredTime() != null ? o.anchoredTime() : seq -> null;
    Policy policy = o.policy();
    List<Leaf> ordered = new ArrayList<>(entries);
    ordered.sort((x, y) -> seqCompare(x.seq(), y.seq()));
    /* Every valid Dispatch Record per nonce, in seq order. */
    Map<String, List<Dispatch>> dispatches = new HashMap<>();
    Map<String, Set<String>> approvalHashes = new HashMap<>();
    for (Leaf e : ordered) {
      Dispatch d = dispatchOf(e.leaf());
      if (d != null) dispatches.computeIfAbsent(d.nonce(), k -> new ArrayList<>()).add(d);
      Map<String, Object> p = payloadObject(e.leaf().signedPayload());
      if (p != null && Div.INTENT_TYPE.equals(p.get("type")) && p.get("nonce") instanceof String nonce)
        approvalHashes.computeIfAbsent(nonce, k -> new HashSet<>()).add(payloadSha256(e.leaf().signedPayload()));
    }

    List<Entry> checks = new ArrayList<>();
    Map<String, List<String>> evidenceSeqs = new HashMap<>();
    /* Per nonce: the governing Dispatch Record of its bound statements (first seen). */
    Map<String, Dispatch> governingByNonce = new HashMap<>();
    Map<String, List<String>> lateContradictions = new HashMap<>();
    Map<String, List<String>> untrustedContradictions = new HashMap<>();
    Map<String, List<ContinuityRecord>> continuityRecords = new HashMap<>();
    for (Leaf e : entries) {
      if (!isEvidenceLeaf(e.leaf())) continue;
      Partial p = checkLeafSteps(e.leaf(), policy, anchoredTime.apply(e.seq()));
      Check c;
      if (p.decided() != null) c = p.decided();
      else {
        Statement s = p.statement();
        boolean trusted = p.trusted();
        String note = p.note();
        continuityRecords.computeIfAbsent(s.source(), k -> new ArrayList<>())
            .add(new ContinuityRecord(s.sequence(), e.leaf().signedPayload()));
        List<Dispatch> all = dispatches.getOrDefault(s.nonce(), List.of());
        Dispatch governing = null;
        for (Dispatch d : all) if (d.payloadSha256().equals(s.payloadSha256())) { governing = d; break; }
        if (governing == null)
          c = check("unbound", withNote(all.isEmpty()
              ? "No Dispatch Record for this approval nonce."
              : "No Dispatch Record for this nonce carries the statement's payload hash.", note), s, trusted);
        else if (!approvalHashes.getOrDefault(s.nonce(), Set.of()).contains(s.payloadSha256()))
          c = check("unbound", withNote("No Approval Record with this nonce and payload hash.", note), s, trusted);
        else {
          governingByNonce.putIfAbsent(s.nonce(), governing);
          long sampled = Ledger.parseAnchorTimestampMs(s.sampledAt());
          Deadline deadline = effectiveDeadlineOf(governing, maxWindowMs);
          // A provisioned key signed this contradiction but established no trust (`note` is set only
          // then). In-window or late, it cannot decide the status and must not be silent (§4.7.4).
          if (sampled >= governing.createdAtMs() - skewMs && !trusted && note != null && s.verdict().equals("contradicted"))
            untrustedContradictions.computeIfAbsent(s.nonce(), k -> new ArrayList<>()).add(e.seq());
          if (sampled < governing.createdAtMs() - skewMs)
            c = check("stale", withNote("Sampled before the dispatch evidence window (early).", note), s, trusted);
          else if (sampled > deadline.ms()) {
            c = check("stale", withNote("Sampled after the dispatch evidence window (late).", note), s, trusted);
            if (trusted && s.verdict().equals("contradicted"))
              lateContradictions.computeIfAbsent(s.nonce(), k -> new ArrayList<>()).add(e.seq());
          } else {
            c = check("verified", withNote("Statement verified and bound to its dispatch and approval.", note), s, trusted);
          }
        }
      }
      checks.add(new Entry(e.seq(), c));
      if (c.nonce() != null) evidenceSeqs.computeIfAbsent(c.nonce(), k -> new ArrayList<>()).add(e.seq());
    }

    TreeSet<String> nonces = new TreeSet<>(approvalHashes.keySet()); // String order is UTF-16 code-unit order
    nonces.addAll(dispatches.keySet());
    nonces.addAll(evidenceSeqs.keySet());
    Map<String, NonceStatus> byNonce = new TreeMap<>();
    List<String> confirmed = new ArrayList<>(), contradicted = new ArrayList<>(), unconfirmed = new ArrayList<>(),
        pending = new ArrayList<>(), notReported = new ArrayList<>(), lateContradicted = new ArrayList<>(),
        untrustedContradicted = new ArrayList<>(), dispatchConflicts = new ArrayList<>();
    for (String nonce : nonces) {
      boolean isConfirmed = false, isContradicted = false;
      for (Entry x : checks) {
        Check c = x.check();
        if (nonce.equals(c.nonce()) && c.status().equals("verified") && c.trusted()) {
          isConfirmed |= "confirmed".equals(c.verdict());
          isContradicted |= "contradicted".equals(c.verdict());
        }
      }
      List<Dispatch> all = dispatches.getOrDefault(nonce, List.of());
      // The governing record: the one the nonce's bound statements bound to, else the first that names it.
      Dispatch d = governingByNonce.containsKey(nonce) ? governingByNonce.get(nonce) : all.isEmpty() ? null : all.get(0);
      Deadline deadline = d == null ? null : effectiveDeadlineOf(d, maxWindowMs);
      String status = isContradicted ? "contradicted" : isConfirmed ? "confirmed" : d == null ? "not_reported"
          : deadline.ms() < now ? "unconfirmed" : "pending";
      Set<String> hashes = new HashSet<>();
      for (Dispatch x : all) hashes.add(x.payloadSha256());
      List<String> conflict = new ArrayList<>();
      if (hashes.size() > 1) for (Dispatch x : all) conflict.add(x.seq());
      List<String> late = lateContradictions.getOrDefault(nonce, List.of());
      List<String> untrusted = untrustedContradictions.getOrDefault(nonce, List.of());
      switch (status) {
        case "contradicted" -> contradicted.add(nonce);
        case "confirmed" -> confirmed.add(nonce);
        case "not_reported" -> notReported.add(nonce);
        case "unconfirmed" -> unconfirmed.add(nonce);
        default -> pending.add(nonce);
      }
      if (!conflict.isEmpty()) dispatchConflicts.add(nonce);
      if (!untrusted.isEmpty()) untrustedContradicted.add(nonce);
      if (!late.isEmpty()) lateContradicted.add(nonce);
      byNonce.put(nonce, new NonceStatus(status, d == null ? null : d.seq(), d == null ? null : d.deadline(),
          deadline == null ? null : DEWP_TIMESTAMP.format(Instant.ofEpochMilli(deadline.ms())),
          deadline != null && deadline.capped(), List.copyOf(conflict), List.copyOf(late), List.copyOf(untrusted),
          List.copyOf(evidenceSeqs.getOrDefault(nonce, List.of()))));
    }
    return new Verification(List.copyOf(checks), byNonce, confirmed, contradicted, unconfirmed, pending, notReported,
        lateContradicted, untrustedContradicted, dispatchConflicts, continuity(continuityRecords));
  }

  private ExecutionEvidence() {}
}
