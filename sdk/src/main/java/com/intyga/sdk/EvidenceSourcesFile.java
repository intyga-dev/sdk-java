package com.intyga.sdk;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.intyga.verify.ExecutionEvidence;
import com.intyga.verify.Ledger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The relying party's evidence-source trust file for DEWP §4.7 execution evidence. Port of {@code
 * packages/sdk/src/evidence-sources.ts} ({@code parseEvidenceSourcesFile} + {@code
 * evidencePolicyFromFile}); the contract is the "evidence-source trust file" paragraph of
 * docs/API.md §2e, and the shared cases are {@code executionEvidence.trustFiles} in {@code
 * verifier-parity-vectors.json}.
 *
 * <p>Deliberately a separate file from the approver trust anchor ({@link
 * com.intyga.sdk.offline.TrustAnchorFile}): an approver is not an independent observer of the action
 * they approved, and a source key accepted as an approver key would let a sensor approve (DEWP
 * §4.7.5). Like the trust anchor it carries no signature — adopting it into your configuration is the
 * act of trust.
 *
 * <pre>{@code
 * EvidenceSourcesFile file = EvidenceSourcesFile.parse(Files.readString(Path.of("sources.json")));
 * ExecutionEvidence.Policy evidencePolicy = file.evidencePolicy();
 * }</pre>
 *
 * @param sources each source in file order
 */
public record EvidenceSourcesFile(List<Source> sources) {

  /** The file's {@code type}. */
  public static final String TYPE = "intyga-evidence-sources";

  /**
   * Tree model only: data binding would quietly drop a misspelt member, and a misspelt bound must be
   * a refusal. Trailing tokens are refused because {@code JSON.parse} refuses them; duplicate members
   * keep the last value, as {@code JSON.parse} does.
   */
  private static final ObjectMapper JSON =
      new ObjectMapper().configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, true);

  /** The reference's {@code /^[A-Za-z0-9+/]+={0,2}$/}: standard base64, no base64url. */
  private static final Pattern BASE64 = Pattern.compile("[A-Za-z0-9+/]+={0,2}");

  /** The only members a key object may carry. */
  private static final Set<String> KEY_MEMBERS = Set.of("key", "notBefore", "notAfter");

  /**
   * One evidence source.
   *
   * @param did the source's identifier — what its statements carry as {@code source}
   * @param publicKeys the keys that speak for it, in file order and exactly as written: each a {@link
   *     String} (a bare base64 SPKI P-256 key, valid at any time) or an {@link
   *     ExecutionEvidence.SourceKey} (the {@code {key, notBefore?, notAfter?}} form; an absent bound
   *     is null). A bounded key establishes trust only when the Evidence Record's anchored time lies
   *     inside {@code [notBefore, notAfter]} (DEWP §4.7.5).
   * @param label display only; null when the file has none
   */
  public record Source(String did, List<Object> publicKeys, String label) {
    public Source {
      publicKeys = List.copyOf(publicKeys);
    }
  }

  public EvidenceSourcesFile {
    sources = List.copyOf(sources);
  }

  /**
   * Parse and validate an evidence-sources file, failing loudly on the first problem.
   *
   * @throws InvalidEvidenceSourcesException naming the single problem found
   */
  public static EvidenceSourcesFile parse(String jsonText) {
    JsonNode obj = readJson(jsonText);
    if (!obj.isObject()) {
      throw fail("root must be an object");
    }
    if (!TYPE.equals(text(obj.get("type")))) {
      throw fail("type must be \"" + TYPE + "\" — approver trust (intyga-trust-anchor) is a separate file");
    }
    // The integer 1, read from the token: a string "1", true or 1.5 is not the version, and neither
    // is asInt()'s coercion of them.
    JsonNode v = obj.get("v");
    // JavaScript `v === 1`: the NUMBER 1 in any JSON spelling (`1.0`, `1e0`), never a boolean or
    // string — as TrustAnchorFile already reads its own version.
    if (v == null || !v.isNumber() || v.decimalValue().compareTo(java.math.BigDecimal.ONE) != 0) {
      throw fail("unsupported version " + show(v) + " (expected 1)");
    }
    JsonNode sources = obj.get("sources");
    if (sources == null || !sources.isArray() || sources.isEmpty()) {
      throw fail("sources must be a non-empty array — an empty file would trust nobody");
    }
    Set<String> seen = new HashSet<>();
    List<Source> parsed = new ArrayList<>();
    for (JsonNode entry : sources) {
      // An array passes the reference's `typeof === "object"` check and then has no did.
      if (!(entry.isObject() || entry.isArray())) {
        throw fail("every sources[] entry must be an object");
      }
      String did = text(entry.get("did"));
      if (did == null || did.isEmpty()) {
        throw fail("every source needs a non-empty did");
      }
      if (!seen.add(did)) {
        throw fail("duplicate source " + did);
      }
      JsonNode publicKeys = entry.get("publicKeys");
      if (publicKeys == null || !publicKeys.isArray() || publicKeys.isEmpty()) {
        throw fail("source " + did + ": publicKeys must be a non-empty array");
      }
      List<Object> keys = new ArrayList<>();
      for (JsonNode key : publicKeys) {
        keys.add(parseKey(did, key));
      }
      JsonNode label = entry.get("label");
      if (label != null && !label.isTextual()) {
        throw fail("source " + did + ": label must be a string");
      }
      parsed.add(new Source(did, keys, text(label)));
    }
    return new EvidenceSourcesFile(parsed);
  }

  /**
   * The verifier's evidence-source trust: each {@code did} mapped to its keys in file order, exactly
   * as written — what {@code Dewp.EvidenceOptions} and {@code ExecutionEvidence} take as their
   * evidence policy. Every entry is a form the verifier reads as well-formed; none is dropped or
   * marked malformed.
   */
  public ExecutionEvidence.Policy evidencePolicy() {
    Map<String, List<Object>> trusted = new LinkedHashMap<>();
    for (Source s : sources) {
      trusted.put(s.did(), s.publicKeys());
    }
    return new ExecutionEvidence.Policy(Collections.unmodifiableMap(trusted));
  }

  /** A bare key as its string, a key object as a {@link ExecutionEvidence.SourceKey}. */
  private static Object parseKey(String did, JsonNode key) {
    if (key.isTextual()) {
      if (!BASE64.matcher(key.textValue()).matches()) {
        throw fail("source " + did + ": every publicKeys[] entry must be a base64 SPKI key");
      }
      return key.textValue();
    }
    if (!key.isObject()) {
      throw fail("source " + did
          + ": every publicKeys[] entry must be a base64 SPKI key or { key, notBefore?, notAfter? }");
    }
    String k = text(key.get("key"));
    if (k == null || !BASE64.matcher(k).matches()) {
      throw fail("source " + did + ": every publicKeys[] entry must carry a base64 SPKI key");
    }
    // Exactly these members: a misspelt bound (`notafter`, `revokedAt`) must not read as "no bound".
    for (Iterator<String> names = key.fieldNames(); names.hasNext(); ) {
      String member = names.next();
      if (!KEY_MEMBERS.contains(member)) {
        throw fail("source " + did + ": unexpected member \"" + member
            + "\" in a publicKeys[] entry (only key, notBefore, notAfter)");
      }
    }
    Long notBefore = timestamp(did, "notBefore", key.get("notBefore"));
    Long notAfter = timestamp(did, "notAfter", key.get("notAfter"));
    if (notBefore != null && notAfter != null && notBefore > notAfter) {
      throw fail("source " + did + ": notBefore is later than notAfter");
    }
    return new ExecutionEvidence.SourceKey(k, text(key.get("notBefore")), text(key.get("notAfter")));
  }

  /**
   * A present bound as epoch milliseconds, or null when absent. It must be a DEWP §4.3 timestamp
   * naming a real instant, read exactly as the verifier reads it ({@link
   * Ledger#parseAnchorTimestampMs}: ASCII digits, strict and round-tripped, so 30 February and hour 24
   * are refused). A bound the loader accepted but the verifier refused would load cleanly and then
   * silently trust nothing. JSON {@code null} is present, and refused.
   */
  private static Long timestamp(String did, String field, JsonNode value) {
    if (value == null) {
      return null;
    }
    Long ms = value.isTextual() ? Ledger.parseAnchorTimestampMs(value.textValue()) : null;
    if (ms == null) {
      throw fail("source " + did + ": " + field + " must be a YYYY-MM-DDTHH:mm:ss.sssZ timestamp");
    }
    return ms;
  }

  /** {@code JSON.parse}: exactly one JSON value, or a refusal. */
  private static JsonNode readJson(String text) {
    if (text == null) {
      throw fail("not valid JSON (no text)");
    }
    JsonNode node;
    try {
      node = JSON.readTree(text);
    } catch (JsonProcessingException e) {
      throw fail("not valid JSON (" + e.getOriginalMessage() + ")");
    }
    // Jackson answers empty input with a MissingNode; JSON.parse("") throws.
    if (node == null || node.isMissingNode()) {
      throw fail("not valid JSON (no value)");
    }
    return node;
  }

  /** The text of a string node, or null for anything else (absent, JSON null, a number…). */
  private static String text(JsonNode n) {
    return n != null && n.isTextual() ? n.textValue() : null;
  }

  /** {@code JSON.stringify} of a value for a message; {@code undefined} for an absent one. */
  private static String show(JsonNode n) {
    return n == null ? "undefined" : n.toString();
  }

  private static InvalidEvidenceSourcesException fail(String detail) {
    return new InvalidEvidenceSourcesException(detail);
  }
}
