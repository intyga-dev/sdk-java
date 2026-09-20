package com.intyga.verify;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Canonical DIV payload builders and the strict RFC 8785 JCS serializer they share. Byte-identical
 * to the TS reference (`@intyga/mcp-schemas` / `@intyga/verify`) and the Go/Rust/Python ports,
 * locked by {@code packages/mcp-schemas/vectors/canonical-vectors.json}.
 */
public final class Canonical {

  /** Refusal of a value whose canonical bytes would differ across the language ports. */
  public static final class NonPortableValueException extends IllegalArgumentException {
    NonPortableValueException(String message) {
      super(message);
    }
  }

  /**
   * Recursively serializes a JSON-shaped value (null, Boolean, String, Number, List, Map) into
   * deterministic JSON with UTF-16-sorted keys.
   *
   * <p>It REFUSES any number whose canonical form could diverge across the TS/Go/Rust/Python/Java
   * ports — NaN/±Inf, negative zero, nonzero |x| &gt;= 1e16, and nonzero non-integer |x| &lt; 1e-4 —
   * mirroring isPortableNumber in the TS reference. Such a value serializes one way in one port and
   * another way elsewhere, so bytes signed over it would fail verification in another port and read
   * as tampering there. Refusing up front, with a reason that names the number, is the only
   * fail-closed option.
   */
  public static String stableStringify(Object v) {
    if (v == null) {
      return "null";
    }
    if (v instanceof Boolean b) {
      return b ? "true" : "false";
    }
    if (v instanceof String s) {
      // MUST NOT rely on a general JSON library for strings: this repo's ports have each shipped a
      // serializer that escaped more than RFC 8785 does (Go: <, >, &, U+2028/U+2029). Escape only
      // what JSON.stringify escapes and emit everything else literally.
      return jsMarshalString(s);
    }
    if (v instanceof Double || v instanceof Float) {
      double d = ((Number) v).doubleValue();
      checkPortableFloat(d);
      if (d == Math.rint(d)) {
        // Safe: checkPortableFloat guarantees |d| < 1e16, far inside long range.
        return Long.toString((long) d);
      }
      return formatShortestDouble(d);
    }
    if (v instanceof Integer || v instanceof Long || v instanceof Short || v instanceof Byte) {
      return portableLong(((Number) v).longValue());
    }
    if (v instanceof BigDecimal bd) {
      // Reached when a caller's mapper is configured with USE_BIG_DECIMAL_FOR_FLOATS, or the params
      // map was hand-built. The canonical form is defined over the IEEE-754 double every other port
      // parses into, so the value is accepted only when the shortest form of that double reads back
      // as the SAME number — otherwise Java would emit digits no other port could reproduce.
      double d = bd.doubleValue();
      String out = stableStringify(d);
      if (new BigDecimal(out).compareTo(bd) != 0) {
        throw new NonPortableValueException(
            bd + " carries more precision than a double, so it does not canonicalize portably");
      }
      return out;
    }
    if (v instanceof BigInteger bi) {
      // Jackson yields BigInteger only beyond long range, which is far outside the portable bound.
      if (bi.abs().compareTo(BigInteger.valueOf((long) 1e16)) >= 0) {
        throw new NonPortableValueException(bi + " is outside the portable range (|x| < 1e16)");
      }
      return portableLong(bi.longValueExact());
    }
    if (v instanceof List<?> list) {
      StringBuilder sb = new StringBuilder("[");
      for (int i = 0; i < list.size(); i++) {
        if (i > 0) {
          sb.append(',');
        }
        sb.append(stableStringify(list.get(i)));
      }
      return sb.append(']').toString();
    }
    if (v instanceof Map<?, ?> map) {
      List<String> keys = new ArrayList<>(map.size());
      for (Object k : map.keySet()) {
        if (!(k instanceof String)) {
          throw new NonPortableValueException("object keys must be strings");
        }
        keys.add((String) k);
      }
      // String.compareTo IS UTF-16 code-unit order — the comparator RFC 8785 requires, and the one
      // the TS reference sorts by. (Go and Rust each had to build this comparator by hand.)
      keys.sort(String::compareTo);
      StringBuilder sb = new StringBuilder("{");
      for (int i = 0; i < keys.size(); i++) {
        if (i > 0) {
          sb.append(',');
        }
        // Object KEYS need the same escaping as values — a key containing "&" is just as
        // divergent as a value containing one.
        sb.append(jsMarshalString(keys.get(i))).append(':').append(stableStringify(map.get(keys.get(i))));
      }
      return sb.append('}').toString();
    }
    throw new NonPortableValueException(
        "unsupported value type for canonicalization: " + v.getClass().getName());
  }

  /**
   * Serializes a string exactly as JS {@code JSON.stringify} does, which is what RFC 8785 requires:
   * escape only {@code "} and {@code \} plus the C0 control range, and emit everything else
   * literally — including {@code <}, {@code >}, {@code &} and U+2028/U+2029, which several JSON
   * libraries escape and JS does not. Iterating UTF-16 code units and appending them unchanged
   * preserves surrogate pairs byte-for-byte.
   */
  static String jsMarshalString(String s) {
    StringBuilder b = new StringBuilder(s.length() + 2);
    b.append('"');
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
        case '"' -> b.append("\\\"");
        case '\\' -> b.append("\\\\");
        case '\b' -> b.append("\\b");
        case '\f' -> b.append("\\f");
        case '\n' -> b.append("\\n");
        case '\r' -> b.append("\\r");
        case '\t' -> b.append("\\t");
        default -> {
          if (c < 0x20 || isLoneSurrogate(s, i)) {
            b.append(String.format("\\u%04x", (int) c));
          } else {
            b.append(c);
          }
        }
      }
    }
    return b.append('"').toString();
  }

  /**
   * Whether the code unit at {@code i} is a surrogate with no partner — a high surrogate not
   * followed by a low one, or a low surrogate not preceded by a high one.
   *
   * <p>Such a code unit is not valid UTF-8 and every language disposes of it differently: the TS
   * reference escapes it (ES2019 well-formed {@code JSON.stringify}), Go's decoder substitutes
   * U+FFFD, and serde_json rejects it at parse. Appending it raw here would be a FOURTH answer —
   * {@code String.getBytes(UTF_8)} maps it to {@code '?'} — so the same receipt would canonicalize
   * differently in Java than anywhere else and read as tampering. Matching the TS reference is
   * correct because TS is the normative source of the canonical form.
   */
  private static boolean isLoneSurrogate(String s, int i) {
    char c = s.charAt(i);
    if (Character.isHighSurrogate(c)) {
      return i + 1 >= s.length() || !Character.isLowSurrogate(s.charAt(i + 1));
    }
    if (Character.isLowSurrogate(c)) {
      return i == 0 || !Character.isHighSurrogate(s.charAt(i - 1));
    }
    return false;
  }

  private static void checkPortableFloat(double val) {
    if (Double.isNaN(val) || Double.isInfinite(val)) {
      throw new NonPortableValueException("NaN/Infinity is not JSON");
    }
    if (val == 0 && Double.doubleToRawLongBits(val) != 0) {
      throw new NonPortableValueException("-0 does not serialize portably across verifiers");
    }
    double abs = Math.abs(val);
    if (val != 0 && abs >= 1e16) {
      throw new NonPortableValueException(val + " is outside the portable range (|x| < 1e16)");
    }
    if (val != 0 && val != Math.rint(val) && abs < 1e-4) {
      throw new NonPortableValueException(
          val + " is outside the portable float range (1e-4 ≤ |x| < 1e16)");
    }
  }

  private static String portableLong(long val) {
    if (val >= (long) 1e16 || val <= -(long) 1e16) {
      throw new NonPortableValueException(val + " is outside the portable range (|x| < 1e16)");
    }
    return Long.toString(val);
  }

  /**
   * Formats a non-integral double in the portable range [1e-4, 1e16) the way ECMAScript
   * Number::toString does: the SHORTEST decimal that round-trips, in plain (non-exponent) notation
   * — the range guarantees ES never uses exponent form here.
   *
   * <p>Deliberately NOT Double.toString: before JDK 19 it can emit more digits than necessary
   * (JDK-4511638), and a consumer running this library on 17 must produce the same bytes as one on
   * 21. The shortening loop below is JDK-version-independent.
   */
  private static String formatShortestDouble(double d) {
    BigDecimal exact = new BigDecimal(d);
    for (int precision = 1; precision <= 17; precision++) {
      BigDecimal candidate = exact.round(new MathContext(precision, RoundingMode.HALF_EVEN));
      if (candidate.doubleValue() == d) {
        return candidate.stripTrailingZeros().toPlainString();
      }
    }
    return exact.toPlainString();
  }

  /**
   * UTF-16 code-unit order over a set element, with a JSON null sorted as the text {@code "null"}.
   *
   * <p>These lists arrive from attacker-supplied JSON and Jackson maps a null inside one to a null
   * ELEMENT, which {@code String::compareTo} throws on — an exception escaping a verifier documented
   * to RETURN a refusal. Sorting it as "null" is what the TS reference's default comparator does
   * ({@code String(null)}), so a non-conformant list still canonicalizes to identical bytes.
   */
  private static int compareSortable(String a, String b) {
    return (a == null ? "null" : a).compareTo(b == null ? "null" : b);
  }

  private static String nz(String s) {
    return s == null ? "" : s;
  }

  private static Map<String, Object> nonNullParams(Map<String, Object> params) {
    return params == null ? new LinkedHashMap<>() : params;
  }

  /**
   * The requester + requirement projection shared by all three builders. One definition rather than
   * three copies: these bytes are the contract, and a field added to one builder but not the others
   * is exactly the drift the golden vectors exist to catch.
   */
  private static Map<String, Object>[] canonicalCommon(
      RequesterIdentity requester, ApprovalRequirement requirement) {
    Map<String, Object> attestation = null;
    if (requester.attestation() != null) {
      attestation = new LinkedHashMap<>();
      attestation.put("method", nz(requester.attestation().method()));
      attestation.put("issuer", nz(requester.attestation().issuer()));
      attestation.put("subject", nz(requester.attestation().subject()));
    }
    // The SET is the policy: sort so two identical allowlists written in different orders produce
    // identical signed bytes. UTF-16 code-unit order — the same comparator the object keys use.
    List<String> aaguids =
        requirement.allowedAaguids() == null
            ? new ArrayList<>()
            : new ArrayList<>(requirement.allowedAaguids());
    aaguids.sort(Canonical::compareSortable);

    Map<String, Object> req = new LinkedHashMap<>();
    req.put("did", nz(requester.did()));
    req.put("attestation", attestation);
    Map<String, Object> rq = new LinkedHashMap<>();
    rq.put("requiredApprovals", requirement.requiredApprovals());
    rq.put("requireHardwareKey", requirement.requireHardwareKey());
    rq.put("allowedAaguids", aaguids);
    rq.put("requesterCannotApprove", requirement.requesterCannotApprove());
    rq.put("signerClass", nz(requirement.signerClass()));
    @SuppressWarnings("unchecked")
    Map<String, Object>[] out = new Map[] {req, rq};
    return out;
  }

  /**
   * Builds a byte-identical DIV Intent Payload (docs/DIV.md v1) via {@link #stableStringify} —
   * strict JCS, every key sorted. Do NOT hand-template key order; the sort is the contract. Throws
   * {@link NonPortableValueException} only when params carry a value stableStringify refuses.
   */
  public static String canonicalIntentPayload(
      String target,
      String actionType,
      String display,
      Map<String, Object> params,
      RequesterIdentity requester,
      ApprovalRequirement requirement,
      String nonce,
      String expiresAt) {
    return canonicalIntentPayload(target, actionType, display, params, requester, requirement, nonce, expiresAt, null);
  }

  public static String canonicalIntentPayload(
      String target, String actionType, String display, Map<String, Object> params,
      RequesterIdentity requester, ApprovalRequirement requirement, String nonce,
      String expiresAt, Map<String, Object> agentContext) {
    Map<String, Object>[] common = canonicalCommon(requester, requirement);
    Map<String, Object> obj = new LinkedHashMap<>();
    obj.put("v", Div.VERSION);
    obj.put("type", Div.INTENT_TYPE);
    obj.put("target", nz(target));
    obj.put("actionType", nz(actionType));
    obj.put("display", nz(display));
    obj.put("params", nonNullParams(params));
    // DIV §4.3.4. Reserved and REQUIRED in the bytes; `null` states that no external-evidence
    // condition applied. LinkedHashMap.put, never Map.of — Map.of throws NullPointerException on a
    // null value, and Verify's catch(RuntimeException) would turn that into an opaque refusal.
    obj.put("evidence", null);
    obj.put("requester", common[0]);
    obj.put("requirement", common[1]);
    obj.put("nonce", nz(nonce));
    if (agentContext == null) {
      obj.put("expiresAt", nz(expiresAt));
    } else {
      obj.put("action", agentContext.get("action"));
      obj.put("agent", agentContext.get("agent"));
      obj.put("session", agentContext.get("session"));
      obj.put("nbf", agentContext.get("nbf"));
      obj.put("exp", nz(expiresAt));
    }
    return stableStringify(obj);
  }

  /**
   * Builds a byte-identical OFFLINE APPROVAL payload (DIV §5a.2). Deliberately a separate method
   * rather than a type argument on {@link #canonicalIntentPayload}, so the ordinary approval path
   * cannot accidentally emit an offline payload. challengedAt exists so a verifier can bound the
   * validity WINDOW, not merely the expiry.
   */
  public static String canonicalOfflineIntentPayload(
      String target,
      String actionType,
      String display,
      Map<String, Object> params,
      RequesterIdentity requester,
      ApprovalRequirement requirement,
      String nonce,
      String challengedAt,
      String expiresAt) {
    Map<String, Object>[] common = canonicalCommon(requester, requirement);
    Map<String, Object> obj = new LinkedHashMap<>();
    obj.put("v", Div.VERSION);
    obj.put("type", Div.OFFLINE_INTENT_TYPE);
    obj.put("target", nz(target));
    obj.put("actionType", nz(actionType));
    obj.put("display", nz(display));
    obj.put("params", nonNullParams(params));
    // DIV §4.3.4. Reserved and REQUIRED in the bytes; `null` states that no external-evidence
    // condition applied. LinkedHashMap.put, never Map.of — Map.of throws NullPointerException on a
    // null value, and Verify's catch(RuntimeException) would turn that into an opaque refusal.
    obj.put("evidence", null);
    obj.put("requester", common[0]);
    obj.put("requirement", common[1]);
    obj.put("nonce", nz(nonce));
    obj.put("challengedAt", nz(challengedAt));
    obj.put("expiresAt", nz(expiresAt));
    return stableStringify(obj);
  }

  /**
   * Builds a byte-identical DELEGATION payload (DIV §5a.5) — a signed statement about WHO MAY
   * APPROVE, not about what may run. delegatedTo is sorted because it is a SET, exactly as
   * allowedAaguids is; requirement describes the quorum that signed this delegation, while
   * delegatedQuorum is how many of delegatedTo must sign at incident time — two different quorums,
   * so both are in the signed bytes.
   */
  public static String canonicalDelegationPayload(
      String target,
      String actionType,
      String display,
      Map<String, Object> params,
      RequesterIdentity requester,
      ApprovalRequirement requirement,
      List<String> delegatedTo,
      int delegatedQuorum,
      String nonce,
      String sealedAt,
      String expiresAt) {
    Map<String, Object>[] common = canonicalCommon(requester, requirement);
    List<String> delegates = delegatedTo == null ? new ArrayList<>() : new ArrayList<>(delegatedTo);
    delegates.sort(Canonical::compareSortable);
    Map<String, Object> obj = new LinkedHashMap<>();
    obj.put("v", Div.VERSION);
    obj.put("type", Div.DELEGATION_TYPE);
    obj.put("target", nz(target));
    obj.put("actionType", nz(actionType));
    obj.put("display", nz(display));
    obj.put("params", nonNullParams(params));
    obj.put("requester", common[0]);
    obj.put("requirement", common[1]);
    obj.put("delegatedTo", delegates);
    obj.put("delegatedQuorum", delegatedQuorum);
    obj.put("nonce", nz(nonce));
    obj.put("sealedAt", nz(sealedAt));
    obj.put("expiresAt", nz(expiresAt));
    return stableStringify(obj);
  }

  private Canonical() {}
}
