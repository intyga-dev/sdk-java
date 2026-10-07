package com.intyga.sdk.offline;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * JSON and JavaScript-semantics helpers. The TypeScript SDK is the reference implementation, and
 * several of its checks lean on JavaScript's own rules ({@code Number.isSafeInteger}, {@code trim},
 * {@code JSON.parse}); these reproduce them over Jackson trees so a bundle refused there is refused
 * here.
 */
final class Js {

  /**
   * Tree model and plain maps only — polymorphic default typing (Jackson's CVE surface) is never
   * enabled. Trailing tokens are refused because {@code JSON.parse} refuses them: Jackson's default
   * would read {@code {"did":"x"} garbage} as the object and silently drop the rest.
   */
  static final ObjectMapper JSON =
      new ObjectMapper()
          .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
          .configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, true);

  private static final double MAX_SAFE_INTEGER = 9007199254740991d;
  private static final BigInteger MAX_SAFE_BIG = BigInteger.valueOf(9007199254740991L);

  private Js() {}

  /** {@code JSON.parse}: the tree, or null when the text is not exactly one JSON value. */
  static JsonNode parse(String text) {
    if (text == null) {
      return null;
    }
    try {
      JsonNode node = JSON.readTree(text);
      // Jackson answers empty input with a MissingNode; JSON.parse("") throws.
      return node == null || node.isMissingNode() ? null : node;
    } catch (JsonProcessingException e) {
      return null;
    }
  }

  /** {@code Number.isSafeInteger}: a number, integral, |x| ≤ 2^53 − 1. */
  static boolean isSafeInteger(JsonNode n) {
    if (n == null || !n.isNumber()) {
      return false;
    }
    if (n.isIntegralNumber()) {
      return n.bigIntegerValue().abs().compareTo(MAX_SAFE_BIG) <= 0;
    }
    double d = n.doubleValue();
    return Double.isFinite(d) && d == Math.rint(d) && Math.abs(d) <= MAX_SAFE_INTEGER;
  }

  /** {@code Number.isInteger}: a finite number with no fractional part. */
  static boolean isInteger(JsonNode n) {
    if (n == null || !n.isNumber()) {
      return false;
    }
    if (n.isIntegralNumber()) {
      return true;
    }
    double d = n.doubleValue();
    return Double.isFinite(d) && d == Math.rint(d);
  }

  /** {@code value === 1} for a JSON number (1 and 1.0 are the same JavaScript number). */
  static boolean isNumberOne(JsonNode n) {
    return n != null && n.isNumber() && n.doubleValue() == 1d;
  }

  static boolean isString(JsonNode n) {
    return n != null && n.isTextual();
  }

  static boolean isNonEmptyString(JsonNode n) {
    return n != null && n.isTextual() && !n.textValue().isEmpty();
  }

  /** A JSON array whose every element is a string — non-empty strings when {@code nonEmpty}. */
  static boolean isStringArray(JsonNode n, boolean nonEmpty) {
    if (n == null || !n.isArray()) {
      return false;
    }
    for (JsonNode e : n) {
      if (!(nonEmpty ? isNonEmptyString(e) : isString(e))) {
        return false;
      }
    }
    return true;
  }

  /** The textual elements of an array, in order; an absent or non-array value yields an empty list. */
  static List<String> strings(JsonNode n) {
    List<String> out = new ArrayList<>();
    if (n != null && n.isArray()) {
      for (JsonNode e : n) {
        if (e.isTextual()) {
          out.add(e.textValue());
        }
      }
    }
    return List.copyOf(out);
  }

  /** The text of a string node, or null for anything else (absent, JSON null, a number…). */
  static String text(JsonNode n) {
    return n != null && n.isTextual() ? n.textValue() : null;
  }

  /** A JSON object as the plain Java map the canonical builders accept (Integer/Long/Double/…). */
  static Map<String, Object> toMap(JsonNode n) {
    return JSON.convertValue(n, new TypeReference<LinkedHashMap<String, Object>>() {});
  }

  /**
   * ECMAScript {@code String.prototype.trim}: strips WhiteSpace and LineTerminator code points,
   * which include U+00A0 and the U+FEFF byte-order mark. {@code String.strip()} keeps both, so a
   * pasted envelope or a BOM-prefixed file would read differently here than in the reference.
   */
  static String trim(String s) {
    int start = 0;
    int end = s.length();
    while (start < end && isJsWhitespace(s.charAt(start))) {
      start++;
    }
    while (end > start && isJsWhitespace(s.charAt(end - 1))) {
      end--;
    }
    return s.substring(start, end);
  }

  private static boolean isJsWhitespace(char c) {
    switch (c) {
      case '\t', '\n', 0x0B, '\f', '\r', ' ', 0x00A0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000,
          0xFEFF:
        return true;
      default:
        return c >= 0x2000 && c <= 0x200A;
    }
  }
}
