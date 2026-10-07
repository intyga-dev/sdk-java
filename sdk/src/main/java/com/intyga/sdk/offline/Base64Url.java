package com.intyga.sdk.offline;

import java.util.Base64;
import java.util.regex.Pattern;

/** base64url without padding, and the reference's lenient decoder. */
final class Base64Url {
  private static final Pattern STRICT = Pattern.compile("[A-Za-z0-9_-]*={0,2}");

  private Base64Url() {}

  /**
   * Strict base64url (unpadded or padded) for the {@code DIV1:} / {@code SIG1:} envelopes, or null
   * when {@code s} carries anything outside that alphabet. A lenient decoder would skip stray
   * characters, so a paste with extra text in it would decode to something other than what was sent;
   * every SDK refuses such input.
   */
  static byte[] decodeStrict(String s) {
    return STRICT.matcher(s).matches() ? decodeLenient(s) : null;
  }

  static String encode(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  /**
   * Decodes the way the reference's JWS reader does ({@code Buffer.from(s.replace(/-/g,"+")
   * .replace(/_/g,"/"), "base64")}): either alphabet, characters outside it skipped, decoding stops
   * at padding, and a dangling sixth-bit character is dropped. Never throws.
   *
   * <p>Used directly only for the trust-bundle JWS, where leniency cannot widen what verifies: the
   * signature covers the encoded TEXT, not the decoded bytes.
   */
  static byte[] decodeLenient(String s) {
    StringBuilder b = new StringBuilder(s.length());
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if (c == '=') {
        break;
      }
      if (c == '-') {
        c = '+';
      } else if (c == '_') {
        c = '/';
      }
      if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+'
          || c == '/') {
        b.append(c);
      }
    }
    if (b.length() % 4 == 1) {
      b.setLength(b.length() - 1);
    }
    return Base64.getDecoder().decode(b.toString());
  }
}
