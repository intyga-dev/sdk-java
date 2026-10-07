package com.intyga.sdk.offline;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.format.ResolverStyle;
import java.time.temporal.ChronoUnit;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * JavaScript {@code Date} semantics: millisecond precision, and {@code toISOString()} output.
 *
 * <p>{@code Instant.toString()} is NOT {@code toISOString()}: it drops a zero millisecond field and
 * prints micro/nanoseconds when present, and the challenge timestamps are signed bytes that every
 * port must reproduce exactly. Hence a fixed formatter, and every "now" truncated to milliseconds.
 */
final class JsTime {
  private static final DateTimeFormatter ISO =
      DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.ROOT)
          .withZone(ZoneOffset.UTC);

  private JsTime() {}

  /** {@code asOf}, or the current instant, at JavaScript's millisecond precision. */
  static Instant nowOr(Instant asOf) {
    return (asOf != null ? asOf : Instant.now()).truncatedTo(ChronoUnit.MILLIS);
  }

  /** {@code new Date(ms).toISOString()}: UTC, exactly three fractional digits, {@code Z}. */
  static String iso(Instant instant) {
    return ISO.format(instant.truncatedTo(ChronoUnit.MILLIS));
  }

  // RFC 3339 §5.6 date-time, strictly: four-digit year, uppercase T, seconds present, a 1–9 digit
  // fraction, an explicit Z or ±hh:mm zone (hours 00–23, minutes 00–59).
  private static final Pattern RFC3339 = Pattern.compile(
      "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,9})?(Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])");

  /**
   * Epoch milliseconds of a timestamp under the DIV §6.2 grammar, or null. Mirrors {@code
   * parseRfc3339Ms} in {@code packages/verify/src/index.ts} and verify-java's package-private {@code
   * SignedTime} — change them together. {@code Date.parse} (and {@code OffsetDateTime.parse}) are
   * too lenient for this: a bare date or a zone-less time would be read in the HOST's time zone,
   * and 30 February would roll into March. The date must exist; no leap second.
   */
  static Long parseMillis(String s) {
    if (s == null) {
      return null;
    }
    Matcher m = RFC3339.matcher(s);
    if (!m.matches()) {
      return null;
    }
    String zone = m.group(2);
    try {
      LocalDateTime local = LocalDateTime.parse(s.substring(0, s.length() - zone.length()),
          DateTimeFormatter.ISO_LOCAL_DATE_TIME.withResolverStyle(ResolverStyle.STRICT));
      long offsetSeconds = 0;
      if (!"Z".equals(zone)) {
        long magnitude = Long.parseLong(zone.substring(1, 3)) * 3600 + Long.parseLong(zone.substring(4, 6)) * 60;
        offsetSeconds = zone.charAt(0) == '-' ? -magnitude : magnitude;
      }
      // Applied by hand: ZoneOffset stops at ±18:00, RFC 3339 (and every other port) at ±23:59.
      return local.minusSeconds(offsetSeconds).toInstant(ZoneOffset.UTC).toEpochMilli();
    } catch (DateTimeParseException | ArithmeticException e) {
      return null;
    }
  }
}
