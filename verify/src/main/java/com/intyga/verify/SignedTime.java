package com.intyga.verify;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.format.ResolverStyle;
import java.util.regex.Pattern;

/**
 * Parses a signed DIV timestamp (expiresAt, challengedAt, sealedAt, signedAt) under the one grammar
 * every port applies (DIV §6.2): RFC 3339 §5.6 {@code date-time} with a four-digit year, uppercase
 * {@code T} and {@code Z}, seconds present, a 1–9 digit fraction and an explicit {@code Z} or
 * {@code ±hh:mm} zone; the date must exist and there is no leap second.
 *
 * <p>{@code OffsetDateTime.parse} alone is laxer: it accepts a missing seconds field, lowercase
 * separators and a year beyond four digits, which the Go, Rust, Python and TS ports refuse — so the
 * same signed string was accepted in one language and refused in another. The ISO formatter's
 * STRICT resolver checks the calendar (30 February) and the clock ranges once the shape is fixed.
 */
final class SignedTime {
  private static final Pattern RFC3339 = Pattern.compile(
      "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,9})?(Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])");

  private SignedTime() {}

  /**
   * The instant, as an {@code OffsetDateTime} at UTC. The offset is applied by hand rather than
   * through {@code ZoneOffset}, which is limited to ±18:00 where RFC 3339 (and every other port)
   * allows up to ±23:59.
   */
  static OffsetDateTime parse(String s) {
    java.util.regex.Matcher m = s == null ? null : RFC3339.matcher(s);
    if (m == null || !m.matches()) {
      throw new DateTimeParseException("not a strict RFC 3339 date-time", s == null ? "" : s, 0);
    }
    String zone = m.group(2);
    LocalDateTime local = LocalDateTime.parse(s.substring(0, s.length() - zone.length()),
        DateTimeFormatter.ISO_LOCAL_DATE_TIME.withResolverStyle(ResolverStyle.STRICT));
    long offsetSeconds = 0;
    if (!"Z".equals(zone)) {
      long magnitude = Long.parseLong(zone.substring(1, 3)) * 3600 + Long.parseLong(zone.substring(4, 6)) * 60;
      offsetSeconds = zone.charAt(0) == '-' ? -magnitude : magnitude;
    }
    return local.minusSeconds(offsetSeconds).atOffset(ZoneOffset.UTC);
  }
}
