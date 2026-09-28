package com.intyga.verify;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.format.DateTimeParseException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** 2026-09-27 review L15, L20 and I7. Cross-language verdicts live in the parity vectors. */
final class InputHardeningTest {
  @Test void signedTimesFollowOneStrictRfc3339Grammar() {
    for (String ok : List.of("2027-09-01T12:00:00Z", "2027-09-01T12:00:00.123456789Z",
        "2027-09-01T14:00:00+02:00", "2028-02-29T00:00:00-23:59")) {
      assertDoesNotThrow(() -> SignedTime.parse(ok), ok);
    }
    // Offsets beyond java.time's ±18:00 are valid RFC 3339 and normalize like any other.
    assertEquals(SignedTime.parse("2028-02-29T23:59:00Z").toInstant(),
        SignedTime.parse("2028-02-29T00:00:00-23:59").toInstant());
    for (String bad : List.of("2027-09-01", "2027-09-01T12:00:00", "2027-09-01T12:00Z",
        "2027-09-01t12:00:00z", "2027-02-30T12:00:00Z", "2027-02-29T12:00:00Z",
        "2027-06-30T23:59:60Z", "2027-09-01T12:00:00,5Z", "2027-09-01T12:00:00.1234567891Z",
        "2027-09-01T12:00:00+24:00", "+02027-09-01T12:00:00Z")) {
      assertThrows(DateTimeParseException.class, () -> SignedTime.parse(bad), bad);
    }
  }

  @Test void rfc3161GenTimeUsesTheStrictResolver() {
    assertEquals(1_788_091_200L, Rfc3161.parseGeneralizedTime("20260830120000Z").seconds());
    // The default SMART resolver read 30 February as 28 February; every other port refuses it.
    assertThrows(IllegalArgumentException.class, () -> Rfc3161.parseGeneralizedTime("20260230120000Z"));
    assertThrows(IllegalArgumentException.class, () -> Rfc3161.parseGeneralizedTime("20260431120000Z"));
  }

  @Test void aKeySharedByTwoDidsCountsOnce() {
    Map<String, String> counted = new LinkedHashMap<>();
    assertNull(Verify.sharedKeyProblem(counted, "AAEC", "did:a"));
    assertNull(Verify.sharedKeyProblem(counted, "AAEC", "did:a"));
    assertNotNull(Verify.sharedKeyProblem(counted, "AAEC", "did:b"));
    assertNull(Verify.sharedKeyProblem(counted, "AAE=", "did:c"));
    // An unpadded spelling of the same bytes is the same key.
    assertNotNull(Verify.sharedKeyProblem(counted, "AAE", "did:d"));
  }
}
