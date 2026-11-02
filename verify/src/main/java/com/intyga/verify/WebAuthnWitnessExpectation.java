package com.intyga.verify;

import java.util.List;

/**
 * What a standalone WebAuthn witness must be bound to, asserted from YOUR configuration — as
 * {@code WebAuthnWitnessExpectation} in {@code @intyga/verify}.
 *
 * @param expectedOrigin the origins the ceremony may have run on; at least one, none empty
 * @param expectedRpId the RP ID whose hash authenticatorData must carry
 * @param requireUserVerification null or true requires the UV flag (the default); false waives it
 * @param allowCrossOrigin true accepts an assertion produced in a cross-origin frame (default false)
 */
public record WebAuthnWitnessExpectation(
    List<String> expectedOrigin,
    String expectedRpId,
    Boolean requireUserVerification,
    boolean allowCrossOrigin) {

  /** One origin, user verification required, no cross-origin frames. */
  public WebAuthnWitnessExpectation(String expectedOrigin, String expectedRpId) {
    this(expectedOrigin == null ? null : java.util.Collections.singletonList(expectedOrigin), expectedRpId, null, false);
  }

  /** Several acceptable origins, user verification required, no cross-origin frames. */
  public WebAuthnWitnessExpectation(List<String> expectedOrigin, String expectedRpId) {
    this(expectedOrigin, expectedRpId, null, false);
  }
}
