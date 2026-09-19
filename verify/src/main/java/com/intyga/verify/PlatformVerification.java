package com.intyga.verify;

import java.util.List;

/** Result of verifying a platform hash-only receipt. */
public record PlatformVerification(boolean ok, String reason, List<String> signers) {
  static PlatformVerification refuse(String reason) { return new PlatformVerification(false, reason, List.of()); }
}
