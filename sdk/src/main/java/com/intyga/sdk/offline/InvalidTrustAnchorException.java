package com.intyga.sdk.offline;

/**
 * A trust-anchor file was refused. The message names exactly one problem, prefixed {@code invalid
 * trust-anchor file:} — a trust anchor is security configuration, so a malformed one fails loudly at
 * load time rather than surfacing later as an unverifiable receipt.
 */
public final class InvalidTrustAnchorException extends IllegalArgumentException {
  InvalidTrustAnchorException(String detail) {
    super("invalid trust-anchor file: " + detail);
  }
}
