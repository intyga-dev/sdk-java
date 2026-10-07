package com.intyga.sdk.offline;

/**
 * What a trust-anchor file is FOR, and so which keys it may pin. {@link #ONLINE} pins passkeys and
 * node keys and verifies ordinary approval receipts; {@link #OFFLINE} pins offline signing keys
 * only and verifies DIV §5a offline approvals. Two files, never one: a bare offline key — no origin
 * binding, no user verification — must not satisfy a relying party that verifies online approvals.
 */
public enum TrustAnchorPurpose {
  /** {@code "online"} — also how a file with no {@code purpose} field is read. */
  ONLINE("online"),
  /** {@code "offline"}. */
  OFFLINE("offline");

  private final String wire;

  TrustAnchorPurpose(String wire) {
    this.wire = wire;
  }

  /** The value as it appears in the file. */
  public String wire() {
    return wire;
  }
}
