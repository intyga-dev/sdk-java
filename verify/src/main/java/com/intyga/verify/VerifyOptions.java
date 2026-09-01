package com.intyga.verify;

import java.time.Instant;

/**
 * Relying-party context required to verify certain receipts. The WebAuthn expectations are
 * mandatory for a WEBAUTHN receipt: without a pinned origin and RP ID, an assertion harvested at
 * any relying party would verify. Immutable; build with {@link #builder()} — {@code
 * VerifyOptions.defaults()} is the fail-closed baseline.
 */
public final class VerifyOptions {
  private final boolean allowAutoApproved;
  private final String expectedOrigin;
  private final String expectedRpId;
  private final Boolean requireUserVerification;
  private final boolean allowExpired;
  private final boolean allowOffline;
  private final VerifiedDelegation delegation;
  private final Instant asOf;
  private final Integer clockSkewSeconds;
  private final boolean allowCrossOrigin;

  private VerifyOptions(Builder b) {
    this.allowAutoApproved = b.allowAutoApproved;
    this.expectedOrigin = b.expectedOrigin;
    this.expectedRpId = b.expectedRpId;
    this.requireUserVerification = b.requireUserVerification;
    this.allowExpired = b.allowExpired;
    this.allowOffline = b.allowOffline;
    this.delegation = b.delegation;
    this.asOf = b.asOf;
    this.clockSkewSeconds = b.clockSkewSeconds;
    this.allowCrossOrigin = b.allowCrossOrigin;
  }

  public static VerifyOptions defaults() {
    return builder().build();
  }

  public static Builder builder() {
    return new Builder();
  }

  boolean allowAutoApproved() {
    return allowAutoApproved;
  }

  String expectedOrigin() {
    return expectedOrigin;
  }

  String expectedRpId() {
    return expectedRpId;
  }

  Boolean requireUserVerification() {
    return requireUserVerification;
  }

  boolean allowExpired() {
    return allowExpired;
  }

  boolean allowOffline() {
    return allowOffline;
  }

  VerifiedDelegation delegation() {
    return delegation;
  }

  Instant asOf() {
    return asOf;
  }

  Integer clockSkewSeconds() {
    return clockSkewSeconds;
  }

  boolean allowCrossOrigin() {
    return allowCrossOrigin;
  }

  public static final class Builder {
    private boolean allowAutoApproved;
    private String expectedOrigin;
    private String expectedRpId;
    private Boolean requireUserVerification;
    private boolean allowExpired;
    private boolean allowOffline;
    private VerifiedDelegation delegation;
    private Instant asOf;
    private Integer clockSkewSeconds;
    private boolean allowCrossOrigin;

    private Builder() {}

    /**
     * Opts in to attesting policy AUTO_APPROVED receipts, which carry no human signature. Off by
     * default: such receipts fail closed.
     */
    public Builder allowAutoApproved(boolean allowAutoApproved) {
      this.allowAutoApproved = allowAutoApproved;
      return this;
    }

    /** The exact origin a WebAuthn assertion must carry, e.g. "https://app.example.com". */
    public Builder expectedOrigin(String expectedOrigin) {
      this.expectedOrigin = expectedOrigin;
      return this;
    }

    /** The RP ID the authenticatorData must hash to, e.g. "app.example.com". */
    public Builder expectedRpId(String expectedRpId) {
      this.expectedRpId = expectedRpId;
      return this;
    }

    /**
     * Demands the User-Verified flag (biometric/PIN). Defaults to true; set false to accept mere
     * user presence.
     */
    public Builder requireUserVerification(boolean requireUserVerification) {
      this.requireUserVerification = requireUserVerification;
      return this;
    }

    /** Opts out of the fail-closed expiry check (DIV §5.8) for post-hoc audit re-verification. */
    public Builder allowExpired(boolean allowExpired) {
      this.allowExpired = allowExpired;
      return this;
    }

    /**
     * Opts in to accepting an OFFLINE APPROVAL (DIV §5a.3). Off by default, exactly like
     * allowAutoApproved: set it at the SPECIFIC call permitted to run under one, never globally.
     * It weakens nothing else: quorum, four-eyes and target binding are still enforced, the window
     * is capped, and a proof whose signed policy demands a hardware key is refused.
     */
    public Builder allowOffline(boolean allowOffline) {
      this.allowOffline = allowOffline;
      return this;
    }

    /**
     * A delegation ALREADY verified by {@link Verify#verifyDelegation}, substituting the eligible
     * approver set and the quorum for this one verification (DIV §5a.6). Only meaningful with
     * allowOffline. It narrows rather than widens.
     */
    public Builder delegation(VerifiedDelegation delegation) {
      this.delegation = delegation;
      return this;
    }

    /**
     * Overrides "now" for time evaluation. Null means the current instant. Also the reference point
     * for the forward-dating rule (DIV §5a.3 rule 3), which allowExpired does NOT waive: that
     * option re-examines a proof that was valid and has lapsed, never one dated in the future.
     */
    public Builder asOf(Instant asOf) {
      this.asOf = asOf;
      return this;
    }

    /** Expiry tolerance in seconds. Null means {@link Div#DEFAULT_CLOCK_SKEW_SECONDS}. */
    public Builder clockSkewSeconds(int clockSkewSeconds) {
      this.clockSkewSeconds = clockSkewSeconds;
      return this;
    }

    /**
     * Accepts an assertion produced inside a cross-origin frame. Defaults to false (refuse):
     * origin and rpIdHash both match for an embedded RP frame, so crossOrigin is the only signal
     * that the ceremony ran inside a third-party embedder.
     */
    public Builder allowCrossOrigin(boolean allowCrossOrigin) {
      this.allowCrossOrigin = allowCrossOrigin;
      return this;
    }

    public VerifyOptions build() {
      return new VerifyOptions(this);
    }
  }
}
