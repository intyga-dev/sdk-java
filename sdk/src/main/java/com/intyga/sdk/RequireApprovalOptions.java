package com.intyga.sdk;

import java.time.Duration;

/** {@link AuthorizeOptions} plus polling controls for {@link IntygaClient#requireApproval}. */
public final class RequireApprovalOptions {
  private final AuthorizeOptions authorize;
  private final Duration timeout;
  private final Duration interval;

  private RequireApprovalOptions(Builder b) {
    if (b.authorize == null) {
      throw new IllegalArgumentException("RequireApprovalOptions requires authorize options (with a target)");
    }
    this.authorize = b.authorize;
    this.timeout = b.timeout == null || b.timeout.isZero() || b.timeout.isNegative()
        ? Duration.ofSeconds(120)
        : b.timeout;
    this.interval = b.interval == null || b.interval.isZero() || b.interval.isNegative()
        ? Duration.ofSeconds(2)
        : b.interval;
  }

  public static Builder builder() {
    return new Builder();
  }

  public AuthorizeOptions authorize() {
    return authorize;
  }

  /**
   * Total wait window. Defaults to 120s. Also sent to the gateway as the challenge TTL (ceiled to
   * whole seconds) so the challenge cannot outlive the wait.
   */
  public Duration timeout() {
    return timeout;
  }

  /** Poll interval. Defaults to 2s. */
  public Duration interval() {
    return interval;
  }

  public static final class Builder {
    private AuthorizeOptions authorize;
    private Duration timeout;
    private Duration interval;

    private Builder() {}

    public Builder authorize(AuthorizeOptions authorize) {
      this.authorize = authorize;
      return this;
    }

    public Builder timeout(Duration timeout) {
      this.timeout = timeout;
      return this;
    }

    public Builder interval(Duration interval) {
      this.interval = interval;
      return this;
    }

    public RequireApprovalOptions build() {
      return new RequireApprovalOptions(this);
    }
  }
}
