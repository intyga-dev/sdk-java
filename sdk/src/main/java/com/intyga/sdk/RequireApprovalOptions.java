package com.intyga.sdk;

import com.intyga.sdk.offline.OfflineApprovalOptions;
import java.time.Duration;

/** {@link AuthorizeOptions} plus polling controls for {@link IntygaClient#requireApproval}. */
public final class RequireApprovalOptions {
  private final AuthorizeOptions authorize;
  private final Duration timeout;
  private final Duration interval;
  private final OfflineApprovalOptions offline;

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
    this.offline = b.offline;
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

  /** The per-call offline-approval opt-in, or null (the default): no fallback, ever. */
  public OfflineApprovalOptions offline() {
    return offline;
  }

  public static final class Builder {
    private AuthorizeOptions authorize;
    private Duration timeout;
    private Duration interval;
    private OfflineApprovalOptions offline;

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

    /**
     * Opt in to the OFFLINE APPROVAL fallback for THIS call (DIV §5a). Omitted means no fallback,
     * ever. Pass it only at the specific call sites permitted to run under an offline approval: a
     * process-wide default would make every gated action accept an out-of-band approval.
     *
     * <p>The fallback runs only when the gateway could not be ASKED — a connection failure, a
     * timeout, a 5xx, or repeated polling failures. A 4xx, DENIED or EXPIRED is a verdict and is
     * never routed offline, and an agent-continuity request never falls back. A completed fallback
     * returns {@link ApprovalStatus#OFFLINE_APPROVED}, never {@code APPROVED}.
     */
    public Builder offline(OfflineApprovalOptions offline) {
      this.offline = offline;
      return this;
    }

    public RequireApprovalOptions build() {
      return new RequireApprovalOptions(this);
    }
  }
}
