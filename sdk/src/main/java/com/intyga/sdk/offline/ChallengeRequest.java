package com.intyga.sdk.offline;

import com.intyga.verify.RequesterIdentity;
import com.intyga.verify.VerifiedDelegation;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Input to {@link OfflineApproval#createOfflineChallenge}. Immutable; build with {@link #builder()}.
 *
 * <p>The approval REQUIREMENT is deliberately not an input: it is read from the trust bundle. A
 * relying party that supplied its own would be choosing the quorum its own action must clear (DIV
 * §5a.3).
 */
public final class ChallengeRequest {
  private final TrustBundle bundle;
  private final String target;
  private final String actionType;
  private final String display;
  private final Map<String, Object> params;
  private final RequesterIdentity requester;
  private final Integer windowMinutes;
  private final Instant asOf;
  private final String nonce;
  private final VerifiedDelegation delegation;

  private ChallengeRequest(Builder b) {
    if (b.bundle == null) {
      throw new IllegalArgumentException("a challenge requires the trust bundle its requirement comes from");
    }
    if (b.requester == null) {
      throw new IllegalArgumentException("a challenge requires the requester identity");
    }
    this.bundle = b.bundle;
    this.target = b.target;
    this.actionType = b.actionType;
    this.display = b.display;
    // Not Map.copyOf: params may carry JSON nulls, and their order should survive to the approver.
    this.params = Collections.unmodifiableMap(new LinkedHashMap<>(b.params));
    this.requester = b.requester;
    this.windowMinutes = b.windowMinutes;
    this.asOf = b.asOf;
    this.nonce = b.nonce;
    this.delegation = b.delegation;
  }

  public static Builder builder() {
    return new Builder();
  }

  public TrustBundle bundle() {
    return bundle;
  }

  public String target() {
    return target;
  }

  public String actionType() {
    return actionType;
  }

  public String display() {
    return display;
  }

  public Map<String, Object> params() {
    return params;
  }

  public RequesterIdentity requester() {
    return requester;
  }

  /** Null means the default, {@value OfflineApproval#DEFAULT_WINDOW_MINUTES} minutes. */
  public Integer windowMinutes() {
    return windowMinutes;
  }

  public Instant asOf() {
    return asOf;
  }

  public String nonce() {
    return nonce;
  }

  public VerifiedDelegation delegation() {
    return delegation;
  }

  public static final class Builder {
    private TrustBundle bundle;
    private String target;
    private String actionType;
    private String display;
    private Map<String, Object> params = new LinkedHashMap<>();
    private RequesterIdentity requester;
    private Integer windowMinutes;
    private Instant asOf;
    private String nonce;
    private VerifiedDelegation delegation;

    private Builder() {}

    /** The verified trust bundle the requirement is read from. Required. */
    public Builder bundle(TrustBundle bundle) {
      this.bundle = bundle;
      return this;
    }

    /** This relying party / execution environment (DIV Target Isolation). Required, non-blank. */
    public Builder target(String target) {
      this.target = target;
      return this;
    }

    /** The exact action ID the bundle's policy is keyed on. */
    public Builder actionType(String actionType) {
      this.actionType = actionType;
      return this;
    }

    /** What the approvers see. Signed; never selects a rule. */
    public Builder display(String display) {
      this.display = display;
      return this;
    }

    /** The exact structured variables that will execute. Signed. */
    public Builder params(Map<String, Object> params) {
      this.params = params == null ? new LinkedHashMap<>() : params;
      return this;
    }

    /** This workload's identity, bound into the signed bytes so approvers see who is asking. Required. */
    public Builder requester(RequesterIdentity requester) {
      this.requester = requester;
      return this;
    }

    /** Validity window; clamped to [1, 60]. */
    public Builder windowMinutes(Integer windowMinutes) {
      this.windowMinutes = windowMinutes;
      return this;
    }

    /** Overrides "now". For tests and deterministic replay. */
    public Builder asOf(Instant asOf) {
      this.asOf = asOf;
      return this;
    }

    /**
     * Overrides the generated nonce, for conformance vectors and deterministic replay. Production
     * callers omit it. A supplied nonce is still this relying party's own (DIV §5a.2), is still
     * single-use through the {@link RedemptionStore}, and must be a safe path segment.
     */
    public Builder nonce(String nonce) {
      this.nonce = nonce;
      return this;
    }

    /**
     * A delegation already verified by {@code Verify.verifyDelegation}, for when the ordinary
     * approvers are unreachable too: its {@code delegatedQuorum} becomes the signed quorum and
     * {@code delegatedTo} the eligible set (DIV §5a.6). It may narrow who approves, never lower how
     * many.
     */
    public Builder delegation(VerifiedDelegation delegation) {
      this.delegation = delegation;
      return this;
    }

    public ChallengeRequest build() {
      return new ChallengeRequest(this);
    }
  }
}
