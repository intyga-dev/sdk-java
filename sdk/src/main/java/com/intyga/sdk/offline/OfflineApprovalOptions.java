package com.intyga.sdk.offline;

import java.nio.file.Path;
import java.time.Instant;
import java.util.function.Consumer;

/**
 * Options for {@link OfflineApproval#useOfflineApproval}, and the per-call opt-in to the client's
 * offline fallback ({@code RequireApprovalOptions.Builder.offline}). Immutable; build with {@link
 * #builder()}.
 *
 * <p>Pass them only at the specific call sites permitted to run under an offline approval. A
 * process-wide default would make every gated action in the service accept an out-of-band approval,
 * which is the difference between an emergency mechanism and a hole.
 */
public final class OfflineApprovalOptions {
  private final Path bundleDir;
  private final String requesterDid;
  private final SignatureCollector collectSignatures;
  private final Path delegationDir;
  private final RedemptionStore store;
  private final Path bufferDir;
  private final Integer windowMinutes;
  private final Consumer<String> warn;
  private final Instant asOf;

  private OfflineApprovalOptions(Builder b) {
    if (b.bundleDir == null) {
      throw new IllegalArgumentException("offline approval requires bundleDir (see TrustBundle.save)");
    }
    if (b.requesterDid == null || b.requesterDid.trim().isEmpty()) {
      throw new IllegalArgumentException("offline approval requires requesterDid — this workload's own identity");
    }
    if (b.collectSignatures == null) {
      throw new IllegalArgumentException("offline approval requires a signature collector");
    }
    this.bundleDir = b.bundleDir;
    this.requesterDid = b.requesterDid;
    this.collectSignatures = b.collectSignatures;
    this.delegationDir = b.delegationDir;
    this.store = b.store;
    this.bufferDir = b.bufferDir;
    this.windowMinutes = b.windowMinutes;
    this.warn = b.warn;
    this.asOf = b.asOf;
  }

  public static Builder builder() {
    return new Builder();
  }

  public Path bundleDir() {
    return bundleDir;
  }

  public String requesterDid() {
    return requesterDid;
  }

  public SignatureCollector collectSignatures() {
    return collectSignatures;
  }

  /** Null when no delegation directory is configured. */
  public Path delegationDir() {
    return delegationDir;
  }

  /** Null means {@code new FileRedemptionStore(bundleDir.resolve(".redeemed"))}. */
  public RedemptionStore store() {
    return store;
  }

  /** Null means {@code bundleDir.resolve(".pending")}. */
  public Path bufferDir() {
    return bufferDir;
  }

  public Integer windowMinutes() {
    return windowMinutes;
  }

  /** Null means standard error — an offline approval must never be quiet. */
  public Consumer<String> warn() {
    return warn;
  }

  public Instant asOf() {
    return asOf;
  }

  public static final class Builder {
    private Path bundleDir;
    private String requesterDid;
    private SignatureCollector collectSignatures;
    private Path delegationDir;
    private RedemptionStore store;
    private Path bufferDir;
    private Integer windowMinutes;
    private Consumer<String> warn;
    private Instant asOf;

    private Builder() {}

    /** Directory holding {@code trust-bundle.jws} and {@code gateway-key.jwk.json}. Required. */
    public Builder bundleDir(Path bundleDir) {
      this.bundleDir = bundleDir;
      return this;
    }

    /** This workload's own identity, bound into the signed bytes so approvers see who is asking. Required. */
    public Builder requesterDid(String requesterDid) {
      this.requesterDid = requesterDid;
      return this;
    }

    /** Gets the challenge to the approvers and returns their {@code SIG1:} envelopes. Required. */
    public Builder collectSignatures(SignatureCollector collectSignatures) {
      this.collectSignatures = collectSignatures;
      return this;
    }

    /** Directory of pre-sealed delegation receipts ({@code *.json}), for when approvers are unreachable too. */
    public Builder delegationDir(Path delegationDir) {
      this.delegationDir = delegationDir;
      return this;
    }

    /** Where redeemed nonces are recorded. Defaults to {@code <bundleDir>/.redeemed}. */
    public Builder store(RedemptionStore store) {
      this.store = store;
      return this;
    }

    /** Where approvals are buffered for reconciliation. Defaults to {@code <bundleDir>/.pending}. */
    public Builder bufferDir(Path bufferDir) {
      this.bufferDir = bufferDir;
      return this;
    }

    /** Validity window in minutes; default 15, clamped to [1, 60]. */
    public Builder windowMinutes(Integer windowMinutes) {
      this.windowMinutes = windowMinutes;
      return this;
    }

    /** Overrides the warning sink (default: standard error). */
    public Builder warn(Consumer<String> warn) {
      this.warn = warn;
      return this;
    }

    /** Overrides "now", for tests and deterministic replay. */
    public Builder asOf(Instant asOf) {
      this.asOf = asOf;
      return this;
    }

    public OfflineApprovalOptions build() {
      return new OfflineApprovalOptions(this);
    }
  }
}
