package com.intyga.sdk;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** Structured, WYSIWYS-bound details of an approval request. Immutable; build with {@link #builder()}. */
public final class AuthorizeOptions {
  private final String target;
  private final String actionType;
  private final Map<String, Object> params;
  private final Map<String, Object> agentContext;
  private final int timeoutSeconds;

  private AuthorizeOptions(Builder b) {
    this.target = b.target;
    this.actionType = b.actionType;
    // Not Map.copyOf: params may carry JSON nulls, and insertion order should survive to the
    // approver's screen.
    this.params = Collections.unmodifiableMap(new LinkedHashMap<>(b.params));
    this.agentContext = b.agentContext == null ? null : Collections.unmodifiableMap(new LinkedHashMap<>(b.agentContext));
    this.timeoutSeconds = b.timeoutSeconds;
  }

  public static Builder builder() {
    return new Builder();
  }

  /**
   * A pre-populated builder — THE way to derive a variant of existing options.
   * {@link IntygaClient#requireApproval} forwards the caller's options wholesale through this and
   * overrides only the timeout: rebuilding options field-by-field silently drops anything added to
   * this class later, which is how {@code target} would have gone missing there even after being
   * made required.
   */
  public Builder toBuilder() {
    Builder b = new Builder();
    b.target = target;
    b.actionType = actionType;
    b.params = new LinkedHashMap<>(params);
    b.agentContext = agentContext == null ? null : new LinkedHashMap<>(agentContext);
    b.timeoutSeconds = timeoutSeconds;
    return b;
  }

  /**
   * The relying party / execution environment this approval is bound to (DIV &#167;3 Invariant 5,
   * Target Isolation). REQUIRED, and asserted from YOUR own identity.
   *
   * <p>Leaving it empty is not neutral: the gateway defaults a missing target to the literal
   * "global", so the signed intent binds no environment and an approval minted for this service
   * verifies at every other relying party that also asserts "global". That is exactly the
   * cross-service replay Target Isolation exists to prevent, which is why the client rejects it
   * rather than quietly defaulting.
   */
  public String target() {
    return target;
  }

  /** The action identifier, e.g. "wire_transfer". Bound into the signed payload. */
  public String actionType() {
    return actionType;
  }

  /** The exact structured variables that will execute — displayed to the approver AND signed. Never null. */
  public Map<String, Object> params() {
    return params;
  }

  public Map<String, Object> agentContext() { return agentContext; }

  /** Optional override of the server's default challenge TTL; 0 means unset (not sent). */
  public int timeoutSeconds() {
    return timeoutSeconds;
  }

  public static final class Builder {
    private String target;
    private String actionType;
    private Map<String, Object> params = new LinkedHashMap<>();
    private Map<String, Object> agentContext;
    private int timeoutSeconds;

    private Builder() {}

    public Builder target(String target) {
      this.target = target;
      return this;
    }

    public Builder actionType(String actionType) {
      this.actionType = actionType;
      return this;
    }

    public Builder params(Map<String, Object> params) {
      this.params = params == null ? new LinkedHashMap<>() : new LinkedHashMap<>(params);
      return this;
    }

    public Builder agentContext(Map<String, Object> context) {
      this.agentContext = context == null ? null : new LinkedHashMap<>(context);
      return this;
    }

    public Builder timeoutSeconds(int timeoutSeconds) {
      this.timeoutSeconds = timeoutSeconds;
      return this;
    }

    public AuthorizeOptions build() {
      return new AuthorizeOptions(this);
    }
  }
}
