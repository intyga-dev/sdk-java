package com.intyga.sdk;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.intyga.verify.ApprovalReceipt;
import com.intyga.verify.ApproverTrustAnchor;
import com.intyga.verify.Canonical;
import com.intyga.verify.Expected;
import com.intyga.verify.RequirementFloor;
import com.intyga.verify.Verify;
import com.intyga.verify.VerifyOptions;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.function.BiConsumer;

/**
 * A framework-neutral, blocking tool guard: snapshot arguments, request human approval, verify the
 * receipt locally, consume it successfully, then execute. Caller-provisioned approver trust is
 * mandatory. There is no unverified, auto-approved or offline execution path.
 */
public final class ApprovalGuard {
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final TypeReference<Map<String, Object>> ARGUMENTS = new TypeReference<>() {};

  /** Execute using only these detached, approved JSON arguments, not the caller's mutable inputs. */
  @FunctionalInterface
  public interface Tool<R> {
    R call(Map<String, Object> arguments) throws Exception;
  }

  private final IntygaClient client;
  private final String target;
  private final String actionType;
  private final String description;
  private final ApproverTrustAnchor approvers;
  private final RequirementFloor requirement;
  private final String tenantId;
  private final VerifyOptions verifyOptions;
  private final Duration timeout;
  private final Duration interval;
  private final int reportDispatch;
  private final BiConsumer<String, Throwable> onDispatchError;

  private ApprovalGuard(Builder b) {
    client = Objects.requireNonNull(b.client, "client");
    approvers = Objects.requireNonNull(b.approvers, "caller-provisioned approvers");
    if (b.target == null || b.target.isBlank() || b.actionType == null || b.actionType.isBlank()) {
      throw new IllegalArgumentException("ApprovalGuard requires target and actionType");
    }
    if (b.reportDispatch != 0 && (b.reportDispatch < 10 || b.reportDispatch > 86400)) {
      throw new IllegalArgumentException("reportDispatch must be zero or 10..86400 seconds");
    }
    target = b.target;
    actionType = b.actionType;
    description = b.description == null ? "Execute " + actionType : b.description;
    requirement = b.requirement;
    tenantId = b.tenantId;
    verifyOptions = VerifyOptions.builder().expectedOrigin(b.expectedOrigin)
        .expectedRpId(b.expectedRpId).build();
    timeout = b.timeout;
    interval = b.interval;
    reportDispatch = b.reportDispatch;
    onDispatchError = b.onDispatchError;
  }

  public static Builder builder(IntygaClient client, ApproverTrustAnchor approvers) {
    return new Builder(client, approvers);
  }

  /** Wrap once, then register the returned callback with your tool framework. */
  public <R> Tool<R> wrap(Tool<R> tool) {
    Objects.requireNonNull(tool, "tool");
    return arguments -> {
      Objects.requireNonNull(arguments, "tool arguments must be a JSON object");
      final Map<String, Object> bound;
      try {
        // Canonicalization rejects non-JSON values before Jackson can coerce them.
        bound = JSON.readValue(Canonical.stableStringify(arguments), ARGUMENTS);
      } catch (JsonProcessingException e) {
        throw new IntygaException("Invalid tool arguments", e);
      }
      ApprovalResult approval = client.requireApproval(description, RequireApprovalOptions.builder()
          .authorize(AuthorizeOptions.builder().target(target).actionType(actionType).params(bound).build())
          .timeout(timeout).interval(interval).build());
      if (approval.status() != ApprovalStatus.APPROVED) {
        throw new ApprovalRefusedException(approval.status(), "The tool action was not approved");
      }
      if (approval.receipt() == null || approval.nonce() == null || approval.nonce().isEmpty()) {
        throw new IntygaException("Tool approval has no receipt or nonce");
      }
      var checked = Verify.verifyApprovalReceipt(ApprovalReceipt.parse(approval.receipt()),
          new Expected(target, approval.nonce(), actionType, bound, approvers)
              .withRequirement(requirement).withTenantId(tenantId),
          verifyOptions);
      if (!checked.ok()) {
        throw new IntygaException("Tool approval unverified: " + checked.reason());
      }
      ConsumeResult consumed = client.consume(approval.nonce(), target, actionType, bound);
      if (!consumed.ok()) {
        throw new IntygaException("Tool approval not consumed: " + consumed.reason());
      }
      if (Thread.currentThread().isInterrupted()) {
        throw new InterruptedException("Interrupted before tool execution");
      }
      try {
        return tool.call(bound);
      } finally {
        reportBestEffort(approval.nonce());
      }
    };
  }

  private void reportBestEffort(String nonce) {
    if (reportDispatch == 0) return;
    try {
      var reply = client.reportDispatched(nonce, reportDispatch);
      if (reply == null || !reply.path("ok").isBoolean() || !reply.path("ok").asBoolean()) {
        throw new IntygaException("Dispatch report was not acknowledged");
      }
    } catch (Throwable error) {
      // The action already ran. Even a diagnostic failure must not change its result or mask
      // its original exception, which could cause the caller to retry a completed action.
      try {
        if (onDispatchError != null) onDispatchError.accept(nonce, error);
        else System.getLogger(ApprovalGuard.class.getName()).log(System.Logger.Level.WARNING,
            "INTYGA: dispatch reporting failed; retry reportDispatched for the consumed approval");
      } catch (Throwable ignored) {
        // Diagnostic only; never a replacement for the action's outcome.
      }
    }
  }

  public static final class Builder {
    private final IntygaClient client;
    private final ApproverTrustAnchor approvers;
    private String target;
    private String actionType;
    private String description;
    private RequirementFloor requirement;
    private String tenantId;
    private String expectedOrigin;
    private String expectedRpId;
    private Duration timeout;
    private Duration interval;
    private int reportDispatch;
    private BiConsumer<String, Throwable> onDispatchError;

    private Builder(IntygaClient client, ApproverTrustAnchor approvers) {
      this.client = client;
      this.approvers = approvers;
    }

    public Builder target(String value) { target = value; return this; }
    public Builder actionType(String value) { actionType = value; return this; }
    public Builder description(String value) { description = value; return this; }
    /** Recommended: the minimum quorum and restrictions required by your deployment. */
    public Builder requirement(RequirementFloor value) { requirement = value; return this; }
    /**
     * The independently trusted tenant expected on DIV v2 receipts: supply it from your trust anchor
     * or other independently trusted configuration; it is never inferred from the gateway response or
     * the receipt. Null keeps v1-only verification, which refuses every v2 receipt the hosted gateway
     * issues.
     */
    public Builder tenantId(String value) { tenantId = value; return this; }
    public Builder expectedOrigin(String value) { expectedOrigin = value; return this; }
    public Builder expectedRpId(String value) { expectedRpId = value; return this; }
    public Builder timeout(Duration value) { timeout = value; return this; }
    public Builder interval(Duration value) { interval = value; return this; }
    /** Evidence window in seconds (10..86400); zero, the default, disables reporting. */
    public Builder reportDispatch(int seconds) { reportDispatch = seconds; return this; }
    /** A failed post-execution report: retain its nonce to retry without running the tool again. */
    public Builder onDispatchError(BiConsumer<String, Throwable> handler) { onDispatchError = handler; return this; }
    public ApprovalGuard build() { return new ApprovalGuard(this); }
  }
}
