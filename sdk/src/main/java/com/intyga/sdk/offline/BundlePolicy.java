package com.intyga.sdk.offline;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;

/**
 * The approval requirement in force for one action pattern, as the gateway resolved it — one
 * {@code policy} entry of a trust bundle (mirrors gateway {@code TrustBundlePolicyEntry}).
 *
 * <p>Built only from the bundle's JSON. Whether the entry is a COMPLETE v1 policy entry is decided
 * on that JSON, where the types are still visible ({@link #complete()}); the typed accessors are a
 * best-effort projection, and nothing resolves a requirement from an incomplete entry.
 */
public final class BundlePolicy implements ApprovalPolicy.Rule {
  private final String signerClass;
  private final String actionPattern;
  private final long requiredApprovals;
  private final boolean requireHardwareKey;
  private final List<String> allowedAaguids;
  private final boolean requesterCannotApprove;
  private final boolean requireAttestedRequester;
  private final List<String> allowedIssuers;
  private final List<String> approverDids;
  private final List<String> approverGroupIds;
  private final List<String> escalationApproverDids;
  private final List<String> escalationGroupIds;
  private final Long escalateAfterSeconds;
  private final String autoApproveRequesterDid;
  private final Integer autoApproveDayOfWeek;
  private final String autoApproveWindowStart;
  private final String autoApproveWindowEnd;
  private final Long selectionRank;
  private final String selectionKey;
  private final boolean complete;

  private BundlePolicy(JsonNode p) {
    boolean object = p != null && p.isObject();
    JsonNode n = object ? p : Js.JSON.createObjectNode();
    this.signerClass = Js.text(n.get("signerClass"));
    this.actionPattern = Js.text(n.get("actionPattern"));
    // A quorum that is not a safe integer becomes 0, which every policy check refuses.
    this.requiredApprovals = Js.isSafeInteger(n.get("requiredApprovals")) ? n.get("requiredApprovals").longValue() : 0;
    this.requireHardwareKey = bool(n.get("requireHardwareKey"));
    this.allowedAaguids = Js.strings(n.get("allowedAaguids"));
    this.requesterCannotApprove = bool(n.get("requesterCannotApprove"));
    this.requireAttestedRequester = bool(n.get("requireAttestedRequester"));
    this.allowedIssuers = Js.strings(n.get("allowedIssuers"));
    this.approverDids = Js.strings(n.get("approverDids"));
    this.approverGroupIds = Js.strings(n.get("approverGroupIds"));
    this.escalationApproverDids = Js.strings(n.get("escalationApproverDids"));
    this.escalationGroupIds = Js.strings(n.get("escalationGroupIds"));
    this.escalateAfterSeconds =
        Js.isSafeInteger(n.get("escalateAfterSeconds")) ? n.get("escalateAfterSeconds").longValue() : null;
    this.autoApproveRequesterDid = Js.text(n.get("autoApproveRequesterDid"));
    this.autoApproveDayOfWeek =
        Js.isInteger(n.get("autoApproveDayOfWeek")) && validDay(n.get("autoApproveDayOfWeek"))
            ? n.get("autoApproveDayOfWeek").intValue()
            : null;
    this.autoApproveWindowStart = Js.text(n.get("autoApproveWindowStart"));
    this.autoApproveWindowEnd = Js.text(n.get("autoApproveWindowEnd"));
    this.selectionRank = Js.isSafeInteger(n.get("selectionRank")) ? n.get("selectionRank").longValue() : null;
    this.selectionKey = Js.text(n.get("selectionKey"));
    this.complete = object && validBundlePolicy(p);
  }

  /** Project one bundle {@code policy} entry. Never throws; check {@link #complete()}. */
  public static BundlePolicy fromJson(JsonNode entry) {
    return new BundlePolicy(entry);
  }

  /**
   * {@code validBundlePolicy} from the reference: every v1 field present with its exact type —
   * {@code signerClass} "human", a non-blank pattern, a safe-integer quorum ≥ 1, the three booleans,
   * the four DID/AAGUID/issuer lists of non-empty strings, and the escalation/auto-approve fields
   * present as null or a valid value. A missing field is not a default; it is an incomplete export.
   *
   * <p>Unresolved group lists are not part of a gateway export; when present they must at least be
   * string lists, so they can be compared rather than throw (stricter than the reference, which
   * would fail on a non-list there with an exception rather than a refusal).
   */
  static boolean validBundlePolicy(JsonNode p) {
    if (p == null || !p.isObject()) {
      return false;
    }
    if (!"human".equals(Js.text(p.get("signerClass")))) {
      return false;
    }
    JsonNode pattern = p.get("actionPattern");
    if (!Js.isString(pattern)
        || Js.trim(pattern.textValue()).isEmpty()
        || !Js.isSafeInteger(p.get("requiredApprovals"))
        || p.get("requiredApprovals").doubleValue() < 1) {
      return false;
    }
    for (String field : List.of("requireHardwareKey", "requesterCannotApprove", "requireAttestedRequester")) {
      JsonNode v = p.get(field);
      if (v == null || !v.isBoolean()) {
        return false;
      }
    }
    for (String field : List.of("approverDids", "allowedAaguids", "allowedIssuers", "escalationApproverDids")) {
      if (!Js.isStringArray(p.get(field), true)) {
        return false;
      }
    }
    JsonNode escalate = p.get("escalateAfterSeconds");
    if (escalate == null
        || (!escalate.isNull() && (!Js.isSafeInteger(escalate) || escalate.doubleValue() < 1))) {
      return false;
    }
    for (String field : List.of("autoApproveRequesterDid", "autoApproveWindowStart", "autoApproveWindowEnd")) {
      JsonNode v = p.get(field);
      if (v == null || (!v.isNull() && !v.isTextual())) {
        return false;
      }
    }
    for (String field : List.of("approverGroupIds", "escalationGroupIds")) {
      JsonNode v = p.get(field);
      if (v != null && !v.isNull() && !Js.isStringArray(v, false)) {
        return false;
      }
    }
    JsonNode day = p.get("autoApproveDayOfWeek");
    return day != null && (day.isNull() || (Js.isInteger(day) && validDay(day)));
  }

  private static boolean validDay(JsonNode day) {
    double d = day.doubleValue();
    return d >= 0 && d <= 6;
  }

  private static boolean bool(JsonNode n) {
    return n != null && n.isBoolean() && n.booleanValue();
  }

  /** Whether this entry is a complete v1 policy entry. An incomplete one refuses every resolution. */
  public boolean complete() {
    return complete;
  }

  /** Always {@code "human"} in a complete entry — the only signer class DIV defines (§4.3.2). */
  public String signerClass() {
    return signerClass;
  }

  @Override
  public String actionPattern() {
    return actionPattern;
  }

  @Override
  public long requiredApprovals() {
    return requiredApprovals;
  }

  @Override
  public boolean requireHardwareKey() {
    return requireHardwareKey;
  }

  @Override
  public List<String> allowedAaguids() {
    return allowedAaguids;
  }

  @Override
  public boolean requesterCannotApprove() {
    return requesterCannotApprove;
  }

  @Override
  public boolean requireAttestedRequester() {
    return requireAttestedRequester;
  }

  @Override
  public List<String> allowedIssuers() {
    return allowedIssuers;
  }

  /** Which approvers are eligible for THIS pattern — a subset of the bundle's approvers. */
  @Override
  public List<String> approverDids() {
    return approverDids;
  }

  @Override
  public List<String> approverGroupIds() {
    return approverGroupIds;
  }

  @Override
  public List<String> escalationApproverDids() {
    return escalationApproverDids;
  }

  @Override
  public List<String> escalationGroupIds() {
    return escalationGroupIds;
  }

  @Override
  public Long escalateAfterSeconds() {
    return escalateAfterSeconds;
  }

  @Override
  public String autoApproveRequesterDid() {
    return autoApproveRequesterDid;
  }

  @Override
  public Integer autoApproveDayOfWeek() {
    return autoApproveDayOfWeek;
  }

  @Override
  public String autoApproveWindowStart() {
    return autoApproveWindowStart;
  }

  @Override
  public String autoApproveWindowEnd() {
    return autoApproveWindowEnd;
  }

  /** Informational only: signed rank metadata never decides selection. Null when absent. */
  public Long selectionRank() {
    return selectionRank;
  }

  /** Informational only: signed selection key metadata. Null when absent. */
  public String selectionKey() {
    return selectionKey;
  }
}
