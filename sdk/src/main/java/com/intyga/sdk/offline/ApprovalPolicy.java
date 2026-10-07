package com.intyga.sdk.offline;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Exact-ID (version 3) approval-rule selection — a faithful port of the version-3 path of
 * {@code packages/verify/src/approval-policy.ts}: {@code validApprovalActionId},
 * {@code validateExactApprovalPolicy}, {@code lostApprovalConstraints} and
 * {@code selectApprovalRule(..., 3, ...)}. Pure: no crypto, file or network access.
 *
 * <p>Display text never selects a rule, and a conflict refuses rather than picking one. Only the
 * exact-ID algorithm is ported: the legacy substring ranking (versions 1 and 2) is not used by any
 * offline path.
 */
public final class ApprovalPolicy {

  /** The rule fields policy resolution reads. Optional list fields are empty, never null. */
  public interface Rule {
    /** Exact action ID, or {@code *} for the tenant baseline. */
    String actionPattern();

    long requiredApprovals();

    List<String> approverDids();

    boolean requireHardwareKey();

    List<String> allowedAaguids();

    boolean requesterCannotApprove();

    boolean requireAttestedRequester();

    List<String> allowedIssuers();

    /** Unresolved approver groups; always empty in a gateway-exported bundle (groups are expanded). */
    List<String> approverGroupIds();

    List<String> escalationApproverDids();

    List<String> escalationGroupIds();

    /** Null when the rule does not escalate. */
    Long escalateAfterSeconds();

    String autoApproveRequesterDid();

    Integer autoApproveDayOfWeek();

    String autoApproveWindowStart();

    String autoApproveWindowEnd();
  }

  private static final Pattern ACTION_ID =
      Pattern.compile("[A-Za-z][A-Za-z0-9]*(?:[._:/-][A-Za-z0-9]+)*");
  private static final long MAX_SAFE_INTEGER = 9007199254740991L;

  private ApprovalPolicy() {}

  /** Version 3 action IDs: a fixed grammar, at most 200 UTF-16 code units. */
  public static boolean validApprovalActionId(String value) {
    return value != null && value.length() <= 200 && ACTION_ID.matcher(value).matches();
  }

  /**
   * Validate the whole v3 policy, so a corrupt or duplicate rule cannot be hidden by another
   * action: every ID valid and unique case-insensitively, every quorum an integer ≥ 1, a {@code *}
   * baseline whenever there are rules, and no rule dropping a constraint the baseline imposes.
   *
   * @throws ApprovalPolicyConflict naming what conflicts
   */
  public static void validateExactApprovalPolicy(List<? extends Rule> rules) {
    Set<String> seen = new HashSet<>();
    for (Rule rule : rules) {
      String pattern = rule.actionPattern();
      if (pattern == null
          || (!pattern.equals("*") && !validApprovalActionId(pattern))
          || rule.requiredApprovals() < 1
          || rule.requiredApprovals() > MAX_SAFE_INTEGER
          || seen.contains(pattern.toLowerCase(Locale.ROOT))) {
        throw new ApprovalPolicyConflict(List.of("invalidOrDuplicateActionId"));
      }
      seen.add(pattern.toLowerCase(Locale.ROOT));
    }
    if (!rules.isEmpty() && !seen.contains("*")) {
      throw new ApprovalPolicyConflict(List.of("missingBaseline"));
    }
    Rule baseline = null;
    for (Rule rule : rules) {
      if ("*".equals(rule.actionPattern())) {
        baseline = rule;
        break;
      }
    }
    if (baseline == null) {
      return;
    }
    for (Rule rule : rules) {
      List<String> fields = lostApprovalConstraints(rule, baseline);
      if (!fields.isEmpty()) {
        throw new ApprovalPolicyConflict(fields);
      }
    }
  }

  /**
   * The constraints {@code other} imposes that {@code selected} would drop, in the reference's
   * order. Empty eligible lists denote the same owner fallback, NOT unrestricted eligibility.
   */
  public static List<String> lostApprovalConstraints(Rule selected, Rule other) {
    List<String> lost = new ArrayList<>();
    if (selected.requiredApprovals() < other.requiredApprovals()) {
      lost.add("requiredApprovals");
    }
    if (other.requireHardwareKey() && !selected.requireHardwareKey()) {
      lost.add("requireHardwareKey");
    }
    if (other.requesterCannotApprove() && !selected.requesterCannotApprove()) {
      lost.add("requesterCannotApprove");
    }
    if (other.requireAttestedRequester() && !selected.requireAttestedRequester()) {
      lost.add("requireAttestedRequester");
    }
    if (narrowsAllowlist(selected.allowedAaguids(), other.allowedAaguids())) {
      lost.add("allowedAaguids");
    }
    if (narrowsAllowlist(selected.allowedIssuers(), other.allowedIssuers())) {
      lost.add("allowedIssuers");
    }
    // Different unresolved groups cannot be compared safely. DB callers expand them first.
    if (!sameSet(selected.approverGroupIds(), other.approverGroupIds())) {
      lost.add("approverGroups");
    }
    List<String> a = selected.approverDids();
    List<String> b = other.approverDids();
    if (a.isEmpty() != b.isEmpty() || !subset(a, b)) {
      lost.add("approverDids");
    }
    // Escalation widens eligibility with time. Conservatively require the same schedule and set.
    if (!Objects.equals(selected.escalateAfterSeconds(), other.escalateAfterSeconds())
        || !sameSet(selected.escalationApproverDids(), other.escalationApproverDids())
        || !sameSet(selected.escalationGroupIds(), other.escalationGroupIds())) {
      lost.add("escalation");
    }
    if (truthy(selected.autoApproveRequesterDid()) || truthy(other.autoApproveRequesterDid())) {
      if (!sameWindow(selected, other)
          || selected.requiredApprovals() != other.requiredApprovals()
          || selected.requireHardwareKey() != other.requireHardwareKey()
          || selected.requesterCannotApprove() != other.requesterCannotApprove()
          || selected.requireAttestedRequester() != other.requireAttestedRequester()
          || !sameSet(a, b)
          || !sameSet(selected.allowedAaguids(), other.allowedAaguids())
          || !sameSet(selected.allowedIssuers(), other.allowedIssuers())) {
        lost.add("autoApproval");
      }
    }
    return lost;
  }

  /**
   * {@code selectApprovalRule(rules, actionType, display, 3, unmatched)}: the rule for exactly
   * {@code actionType}, else the {@code *} baseline under {@code BASELINE}, else empty. Display
   * text is deliberately not a parameter — it never selects.
   *
   * @param unmatched {@code DENY} or {@code BASELINE}; {@code OWNER_APPROVAL} is a conflict here
   * @throws ApprovalPolicyConflict when the policy is invalid, the fallback is OWNER_APPROVAL, or
   *     {@code actionType} is a differently cased spelling of a configured ID
   */
  public static <T extends Rule> Optional<T> selectExactApprovalRule(
      List<T> rules, String actionType, String unmatched) {
    validateExactApprovalPolicy(rules);
    if ("OWNER_APPROVAL".equals(unmatched)) {
      throw new ApprovalPolicyConflict(List.of("invalidFallback"));
    }
    if (actionType == null || actionType.isEmpty() || !validApprovalActionId(actionType)) {
      return Optional.empty();
    }
    // IDs stay case-sensitive on the wire, but a differently cased spelling of a protected ID must
    // not drop to a weaker baseline. The caller must use the configured spelling.
    for (T r : rules) {
      String p = r.actionPattern();
      if (!p.equals("*")
          && !p.equals(actionType)
          && p.toLowerCase(Locale.ROOT).equals(actionType.toLowerCase(Locale.ROOT))) {
        throw new ApprovalPolicyConflict(List.of("actionIdCaseMismatch"));
      }
    }
    for (T r : rules) {
      if (r.actionPattern().equals(actionType)) {
        return Optional.of(r);
      }
    }
    if ("BASELINE".equals(unmatched)) {
      for (T r : rules) {
        if (r.actionPattern().equals("*")) {
          return Optional.of(r);
        }
      }
    }
    return Optional.empty();
  }

  /** {@code b.length && (!a.length || !subset(a, b))}: a non-empty allowlist must not be widened. */
  private static boolean narrowsAllowlist(List<String> selected, List<String> other) {
    return !other.isEmpty() && (selected.isEmpty() || !subset(selected, other));
  }

  private static boolean subset(List<String> a, List<String> b) {
    return b.containsAll(a);
  }

  private static boolean sameSet(List<String> a, List<String> b) {
    return subset(a, b) && subset(b, a);
  }

  /** JavaScript truthiness of an optional string: non-null and non-empty. */
  private static boolean truthy(String s) {
    return s != null && !s.isEmpty();
  }

  private static boolean sameWindow(Rule a, Rule b) {
    return Objects.equals(a.autoApproveRequesterDid(), b.autoApproveRequesterDid())
        && Objects.equals(a.autoApproveDayOfWeek(), b.autoApproveDayOfWeek())
        && Objects.equals(a.autoApproveWindowStart(), b.autoApproveWindowStart())
        && Objects.equals(a.autoApproveWindowEnd(), b.autoApproveWindowEnd());
  }
}
