package com.intyga.sdk.offline;

import java.util.List;

/**
 * The approval policy cannot be resolved unambiguously: a rule is malformed or duplicated, the
 * baseline is missing, a rule would drop a constraint the baseline imposes, or an action ID was
 * spelled with different case. Mirrors {@code ApprovalPolicyConflict} in
 * {@code packages/verify/src/approval-policy.ts}; {@link #fields()} carries the same names.
 */
public final class ApprovalPolicyConflict extends RuntimeException {
  private final List<String> fields;

  public ApprovalPolicyConflict(List<String> fields) {
    super("Conflicting approval requirements: " + String.join(", ", fields));
    this.fields = List.copyOf(fields);
  }

  /** What conflicts, e.g. {@code invalidOrDuplicateActionId}, {@code missingBaseline}, {@code requiredApprovals}. */
  public List<String> fields() {
    return fields;
  }
}
