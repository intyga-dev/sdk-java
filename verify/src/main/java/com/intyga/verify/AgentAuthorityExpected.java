package com.intyga.verify;

/**
 * Caller-owned expectations for a sealed agent authority.
 *
 * <p>{@code requirement} is STRONGLY RECOMMENDED: YOUR sealing policy for agent authority (DIV §5b.3,
 * §5 step 3d). Null enforces only the sealers' own stated quorum. See {@link RequirementFloor}.
 */
public record AgentAuthorityExpected(
    ApproverTrustAnchor approvers, String target, String agentDid, RequirementFloor requirement) {
  public AgentAuthorityExpected(ApproverTrustAnchor approvers, String target, String agentDid) {
    this(approvers, target, agentDid, null);
  }
}
