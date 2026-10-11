package com.intyga.verify;

/** Independently asserted action whose agent-authority chain is being checked. */
public record AgentDelegatedAction(
    String tenantId, String target, String actionType, String agentDid, String delegatedBy) {}
