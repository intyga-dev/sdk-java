package com.intyga.verify;

/** Caller-owned expectations for a sealed agent authority. */
public record AgentAuthorityExpected(ApproverTrustAnchor approvers, String target, String agentDid) {}
