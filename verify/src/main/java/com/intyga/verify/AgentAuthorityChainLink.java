package com.intyga.verify;

/** One human-sealed authority receipt and its caller-owned verification expectations. */
public record AgentAuthorityChainLink(ApprovalReceipt receipt, AgentAuthorityExpected expected) {}
