package com.intyga.verify;

/** Result of verifying a DIV §5b authority seal. */
public record AgentAuthorityVerification(boolean ok, String reason, VerifiedAgentAuthority authority) {
  static AgentAuthorityVerification refuse(String reason) {
    return new AgentAuthorityVerification(false, reason, null);
  }
}
