package com.intyga.verify;

/** DIV protocol constants (docs/DIV.md v1). */
public final class Div {
  public static final int VERSION = 1;
  public static final String INTENT_TYPE = "div-intent-verification";

  /**
   * Marks an OFFLINE APPROVAL (DIV §5a.2): a normal quorum approval collected OUT OF BAND at
   * incident time because the gateway is unreachable. The distinct type lives INSIDE the signed
   * bytes, so an offline proof can never verify as a normal approval, or the reverse.
   */
  public static final String OFFLINE_INTENT_TYPE = "div-offline-intent";

  /**
   * Marks a DELEGATION (DIV §5a.5): a pre-signed statement transferring the AUTHORITY TO APPROVE
   * one pre-declared action to named local operators. It authorizes NOTHING on its own —
   * {@link Verify#verifyApprovalReceipt} refuses this type outright, with no opt-in.
   */
  public static final String DELEGATION_TYPE = "div-delegation";

  /** Standing, quorum-sealed agent scope. It is governance evidence, never an approval. */
  public static final String AGENT_AUTHORITY_TYPE = "div-agent-authority";

  /** Platform subject hash-only WebAuthn intent (DIV §5c). */
  public static final String PLATFORM_INTENT_TYPE = "div-platform-intent";

  /** RECOMMENDED expiry tolerance (DIV §6.2). */
  public static final int DEFAULT_CLOCK_SKEW_SECONDS = 30;

  /**
   * Caps an offline proof's validity window, enforced at verification and not only at mint. An
   * offline relying party has no revocation channel, so the short window is the only bound there is
   * (DIV §5a.3).
   */
  public static final int MAX_OFFLINE_WINDOW_MINUTES = 60;

  /** Caps a delegation's window (DIV §5a.6). Hours, not weeks. */
  public static final int MAX_DELEGATION_WINDOW_HOURS = 72;

  /**
   * Caps the witness list either verifier will process. A DIV quorum is single digits — this is a
   * denial-of-service bound, not a policy limit, because verification runs in the relying party's
   * own process on an attacker-supplied receipt immediately before an irreversible action.
   */
  public static final int MAX_WITNESSES = 64;

  static final int MAX_REPORTED_FAILURES = 8;

  private Div() {}
}
