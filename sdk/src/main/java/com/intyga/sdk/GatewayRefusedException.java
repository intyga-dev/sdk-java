package com.intyga.sdk;

/**
 * The gateway answered, and the answer was a refusal (any non-2xx status).
 *
 * <p>Distinct from {@link GatewayUnreachableException} on purpose, and the split is load-bearing:
 * DIV &#167;5a's offline path exists only for "could not ask". A policy refusal handled as an outage
 * is a policy bypass.
 */
public final class GatewayRefusedException extends IntygaException {
  private final int status;

  public GatewayRefusedException(int status, String message) {
    super(message);
    this.status = status;
  }

  /** The HTTP status the gateway answered with. */
  public int status() {
    return status;
  }
}
