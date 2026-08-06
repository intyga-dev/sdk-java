package com.intyga.sdk;

/**
 * The gateway could not be asked at all — connect failure, timeout, interrupted wait. No verdict
 * was rendered. See {@link GatewayRefusedException} for why the two are never conflated.
 */
public final class GatewayUnreachableException extends IntygaException {
  public GatewayUnreachableException(String message, Throwable cause) {
    super(message, cause);
  }
}
