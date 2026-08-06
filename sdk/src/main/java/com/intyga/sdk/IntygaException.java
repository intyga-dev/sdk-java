package com.intyga.sdk;

/** Base class for everything this SDK throws deliberately. */
public class IntygaException extends RuntimeException {
  public IntygaException(String message) {
    super(message);
  }

  public IntygaException(String message, Throwable cause) {
    super(message, cause);
  }
}
