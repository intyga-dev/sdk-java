package com.intyga.verify;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Shared Jackson mapper for the receipt/vector data model. Tree-model + own-final-records only;
 * polymorphic default typing is never enabled; unknown fields are ignored so a producer that grows
 * a field does not break deployed verifiers.
 */
final class Records {
  static final ObjectMapper JSON =
      new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

  private Records() {}
}
