package com.intyga.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.intyga.sdk.offline.TrustAnchorFile;
import org.junit.jupiter.api.Test;

class TrustAnchorTenantTest {
  private static String json(String tenantField) {
    return "{\"v\":1,\"type\":\"intyga-trust-anchor\",\"epoch\":1,"
        + "\"approvers\":[{\"did\":\"did:intyga:key:abc\",\"publicKeys\":[]}]"
        + tenantField + "}";
  }

  @Test
  void optionalTenantIsPreservedAndValidated() {
    assertNull(TrustAnchorFile.parse(json("")).tenantId());
    assertEquals("tenant-alpha", TrustAnchorFile.parse(json(",\"tenantId\":\"tenant-alpha\"")).tenantId());
    assertThrows(IllegalArgumentException.class, () -> TrustAnchorFile.parse(json(",\"tenantId\":\"\"")));
    assertThrows(IllegalArgumentException.class, () -> TrustAnchorFile.parse(json(",\"tenantId\":7")));
  }
}
