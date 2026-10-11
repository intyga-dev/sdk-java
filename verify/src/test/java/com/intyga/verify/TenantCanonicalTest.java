package com.intyga.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class TenantCanonicalTest {
  private static final String TENANT = "tenant-alpha";
  private static final RequesterIdentity REQUESTER = new RequesterIdentity("did:example:human", null);
  private static final ApprovalRequirement REQUIREMENT =
      new ApprovalRequirement(1, false, List.of(), false, "human");

  private static void assertV2(String payload) throws Exception {
    var parsed = Records.JSON.readTree(payload);
    assertEquals(Div.TENANT_VERSION, parsed.path("v").asInt());
    assertEquals(TENANT, parsed.path("tenantId").asText());
  }

  @Test
  void optionalTenantKeepsV1AndAddsExactTenantToAllPayloadKinds() throws Exception {
    String v1 = Canonical.canonicalIntentPayload("target", "act", "Act", Map.of(), REQUESTER,
        REQUIREMENT, "n", "2026-10-10T00:00:00Z");
    assertEquals(Div.VERSION, Records.JSON.readTree(v1).path("v").asInt());
    assertFalse(Records.JSON.readTree(v1).has("tenantId"));
    assertV2(Canonical.canonicalIntentPayloadWithTenant("target", "act", "Act", Map.of(),
        REQUESTER, REQUIREMENT, "n", "2026-10-10T00:00:00Z", TENANT));
    assertV2(Canonical.canonicalOfflineIntentPayloadWithTenant("target", "act", "Act", Map.of(),
        REQUESTER, REQUIREMENT, "n", "2026-10-09T23:59:00Z", "2026-10-10T00:00:00Z", TENANT));
    assertV2(Canonical.canonicalDelegationPayloadWithTenant("target", "act", "Act", Map.of(),
        REQUESTER, REQUIREMENT, List.of("did:example:delegate"), 1, "n",
        "2026-10-09T23:59:00Z", "2026-10-10T00:00:00Z", TENANT));
    assertV2(Verify.canonicalAgentAuthorityPayloadWithTenant("target", List.of("act"), "Act",
        "did:example:agent", REQUESTER, REQUIREMENT, "n", "2026-10-09T23:59:00Z",
        "2026-10-10T00:00:00Z", null, TENANT));
    assertV2(Verify.canonicalPlatformIntentPayloadWithTenant("a".repeat(64), "rp.example",
        "subject-1", "2026-10-09T23:59:00Z", "2026-10-10T00:00:00Z", "n", TENANT));
    assertThrows(IllegalArgumentException.class,
        () -> Canonical.canonicalIntentPayloadWithTenant("target", "act", "Act", Map.of(),
            REQUESTER, REQUIREMENT, "n", "2026-10-10T00:00:00Z", ""));
  }
}
