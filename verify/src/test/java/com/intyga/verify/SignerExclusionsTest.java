package com.intyga.verify;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SignerExclusionsTest {
  private static final ApprovalRequirement BASE =
      new ApprovalRequirement(1, false, List.of(), false, "human");

  @Test void absentExtensionsPreserveLegacyShapeAndEmptyListIsSigned() throws Exception {
    String legacy = Canonical.canonicalIntentPayload("t", "a", "d", Map.of(),
        new RequesterIdentity("did:r", null), BASE, "n", "2027-01-01T00:00:00.000Z");
    var old = Records.JSON.readTree(legacy);
    assertFalse(old.path("requirement").has("excludedSignerDids"));
    assertFalse(old.path("requester").has("credentialIssuerDid"));
    String extended = Canonical.canonicalIntentPayload("t", "a", "d", Map.of(),
        new RequesterIdentity("did:r", null, "did:issuer"),
        new ApprovalRequirement(1, false, List.of(), false, "human", List.of()),
        "n", "2027-01-01T00:00:00.000Z");
    var next = Records.JSON.readTree(extended);
    assertTrue(next.path("requirement").has("excludedSignerDids"));
    assertEquals("did:issuer", next.path("requester").path("credentialIssuerDid").asText());
  }

  @Test void canonicalExclusionsAreSortedUniqueAndFloorRequiresPresence() throws Exception {
    var requirement = new ApprovalRequirement(1, false, List.of(), false, "human",
        List.of("did:z", "did:a", "did:z"));
    var payload = Records.JSON.readTree(Canonical.canonicalIntentPayload("t", "a", "d", Map.of(),
        new RequesterIdentity("did:r", null), requirement, "n", "2027-01-01T00:00:00.000Z"));
    assertEquals(List.of("did:a", "did:z"), Records.JSON.convertValue(
        payload.path("requirement").path("excludedSignerDids"),
        Records.JSON.getTypeFactory().constructCollectionType(List.class, String.class)));
    assertNotNull(RequirementFloor.problem(BASE, new RequirementFloor(1, false, false, List.of())));
    assertNull(RequirementFloor.problem(requirement,
        new RequirementFloor(1, false, false, List.of("did:a"))));
  }

  @Test void floorAcceptsDuplicateDidsAndRefusesMalformedOnes() {
    var signed = new ApprovalRequirement(1, false, List.of(), false, "human", List.of("did:a"));
    // The floor is a set the signed exclusions must cover, as in the reference and every port.
    assertNull(RequirementFloor.problem(signed,
        new RequirementFloor(1, false, false, List.of("did:a", "did:a"))));
    for (String bad : new String[] {"", "did:", "not-a-did", "did:with space"}) {
      String reason = RequirementFloor.problem(signed, new RequirementFloor(1, false, false, List.of(bad)));
      assertNotNull(reason, bad);
      assertTrue(reason.contains("malformed"), reason);
    }
  }

  @Test void buildersRefuseMalformedIdentityExtensions() {
    // As the reference (NonCanonicalValue) and Go/Python do: no signable bytes for a shape every
    // verifier refuses.
    for (String bad : new String[] {"", "did:", "not-a-did", "did:with space"}) {
      var issuer = assertThrows(Canonical.NonPortableValueException.class,
          () -> Canonical.canonicalIntentPayload("t", "a", "d", Map.of(),
              new RequesterIdentity("did:r", null, bad), BASE, "n", "2027-01-01T00:00:00.000Z"));
      assertEquals("credentialIssuerDid must be a valid DID", issuer.getMessage());
      var exclusions = assertThrows(Canonical.NonPortableValueException.class,
          () -> Verify.canonicalAgentAuthorityPayload("t", List.of("p"), "d", "did:agent",
              new RequesterIdentity("did:r", null),
              new ApprovalRequirement(1, false, List.of(), false, "human", List.of("did:a", bad)),
              "n", "2026-01-01T00:00:00.000Z", "2027-01-01T00:00:00.000Z", null));
      assertEquals("excludedSignerDids must be a DID array", exclusions.getMessage());
    }
  }

  @Test void presentNullBindsAsMalformedAndAbsentStaysNull() throws Exception {
    // DIV §4.3.2: present-but-null is refused, not dropped; Jackson alone binds both as null.
    var nullIssuer = Records.JSON.readValue(
        "{\"did\":\"did:r\",\"attestation\":null,\"credentialIssuerDid\":null}", RequesterIdentity.class);
    assertEquals("", nullIssuer.credentialIssuerDid());
    assertNull(Records.JSON.readValue("{\"did\":\"did:r\",\"attestation\":null}", RequesterIdentity.class)
        .credentialIssuerDid());
    String base = "{\"requiredApprovals\":1,\"requireHardwareKey\":false,\"allowedAaguids\":[],"
        + "\"requesterCannotApprove\":false,\"signerClass\":\"human\"";
    assertEquals(List.of(""), Records.JSON.readValue(base + ",\"excludedSignerDids\":null}",
        ApprovalRequirement.class).excludedSignerDids());
    assertNull(Records.JSON.readValue(base + "}", ApprovalRequirement.class).excludedSignerDids());
    assertEquals(List.of("did:a"), Records.JSON.readValue(base + ",\"excludedSignerDids\":[\"did:a\"]}",
        ApprovalRequirement.class).excludedSignerDids());
  }
}
