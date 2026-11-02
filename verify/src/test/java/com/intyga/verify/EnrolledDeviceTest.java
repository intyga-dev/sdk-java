package com.intyga.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * DIV §4.3.2 "Enrolled approver devices" in the canonical builders and the strict binding of the
 * signed field. The verifier's behaviour is pinned by the shared enrolledDevice vectors
 * ({@link SharedParityVectorsTest#enrolledDeviceVectors}); this covers what those cannot reach.
 */
final class EnrolledDeviceTest {
  private static final RequesterIdentity REQUESTER = new RequesterIdentity("did:intyga:agent:ci", null, null);

  private static ApprovalRequirement requirement(boolean hardware, List<String> aaguids, Boolean device) {
    return new ApprovalRequirement(1, hardware, aaguids, true, "human", null, device);
  }

  private static String intent(ApprovalRequirement r) {
    return Canonical.canonicalIntentPayload("prod-deploy", "deploy.production", "Deploy", Map.of(),
        REQUESTER, r, "n-1", "2999-01-01T00:00:00.000Z");
  }

  @Test
  void signedOnlyWhenTrueAndOmittedOtherwise() {
    String withField = intent(requirement(false, List.of(), Boolean.TRUE));
    assertTrue(withField.contains("\"requireEnrolledDevice\":true"), withField);
    // Absent and FALSE both keep the historical bytes: one policy, one encoding.
    String absent = intent(requirement(false, List.of(), null));
    assertEquals(absent, intent(requirement(false, List.of(), Boolean.FALSE)));
    assertFalse(absent.contains("requireEnrolledDevice"), absent);
    assertEquals(absent, intent(new ApprovalRequirement(1, false, List.of(), true, "human", null)));
  }

  @Test
  void ordinaryIntentsOnly() {
    ApprovalRequirement r = requirement(false, List.of(), Boolean.TRUE);
    String ordinaryOnly = "requireEnrolledDevice is defined only for ordinary approval intents (DIV §4.3.2)";
    assertEquals(ordinaryOnly, assertThrows(Canonical.NonPortableValueException.class, () ->
        Canonical.canonicalOfflineIntentPayload("t", "a", "d", Map.of(), REQUESTER, r, "n",
            "2026-01-01T00:00:00.000Z", "2026-01-01T00:30:00.000Z")).getMessage());
    assertEquals(ordinaryOnly, assertThrows(Canonical.NonPortableValueException.class, () ->
        Canonical.canonicalDelegationPayload("t", "a", "d", Map.of(), REQUESTER, r, List.of("did:intyga:x"), 1,
            "n", "2026-01-01T00:00:00.000Z", "2026-01-02T00:00:00.000Z")).getMessage());
    assertEquals(ordinaryOnly, assertThrows(Canonical.NonPortableValueException.class, () ->
        Verify.canonicalAgentAuthorityPayload("t", List.of("deploy"), "d", "did:intyga:agent:x", REQUESTER, r,
            "n", "2026-01-01T00:00:00.000Z", "2026-01-02T00:00:00.000Z")).getMessage());
  }

  @Test
  void neverWithAHardwareRequirement() {
    String combo = "requireEnrolledDevice cannot be combined with requireHardwareKey or allowedAaguids (DIV §4.3.2)";
    assertEquals(combo, assertThrows(Canonical.NonPortableValueException.class,
        () -> intent(requirement(true, List.of(), Boolean.TRUE))).getMessage());
    assertEquals(combo, assertThrows(Canonical.NonPortableValueException.class,
        () -> intent(requirement(false, List.of("cb69481e-8ff7-4039-93ec-0a2729a154a8"), Boolean.TRUE))).getMessage());
  }

  @Test
  void bindingDistinguishesAbsentTrueAndEveryOtherValue() throws IOException {
    String base = "{\"requiredApprovals\":1,\"requireHardwareKey\":false,\"allowedAaguids\":[],"
        + "\"requesterCannotApprove\":false,\"signerClass\":\"human\"";
    assertNull(Records.JSON.readValue(base + "}", ApprovalRequirement.class).requireEnrolledDevice());
    assertEquals(Boolean.TRUE,
        Records.JSON.readValue(base + ",\"requireEnrolledDevice\":true}", ApprovalRequirement.class).requireEnrolledDevice());
    // No coercion: every present value other than the literal true is malformed, never "true" or absent.
    for (String bad : List.of("false", "null", "\"true\"", "1", "{}", "[true]")) {
      ApprovalRequirement r = Records.JSON.readValue(base + ",\"requireEnrolledDevice\":" + bad + "}", ApprovalRequirement.class);
      assertEquals(Boolean.FALSE, r.requireEnrolledDevice(), bad);
      assertFalse(r.requiresEnrolledDevice(), bad);
    }
  }

  @Test
  void floorFromJsonRefusesWronglyTypedFlags() {
    String malformed = "expected.requirement() is malformed: requiredApprovals must be an integer of at least 1"
        + " and the flags booleans";
    assertNull(RequirementFloor.fromJson(null));
    RequirementFloor f = RequirementFloor.fromJson(Records.JSON.valueToTree(
        Map.of("requiredApprovals", 2, "requireEnrolledDevice", true)));
    assertEquals(new RequirementFloor(2, false, false, null, true), f);
    for (String bad : List.of("{\"requiredApprovals\":1,\"requireEnrolledDevice\":\"yes\"}",
        "{\"requiredApprovals\":1,\"requireHardwareKey\":null}", "{\"requiredApprovals\":1.5}",
        "{\"requiredApprovals\":\"1\"}", "{}", "{\"requiredApprovals\":1,\"excludedSignerDids\":\"did:x\"}")) {
      assertEquals(malformed, assertThrows(IllegalArgumentException.class,
          () -> RequirementFloor.fromJson(Records.JSON.readTree(bad))).getMessage(), bad);
    }
  }

  /** The shared golden intent vector carrying the field is present and is the one Java reproduces. */
  @Test
  void goldenIntentVectorCarriesTheField() throws IOException {
    JsonNode doc = Records.JSON.readTree(Files.readString(Path.of("vectors", "canonical-vectors.json")));
    int carrying = 0;
    for (JsonNode c : doc.path("intentPayloads")) {
      if (!c.path("input").path("requirement").has("requireEnrolledDevice")) continue;
      carrying++;
      ApprovalRequirement r = Records.JSON.convertValue(c.path("input").path("requirement"), ApprovalRequirement.class);
      assertTrue(r.requiresEnrolledDevice());
      assertTrue(c.path("expected").asText().contains("\"requireEnrolledDevice\":true"));
    }
    assertTrue(carrying > 0, "no intent vector carries requireEnrolledDevice");
  }
}
