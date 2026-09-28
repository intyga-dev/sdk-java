package com.intyga.verify;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * DIV §5 step 3d (H1). The signed requirement is authored by the signers, so one approver who is
 * also the requester can self-compose a 1-of-1 receipt for a 3-of-3 four-eyes action. Without a
 * floor it verifies (legacy behaviour, pinned); with the relying party's floor it is refused.
 */
class RequirementFloorTest {
  private static KeyPair keyPair() throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
    g.initialize(new ECGenParameterSpec("secp256r1"));
    return g.generateKeyPair();
  }

  private static String spki(KeyPair kp) {
    return Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
  }

  private static String sign(KeyPair kp, String payload) throws Exception {
    Signature s = Signature.getInstance("SHA256withECDSA");
    s.initSign(kp.getPrivate());
    s.update(payload.getBytes(StandardCharsets.UTF_8));
    return Base64.getEncoder().encodeToString(s.sign());
  }

  private static ApprovalReceipt receipt(String canonical, String display, Map<String, Object> params,
      RequesterIdentity requester, Map<String, KeyPair> signers) throws Exception {
    List<ApprovalWitness> ws = new ArrayList<>();
    for (var e : signers.entrySet()) {
      ws.add(new ApprovalWitness(e.getKey(), spki(e.getValue()), sign(e.getValue(), canonical), "ES256", null, null));
    }
    return new ApprovalReceipt(canonical, null, null, display, params, ws, null, null, null, null, null, null, requester, "");
  }

  @Test
  void floorRefusesSelfComposedDowngradeOnEveryQuorumEntryPoint() throws Exception {
    KeyPair alice = keyPair();
    KeyPair bob = keyPair();
    Map<String, String> keys = Map.of("did:ex:alice", spki(alice), "did:ex:bob", spki(bob));
    ApproverTrustAnchor anchor = ApproverTrustAnchor.ofDids(List.copyOf(keys.keySet()), keys::get);
    RequesterIdentity requester = new RequesterIdentity("did:ex:alice", null);
    Map<String, Object> params = Map.of("amount", 1000000, "to", "acct-9");
    ApprovalRequirement weak = new ApprovalRequirement(1, false, List.of(), false, "human");
    RequirementFloor fourEyes3 = new RequirementFloor(3, true, false);

    String canonical = Canonical.canonicalIntentPayload("prod-payments", "payments.wire", "Wire", params,
        requester, weak, "c_real_nonce", "2999-01-01T00:00:00.000Z");
    ApprovalReceipt forged = receipt(canonical, "Wire", params, requester, Map.of("did:ex:alice", alice));
    Expected expected = new Expected("prod-payments", "c_real_nonce", "payments.wire", params, anchor);
    assertTrue(Verify.verifyApprovalReceipt(forged, expected, VerifyOptions.defaults()).ok(),
        "without a floor the signers' own quorum is what is proved (legacy behaviour)");
    VerifyResult refused = Verify.verifyApprovalReceipt(forged, expected.withRequirement(fourEyes3), VerifyOptions.defaults());
    assertFalse(refused.ok());
    assertTrue(refused.reason().contains(RequirementFloor.WEAKER_REASON), refused.reason());
    for (RequirementFloor f : List.of(new RequirementFloor(1, true, false), new RequirementFloor(1, false, true),
        new RequirementFloor(0, false, false))) {
      assertFalse(Verify.verifyApprovalReceipt(forged, expected.withRequirement(f), VerifyOptions.defaults()).ok(), f.toString());
    }
    assertTrue(Verify.verifyApprovalReceipt(forged, expected.withRequirement(RequirementFloor.ofQuorum(1)), VerifyOptions.defaults()).ok());

    java.time.Instant now = java.time.Instant.now();
    String sealed = now.toString();
    String exp = now.plusSeconds(3600).toString();
    String delegation = Canonical.canonicalDelegationPayload("prod", "restart", "Restart", Map.of(), requester, weak,
        List.of("did:ex:bob"), 1, "d_nonce", sealed, exp);
    ApprovalReceipt seal = receipt(delegation, "Restart", Map.of(), requester, Map.of("did:ex:alice", alice));
    Expected dx = new Expected("prod", "", "restart", Map.of(), anchor);
    assertTrue(Verify.verifyDelegation(seal, dx, VerifyOptions.defaults()).result().ok());
    DelegationVerification dr = Verify.verifyDelegation(seal, dx.withRequirement(RequirementFloor.ofQuorum(2)), VerifyOptions.defaults());
    assertFalse(dr.result().ok());
    assertTrue(dr.result().reason().contains(RequirementFloor.WEAKER_REASON), dr.result().reason());

    String authority = Verify.canonicalAgentAuthorityPayload("prod", List.of("restart"), "Restart", "did:ex:agent",
        requester, weak, "a_nonce", sealed, exp);
    ApprovalReceipt auth = receipt(authority, "Restart", Map.of(), requester, Map.of("did:ex:alice", alice));
    assertTrue(Verify.verifyAgentAuthority(auth, new AgentAuthorityExpected(anchor, "prod", "did:ex:agent"), VerifyOptions.defaults()).ok());
    AgentAuthorityVerification ar = Verify.verifyAgentAuthority(auth,
        new AgentAuthorityExpected(anchor, "prod", "did:ex:agent", RequirementFloor.ofQuorum(2)), VerifyOptions.defaults());
    assertFalse(ar.ok());
    assertTrue(ar.reason().contains(RequirementFloor.WEAKER_REASON), ar.reason());
  }
}
