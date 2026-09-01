package com.intyga.verify;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * DIV §4.4.6: a Delegation REQUIRES an identity-associating anchor and MUST be refused under a
 * key-set anchor — at seal verification, not only when {@code delegatedTo} is enforced at use time.
 * The sealing quorum names people; a public-keys anchor counts credentials instead.
 */
class DelegationAnchorTest {
  @Test
  void delegationRefusesKeySetAnchorAtSealVerification() {
    ApprovalReceipt receipt =
        ApprovalReceipt.parse(
            "{\"canonicalPayload\":\"{\\\"v\\\":1,\\\"type\\\":\\\"div-delegation\\\"}\","
                + "\"actionDescription\":\"d\",\"params\":{}}");
    Expected expected =
        new Expected("t", "n", "x", Map.of(), ApproverTrustAnchor.ofPublicKeys(List.of("k")));
    DelegationVerification res =
        Verify.verifyDelegation(receipt, expected, VerifyOptions.defaults());
    assertFalse(res.result().ok());
    assertTrue(res.result().reason().contains("§4.4.6"), res.result().reason());
  }
}
