package com.intyga.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Cross-port DIV v2 tenant-binding contract vectors. */
final class TenantBindingVectorsTest {
  private static JsonNode vectors() {
    try {
      return Records.JSON.readTree(Files.readString(
          Path.of("vectors", "tenant-binding-vectors.json")));
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  private static Map<String, JsonNode> keys(JsonNode root) {
    Map<String, JsonNode> out = new HashMap<>();
    root.path("keys").forEach(k -> out.put(k.path("id").asText(), k));
    return out;
  }

  private static ApproverTrustAnchor keyAnchor(JsonNode expected, Map<String, JsonNode> keys) {
    List<String> publicKeys = new ArrayList<>();
    expected.path("approverKeyIds").forEach(id ->
        publicKeys.add(keys.get(id.asText()).path("spkiB64").asText()));
    return ApproverTrustAnchor.ofPublicKeys(publicKeys);
  }

  private static ApproverTrustAnchor didAnchor(JsonNode expected, Map<String, JsonNode> keys) {
    Map<String, List<String>> byDid = new HashMap<>();
    expected.path("approverDids").fields().forEachRemaining(entry -> {
      List<String> publicKeys = new ArrayList<>();
      entry.getValue().forEach(id -> publicKeys.add(keys.get(id.asText()).path("spkiB64").asText()));
      byDid.put(entry.getKey(), publicKeys);
    });
    return ApproverTrustAnchor.ofDidsMultiKey(new ArrayList<>(byDid.keySet()), byDid::get);
  }

  private static String optionalText(JsonNode node) {
    return node == null || node.isNull() ? null : node.asText();
  }

  private static VerifyOptions options(JsonNode node) {
    VerifyOptions.Builder builder = VerifyOptions.builder()
        .asOf(Instant.parse(node.path("asOf").asText()));
    if (node.path("allowOffline").asBoolean(false)) builder.allowOffline(true);
    if (node.has("expectedOrigin")) builder.expectedOrigin(node.path("expectedOrigin").asText());
    if (node.has("expectedRpId")) builder.expectedRpId(node.path("expectedRpId").asText());
    if (node.has("clockSkewSeconds")) builder.clockSkewSeconds(node.path("clockSkewSeconds").asInt());
    return builder.build();
  }

  @Test void allSupportedTenantBindingCases() {
    JsonNode root = vectors();
    Map<String, JsonNode> keyById = keys(root);
    for (JsonNode c : root.path("cases")) {
      String name = c.path("name").asText();
      String verifier = c.path("verifier").asText();
      ObjectNode options = c.path("options").deepCopy();
      boolean got;
      String reason = "";
      if (verifier.equals("approval") || verifier.equals("approval-with-delegation")) {
        Expected expected = new Expected(c.path("expected").path("target").asText(),
            c.path("expected").path("nonce").asText(), c.path("expected").path("actionType").asText(),
            Records.JSON.convertValue(c.path("expected").path("params"),
                new com.fasterxml.jackson.core.type.TypeReference<>() {}),
            keyAnchor(c.path("expected"), keyById),
            c.path("expected").has("agentContext")
                ? Records.JSON.convertValue(c.path("expected").path("agentContext"),
                    new com.fasterxml.jackson.core.type.TypeReference<>() {}) : null)
            .withRequesterDid(optionalText(c.path("expected").get("requesterDid")));
        JsonNode expectedTenant = c.get("expectedTenantId");
        if (expectedTenant != null && !expectedTenant.isNull()) expected = expected.withTenantId(expectedTenant.asText());
        VerifyOptions opts = options(options);
        if (c.path("chain").isArray() && !c.path("chain").isEmpty()) {
          List<AgentAuthorityChainLink> chain = new ArrayList<>();
          c.path("chain").forEach(link -> {
            JsonNode e = link.path("expected");
            chain.add(new AgentAuthorityChainLink(ApprovalReceipt.parse(link.path("receipt")),
                new AgentAuthorityExpected(didAnchor(e, keyById), e.path("target").asText(),
                    e.path("agentDid").asText(), null, optionalText(link.get("expectedTenantId")))));
          });
          opts = VerifyOptions.builder().asOf(Instant.parse(options.path("asOf").asText()))
              .agentAuthorityChain(chain).build();
        }
        if (verifier.equals("approval-with-delegation")) {
          JsonNode de = c.path("delegationExpected");
          Expected delegationExpected = new Expected(de.path("target").asText(), de.path("nonce").asText(),
              de.path("actionType").asText(), Records.JSON.convertValue(de.path("params"),
                  new com.fasterxml.jackson.core.type.TypeReference<>() {}), didAnchor(de, keyById))
              .withRequesterDid(optionalText(de.get("requesterDid")));
          JsonNode delegationTenant = c.get("delegationExpectedTenantId");
          if (delegationTenant != null && !delegationTenant.isNull()) delegationExpected = delegationExpected.withTenantId(delegationTenant.asText());
          var delegation = Verify.verifyDelegation(ApprovalReceipt.parse(c.path("delegationReceipt")),
              delegationExpected, opts);
          if (!delegation.result().ok() || delegation.delegation() == null) {
            got = false;
            reason = delegation.result().reason();
            assertEquals(c.path("ok").asBoolean(), got, name + ": " + reason);
            continue;
          }
          opts = VerifyOptions.builder().asOf(Instant.parse(options.path("asOf").asText()))
              .allowOffline(true).delegation(delegation.delegation()).build();
        }
        VerifyResult result = Verify.verifyApprovalReceipt(ApprovalReceipt.parse(c.path("receipt")), expected, opts);
        got = result.ok();
        reason = result.reason();
      } else if (verifier.equals("delegation")) {
        JsonNode e = c.path("expected");
        Expected expected = new Expected(e.path("target").asText(), e.path("nonce").asText(),
            e.path("actionType").asText(), Records.JSON.convertValue(e.path("params"),
                new com.fasterxml.jackson.core.type.TypeReference<>() {}), didAnchor(e, keyById));
        if (!c.path("expectedTenantId").isNull()) expected = expected.withTenantId(c.path("expectedTenantId").asText());
        var result = Verify.verifyDelegation(ApprovalReceipt.parse(c.path("receipt")), expected, options(options));
        got = result.result().ok(); reason = result.result().reason();
      } else if (verifier.equals("authority")) {
        JsonNode e = c.path("expected");
        AgentAuthorityExpected expected = new AgentAuthorityExpected(didAnchor(e, keyById),
            e.path("target").asText(), e.path("agentDid").asText(), null,
            optionalText(c.get("expectedTenantId")));
        var result = Verify.verifyAgentAuthority(ApprovalReceipt.parse(c.path("receipt")), expected, options(options));
        got = result.ok(); reason = result.reason();
      } else if (verifier.equals("platform")) {
        JsonNode e = c.path("expected");
        List<String> platformKeys = new ArrayList<>();
        e.path("approverKeyIds").forEach(id -> platformKeys.add(keyById.get(id.asText()).path("coseB64").asText()));
        PlatformExpected expected = new PlatformExpected(ApproverTrustAnchor.ofPublicKeys(platformKeys), e.path("payloadHash").asText(),
            e.path("rpId").asText(), e.path("nonce").asText(), e.path("subjectExternalId").asText(),
            optionalText(c.get("expectedTenantId")));
        VerifyOptions opts = VerifyOptions.builder().asOf(Instant.parse(options.path("asOf").asText()))
            .expectedOrigin(options.path("expectedOrigin").asText()).expectedRpId(e.path("rpId").asText()).build();
        var result = Verify.verifyPlatformReceipt(PlatformReceipt.parse(c.path("receipt")), expected, opts);
        got = result.ok(); reason = result.reason();
      } else if (verifier.equals("authority-chain")) {
        List<AgentAuthorityChainLink> chain = new ArrayList<>();
        c.path("chain").forEach(link -> {
          JsonNode e = link.path("expected");
          chain.add(new AgentAuthorityChainLink(ApprovalReceipt.parse(link.path("receipt")),
              new AgentAuthorityExpected(didAnchor(e, keyById), e.path("target").asText(),
                  e.path("agentDid").asText(), null, optionalText(link.get("expectedTenantId")))));
        });
        JsonNode a = c.path("action");
        AgentDelegatedAction action = new AgentDelegatedAction(optionalText(a.get("tenantId")),
            a.path("target").asText(), a.path("actionType").asText(), a.path("agentDid").asText(),
            a.path("delegatedBy").asText());
        var result = Verify.verifyAgentDelegationChain(chain, action, options(options));
        got = result.ok(); reason = result.reason();
      } else {
        continue; // Unsupported verifier shape is deliberately not counted as implemented.
      }
      assertEquals(c.path("ok").asBoolean(), got, name + (reason == null || reason.isEmpty() ? "" : ": " + reason));
    }
  }

  @Test void sharedAgentReceiptDigestProjectionCases() {
    JsonNode root = vectors();
    for (JsonNode c : root.path("agentReceiptDigestCases")) {
      String actual = Verify.agentReceiptDigest(ApprovalReceipt.parse(c.path("receipt")));
      org.junit.jupiter.api.Assertions.assertEquals(c.path("expected").asText(), actual, c.path("name").asText());
    }
  }

  @Test void malformedWitnessDigestRefusesInsteadOfEscapingTheDelegationChainVerifier() {
    JsonNode root = vectors();
    JsonNode vector = null;
    for (JsonNode c : root.path("cases")) {
      if (c.path("name").asText().equals("tenant-v2-cross-tenant-authority-chain-refused")) vector = c;
    }
    if (vector == null) throw new AssertionError("authority chain vector missing");
    Map<String, JsonNode> keyById = keys(root);
    List<AgentAuthorityChainLink> chain = new ArrayList<>();
    for (int i = 0; i < vector.path("chain").size(); i++) {
      JsonNode link = vector.path("chain").get(i);
      ObjectNode receipt = link.path("receipt").deepCopy();
      if (i == 0) {
        // The ES256 signature remains valid; this optional field is ignored by signature checking,
        // but canonicalizing the complete receipt digest must refuse the unpaired surrogate.
        receipt.put("clientDataJSON", "\uD800");
      }
      JsonNode e = link.path("expected");
      chain.add(new AgentAuthorityChainLink(ApprovalReceipt.parse(receipt),
          new AgentAuthorityExpected(didAnchor(e, keyById), e.path("target").asText(),
              e.path("agentDid").asText(), null, optionalText(link.get("expectedTenantId")))));
    }
    JsonNode a = vector.path("action");
    AgentDelegatedAction action = new AgentDelegatedAction(optionalText(a.get("tenantId")),
        a.path("target").asText(), a.path("actionType").asText(), a.path("agentDid").asText(),
        a.path("delegatedBy").asText());
    VerifyResult result = Verify.verifyAgentDelegationChain(chain, action, options(vector.path("options")));
    assertFalse(result.ok());
    org.junit.jupiter.api.Assertions.assertEquals("authority link 1 cannot be digested", result.reason());
  }

  @Test void incompleteWitnessCannotBeDroppedFromAnAuthorityParentDigest() {
    JsonNode root = vectors();
    JsonNode vector = null;
    for (JsonNode c : root.path("cases")) {
      if (c.path("name").asText().equals("tenant-v2-cross-tenant-authority-chain-refused")) vector = c;
    }
    if (vector == null) throw new AssertionError("authority chain vector missing");
    Map<String, JsonNode> keyById = keys(root);
    List<AgentAuthorityChainLink> chain = new ArrayList<>();
    for (int i = 0; i < vector.path("chain").size(); i++) {
      JsonNode link = vector.path("chain").get(i);
      ObjectNode receipt = link.path("receipt").deepCopy();
      if (i == 0) {
        ObjectNode witness = Records.JSON.createObjectNode()
            .put("signerDid", receipt.path("signerDid").asText())
            .put("signerPublicKey", receipt.path("signerPublicKey").asText())
            .put("signature", receipt.path("signature").asText())
            .put("sigAlg", receipt.path("sigAlg").asText());
        var witnesses = Records.JSON.createArrayNode();
        witnesses.add(witness);
        witnesses.addObject();
        receipt.set("signatures", witnesses);
      }
      JsonNode e = link.path("expected");
      chain.add(new AgentAuthorityChainLink(ApprovalReceipt.parse(receipt),
          new AgentAuthorityExpected(didAnchor(e, keyById), e.path("target").asText(),
              e.path("agentDid").asText(), null, optionalText(link.get("expectedTenantId")))));
    }
    JsonNode a = vector.path("action");
    AgentDelegatedAction action = new AgentDelegatedAction(optionalText(a.get("tenantId")),
        a.path("target").asText(), a.path("actionType").asText(), a.path("agentDid").asText(),
        a.path("delegatedBy").asText());
    VerifyResult result = Verify.verifyAgentDelegationChain(chain, action, options(vector.path("options")));
    assertFalse(result.ok());
    org.junit.jupiter.api.Assertions.assertEquals("authority link 1 cannot be digested", result.reason());
  }
}
