package com.intyga.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.intyga.verify.ApprovalReceipt;
import com.intyga.verify.ApproverTrustAnchor;
import com.intyga.verify.Expected;
import com.intyga.verify.Verify;
import com.intyga.verify.VerifyOptions;
import com.intyga.verify.VerifyResult;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The handoff this SDK exists to make possible: a receipt that arrives over HTTP from the gateway
 * is verified OFFLINE, in-process, against a key the relying party resolved itself.
 *
 * <p>The receipt served by the mock gateway is a real committed golden vector, so this exercises
 * the genuine signature path rather than a hand-made stub — a mock receipt that "verifies" because
 * the test also made up the key would prove nothing.
 */
class ReceiptVerificationTest {

  private static final ObjectMapper JSON = new ObjectMapper();

  private HttpServer server;
  private JsonNode vector;

  @BeforeEach
  void setUp() throws IOException {
    // The WebAuthn vector is one self-contained passkey approval with its enrollment key.
    vector = JSON.readTree(
        Files.readString(Path.of("vectors", "webauthn-vector.json")));
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.start();
  }

  @AfterEach
  void tearDown() {
    server.stop(0);
  }

  private String baseUrl() {
    return "http://127.0.0.1:" + server.getAddress().getPort();
  }

  private void serveApproval() {
    JsonNode receipt = vector.get("receipt");
    server.createContext("/authorize", exchange -> {
      byte[] out = "{\"nonce\":\"n_v\",\"status\":\"PENDING\"}".getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(200, out.length);
      exchange.getResponseBody().write(out);
      exchange.close();
    });
    server.createContext("/authorize/n_v", exchange -> {
      String body = "{\"status\":\"APPROVED\",\"signatureHash\":\"sh\",\"receipt\":" + receipt + "}";
      byte[] out = body.getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(200, out.length);
      exchange.getResponseBody().write(out);
      exchange.close();
    });
  }

  private ApprovalResult approve() {
    serveApproval();
    IntygaClient client = IntygaClient.builder().gatewayUrl(baseUrl()).token("t").build();
    return client.requireApproval(
        "Approve the vector action",
        RequireApprovalOptions.builder()
            .authorize(AuthorizeOptions.builder().target("t").build())
            .interval(Duration.ofMillis(10))
            .build());
  }

  /** The relying party's own expectation — target, nonce and approver keys asserted from its state. */
  private Expected expectationFrom(String trustedKey, Map<String, Object> params) {
    JsonNode exp = vector.get("expected");
    return new Expected(
        exp.get("target").asText(),
        exp.get("nonce").asText(),
        exp.get("actionType").asText(),
        params,
        ApproverTrustAnchor.ofPublicKeys(List.of(trustedKey)));
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> vectorParams() {
    return JSON.convertValue(vector.get("expected").get("params"), Map.class);
  }

  @Test
  void receiptFromTheGatewayVerifiesOffline() {
    ApprovalResult approval = approve();
    assertEquals(ApprovalStatus.APPROVED, approval.status());
    assertNotNull(approval.receipt(), "an APPROVED result must carry a receipt to verify");

    // The bridge: the SDK's raw receipt JSON becomes a verifier receipt with no re-serialization.
    ApprovalReceipt receipt = ApprovalReceipt.parse(approval.receipt());
    String trustedKey = vector.get("receipt").get("signerPublicKey").asText();

    VerifyResult res = Verify.verifyApprovalReceipt(
        receipt,
        expectationFrom(trustedKey, vectorParams()),
        VerifyOptions.builder()
            .expectedOrigin(vector.get("origin").asText())
            .expectedRpId(vector.get("rpId").asText())
            .build());

    assertTrue(res.ok(), "receipt from the gateway should verify offline: " + res.reason());
  }

  @Test
  void verificationRefusesParamsTheApproverNeverSaw() {
    ApprovalResult approval = approve();
    ApprovalReceipt receipt = ApprovalReceipt.parse(approval.receipt());
    String trustedKey = vector.get("receipt").get("signerPublicKey").asText();

    // The whole point of verifying locally: the gateway said APPROVED, but the params about to
    // execute are not the ones a human signed.
    VerifyResult res = Verify.verifyApprovalReceipt(
        receipt,
        expectationFrom(trustedKey, Map.of("amount", 999999)),
        VerifyOptions.builder()
            .expectedOrigin(vector.get("origin").asText())
            .expectedRpId(vector.get("rpId").asText())
            .build());

    assertFalse(res.ok(), "params the approver never saw must not verify");
  }

  @Test
  void verificationRefusesAnUntrustedApproverKey() {
    ApprovalResult approval = approve();
    ApprovalReceipt receipt = ApprovalReceipt.parse(approval.receipt());

    // A different key than the one this relying party enrolled. The receipt still carries its own
    // key, and that is exactly what must NOT be consulted (DIV Invariant 3).
    String otherKey = vector.get("receipt").get("signerPublicKey").asText().replace('A', 'B');
    VerifyResult res = Verify.verifyApprovalReceipt(
        receipt,
        expectationFrom(otherKey, vectorParams()),
        VerifyOptions.builder()
            .expectedOrigin(vector.get("origin").asText())
            .expectedRpId(vector.get("rpId").asText())
            .build());

    assertFalse(res.ok(), "a receipt must not verify against a key the relying party did not trust");
  }
}
