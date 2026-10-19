package com.intyga.sdk;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.intyga.verify.ApproverTrustAnchor;
import com.intyga.verify.RequirementFloor;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ApprovalGuardTest {
  private static final ObjectMapper JSON = new ObjectMapper();
  private HttpServer server;
  private IntygaClient client;
  private JsonNode vector;
  private JsonNode receipt;
  private Map<String, Object> params;
  private String nonce;
  private String status;
  private boolean consumeOk;
  private boolean dispatchOk;
  private String failPath;
  private Runnable onAuthorize;
  private final List<String> events = new CopyOnWriteArrayList<>();
  private final List<JsonNode> bodies = new CopyOnWriteArrayList<>();

  @BeforeEach
  void setUp() throws IOException {
    reset();
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/authorize", exchange -> {
      String path = exchange.getRequestURI().getPath();
      ObjectNode response = JSON.createObjectNode();
      switch (path) {
        case "/authorize" -> {
          bodies.add(JSON.readTree(exchange.getRequestBody()));
          if (onAuthorize != null) onAuthorize.run();
          events.add("authorize");
          response.put("status", "PENDING").put("nonce", nonce);
        }
        case "/authorize/verify" -> {
          bodies.add(JSON.readTree(exchange.getRequestBody()));
          events.add("consume");
          response.put("ok", consumeOk).put("reason", "already consumed");
        }
        default -> {
          if (path.endsWith("/dispatched")) {
            bodies.add(JSON.readTree(exchange.getRequestBody()));
            events.add("dispatch");
            response.put("ok", dispatchOk);
          } else {
            events.add("status");
            response.put("status", status).set("receipt", receipt);
          }
        }
      }
      byte[] out = JSON.writeValueAsBytes(response);
      exchange.sendResponseHeaders(path.equals(failPath) ? 403 : 200, out.length);
      exchange.getResponseBody().write(out);
      exchange.close();
    });
    server.start();
    client = IntygaClient.builder().gatewayUrl("http://127.0.0.1:" + server.getAddress().getPort())
        .token("test-token").build();
  }

  private void reset() throws IOException {
    vector = JSON.readTree(Files.readString(Path.of("vectors", "webauthn-vector.json")));
    receipt = vector.get("receipt").deepCopy();
    params = JSON.convertValue(vector.path("expected").path("params"), new TypeReference<>() {});
    nonce = vector.path("expected").path("nonce").asText();
    status = "APPROVED";
    consumeOk = true;
    dispatchOk = true;
    failPath = "";
    onAuthorize = null;
    events.clear();
    bodies.clear();
  }

  @AfterEach
  void tearDown() { if (server != null) server.stop(0); }

  private ApproverTrustAnchor trust() {
    return ApproverTrustAnchor.ofPublicKeys(List.of(vector.path("receipt").path("signerPublicKey").asText()));
  }

  private ApprovalGuard.Builder options(ApproverTrustAnchor approvers) {
    return ApprovalGuard.builder(client, approvers)
        .target(vector.path("expected").path("target").asText())
        .actionType(vector.path("expected").path("actionType").asText())
        .expectedOrigin(vector.path("origin").asText()).expectedRpId(vector.path("rpId").asText())
        .timeout(Duration.ofSeconds(1)).interval(Duration.ofMillis(1)).reportDispatch(60);
  }

  @Test
  @SuppressWarnings("unchecked")
  void snapshotsArgumentsAndExecutesOnlyAfterVerifiedConsumption() throws Exception {
    JsonNode expectedParams = JSON.valueToTree(params);
    onAuthorize = () -> {
      params.put("amount", 999999);
      ((Map<String, Object>) params.get("meta")).put("ok", false);
    };
    var builder = options(trust());
    var guarded = builder.build().wrap(args -> {
      events.add("tool");
      assertEquals(expectedParams, JSON.valueToTree(args));
      return "sent";
    });
    builder.target("another-service"); // A built guard has its own immutable configuration.
    assertEquals("sent", guarded.call(params));
    assertEquals(List.of("authorize", "status", "consume", "tool", "dispatch"), events);
    for (JsonNode body : bodies.subList(0, 2)) {
      assertEquals(expectedParams, body.get("params"));
      assertEquals(vector.path("expected").path("target"), body.get("target"));
      assertEquals(vector.path("expected").path("actionType"), body.get("actionType"));
    }
    assertEquals(nonce, bodies.get(1).path("nonce").asText());
    assertEquals(60, bodies.get(2).path("evidenceWithinSeconds").asInt());
  }

  @Test
  void refusesBeforeExecutionAndDispatch() throws Exception {
    for (String reason : List.of("denied", "expired", "consumed", "offline", "no receipt", "nonce",
        "target", "action", "params", "signer", "empty trust", "signature", "origin", "rpId", "missing pins",
        "tenant", "floor", "consume false", "consume HTTP", "authorize HTTP", "non JSON")) {
      reset();
      var builder = options(trust());
      switch (reason) {
        case "denied" -> status = "DENIED";
        case "expired" -> status = "EXPIRED";
        case "consumed" -> status = "CONSUMED";
        case "offline" -> status = "OFFLINE_APPROVED";
        case "no receipt" -> receipt = null;
        case "nonce" -> nonce = "another-challenge";
        case "target" -> builder.target("another-service");
        case "action" -> builder.actionType("another-action");
        case "params" -> params.put("amount", 1);
        case "signer" -> builder = options(ApproverTrustAnchor.ofPublicKeys(List.of("untrusted")));
        case "empty trust" -> builder = options(ApproverTrustAnchor.ofPublicKeys(List.of()));
        case "signature" -> ((ObjectNode) receipt).put("signature", "invalid");
        case "origin" -> builder.expectedOrigin("https://wrong.example");
        case "rpId" -> builder.expectedRpId("wrong.example");
        case "missing pins" -> builder.expectedOrigin(null).expectedRpId(null);
        // The vector's receipt is v1: an expected tenant reaches the verifier, which refuses it.
        case "tenant" -> builder.tenantId("another-workspace");
        case "floor" -> builder.requirement(new RequirementFloor(2, false, false));
        case "consume false" -> consumeOk = false;
        case "consume HTTP" -> failPath = "/authorize/verify";
        case "authorize HTTP" -> failPath = "/authorize";
        case "non JSON" -> params.put("bad", new Object());
        default -> fail("unknown test case");
      }
      var guarded = builder.build().wrap(args -> { fail("refused tool ran: " + reason); return "sent"; });
      assertThrows(Exception.class, () -> guarded.call(params), reason);
      assertFalse(events.contains("dispatch"), reason);
      if (!reason.startsWith("consume")) assertFalse(events.contains("consume"), reason);
    }
  }

  @Test
  void dispatchAndDiagnosticFailuresPreserveOriginalResultAndException() throws Exception {
    for (String outcome : List.of("success", "exception", "error")) {
      reset();
      failPath = "/authorize/" + nonce + "/dispatched";
      var diagnosed = new AtomicBoolean();
      Exception original = new Exception("original tool exception");
      AssertionError originalError = new AssertionError("original tool error");
      var guarded = options(trust()).onDispatchError((failedNonce, error) -> {
        assertEquals(nonce, failedNonce);
        assertNotNull(error);
        diagnosed.set(true);
        throw new AssertionError("diagnostic failed");
      }).build().wrap(args -> {
        if (outcome.equals("exception")) throw original;
        if (outcome.equals("error")) throw originalError;
        return "sent";
      });
      switch (outcome) {
        case "success" -> assertEquals("sent", guarded.call(params));
        case "exception" -> assertSame(original, assertThrows(Exception.class, () -> guarded.call(params)));
        case "error" -> assertSame(originalError, assertThrows(AssertionError.class, () -> guarded.call(params)));
        default -> fail();
      }
      assertTrue(diagnosed.get());
    }
  }

  @Test
  void reportingIsOptInAndRunsAfterToolExceptions() throws Exception {
    for (int seconds : List.of(0, 60)) {
      reset();
      Exception original = new Exception("tool failed");
      var guarded = options(trust()).reportDispatch(seconds).build().wrap(args -> { throw original; });
      assertSame(original, assertThrows(Exception.class, () -> guarded.call(params)));
      assertEquals(seconds != 0, events.contains("dispatch"));
    }
  }

  @Test
  void requiresValidConfiguration() {
    assertThrows(NullPointerException.class, () -> options(null).build());
    assertThrows(IllegalArgumentException.class, () -> options(trust()).target(" ").build());
    assertThrows(IllegalArgumentException.class, () -> options(trust()).actionType("").build());
    assertThrows(IllegalArgumentException.class, () -> options(trust()).reportDispatch(9).build());
    assertThrows(IllegalArgumentException.class, () -> options(trust()).reportDispatch(86401).build());
    assertThrows(NullPointerException.class, () -> options(trust()).build().wrap(null));
  }

  @Test
  void unacknowledgedDispatchIsReportedWithoutRetryingTheTool() throws Exception {
    dispatchOk = false;
    var diagnosed = new java.util.concurrent.atomic.AtomicInteger();
    var calls = new java.util.concurrent.atomic.AtomicInteger();
    var guarded = options(trust()).onDispatchError((failedNonce, error) -> {
      assertEquals(nonce, failedNonce);
      assertNotNull(error);
      diagnosed.incrementAndGet();
    }).build().wrap(args -> { calls.incrementAndGet(); return "sent"; });
    assertEquals("sent", guarded.call(params));
    assertEquals(1, calls.get());
    assertEquals(1, diagnosed.get());
  }
}
