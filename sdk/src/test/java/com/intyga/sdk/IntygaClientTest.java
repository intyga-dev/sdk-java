package com.intyga.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * In-process {@link HttpServer} on port 0 — no child process, no external socket, mirroring the Go
 * suite. Handler threads cannot fail a JUnit test directly, so every handler records mismatches
 * into {@link #violations} and each test ends by asserting that queue is empty: an assertion
 * swallowed by the server thread is exactly how a permissive mock once hid a production 400 in the
 * Go client's consume path.
 */
class IntygaClientTest {

  private static final ObjectMapper JSON = new ObjectMapper();

  private HttpServer server;
  private ConcurrentLinkedQueue<String> violations;

  @BeforeEach
  void setUp() throws IOException {
    violations = new ConcurrentLinkedQueue<>();
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

  private void expect(boolean condition, String description) {
    if (!condition) {
      violations.add(description);
    }
  }

  private void assertNoViolations() {
    assertEquals(List.of(), List.copyOf(violations));
  }

  private static String readBody(HttpExchange exchange) throws IOException {
    return new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
  }

  private static void respond(HttpExchange exchange, int status, String json) throws IOException {
    byte[] out = json.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("content-type", "application/json");
    exchange.sendResponseHeaders(status, out.length);
    exchange.getResponseBody().write(out);
    exchange.close();
  }

  private static AuthorizeOptions wipeOptions() {
    return AuthorizeOptions.builder()
        .target("prod-db-cluster-01")
        .actionType("wipe_production")
        .params(Map.of("database", "prod-db-1"))
        .build();
  }

  @Test
  void requireApprovalHappyPath() {
    AtomicInteger polls = new AtomicInteger();
    server.createContext(
        "/authorize",
        exchange -> {
          expect(
              "Bearer test-token".equals(exchange.getRequestHeaders().getFirst("Authorization")),
              "authorize: wrong authorization header");
          JsonNode body = JSON.readTree(readBody(exchange));
          expect(
              "Delete production database".equals(body.path("actionDescription").asText()),
              "authorize: actionDescription missing from body");
          respond(exchange, 200, "{\"nonce\":\"n_abc123\",\"status\":\"PENDING\"}");
        });
    server.createContext(
        "/authorize/n_abc123",
        exchange -> {
          if (polls.incrementAndGet() == 1) {
            respond(exchange, 200, "{\"status\":\"PENDING\"}");
          } else {
            respond(
                exchange,
                200,
                "{\"status\":\"APPROVED\",\"signatureHash\":\"sh_1\","
                    + "\"receipt\":{\"verificationCode\":\"1234-5678\"}}");
          }
        });

    IntygaClient client = IntygaClient.builder().gatewayUrl(baseUrl()).token("test-token").build();
    ApprovalResult r =
        client.requireApproval(
            "Delete production database",
            RequireApprovalOptions.builder()
                .authorize(wipeOptions())
                .interval(Duration.ofMillis(10))
                .build());

    assertEquals(ApprovalStatus.APPROVED, r.status());
    assertEquals("n_abc123", r.nonce());
    assertEquals("sh_1", r.signatureHash());
    assertNotNull(r.receipt());
    assertEquals("1234-5678", r.receipt().path("verificationCode").asText());
    assertTrue(polls.get() >= 2, "should have polled through PENDING at least once");
    assertNoViolations();
  }

  @Test
  void deniedStopsPolling() {
    AtomicInteger polls = new AtomicInteger();
    server.createContext(
        "/authorize",
        exchange -> respond(exchange, 200, "{\"nonce\":\"n_1\",\"status\":\"PENDING\"}"));
    server.createContext(
        "/authorize/n_1",
        exchange -> {
          polls.incrementAndGet();
          respond(exchange, 200, "{\"status\":\"DENIED\"}");
        });

    IntygaClient client = IntygaClient.builder().gatewayUrl(baseUrl()).token("t").build();
    ApprovalResult r =
        client.requireApproval(
            "x",
            RequireApprovalOptions.builder()
                .authorize(wipeOptions())
                .interval(Duration.ofMillis(10))
                .build());

    assertEquals(ApprovalStatus.DENIED, r.status());
    assertEquals("n_1", r.nonce());
    assertEquals(1, polls.get());
    assertNoViolations();
  }

  @Test
  void tokenExchangeAndCache() {
    AtomicInteger exchanges = new AtomicInteger();
    String expectedBasic =
        java.util.Base64.getEncoder().encodeToString("cid:secret".getBytes(StandardCharsets.UTF_8));
    server.createContext(
        "/oauth/token",
        exchange -> {
          exchanges.incrementAndGet();
          expect(
              ("Basic " + expectedBasic)
                  .equals(exchange.getRequestHeaders().getFirst("Authorization")),
              "token: wrong basic auth header");
          // No expires_in at all: a gateway or proxy that omits it must not NPE the exchange, and
          // the token is then served until a 401 evicts it — however far the clock moves.
          respond(exchange, 200, "{\"access_token\":\"tok_exchanged\"}");
        });

    AtomicLong clock = new AtomicLong();
    IntygaClient client =
        IntygaClient.builder()
            .gatewayUrl(baseUrl())
            .clientId("cid")
            .clientSecret("secret")
            .nanoClock(clock::get)
            .build();

    assertEquals("tok_exchanged", client.token());
    assertEquals("tok_exchanged", client.token());
    clock.addAndGet(Duration.ofDays(30).toNanos());
    assertEquals("tok_exchanged", client.token());
    assertEquals(1, exchanges.get(), "token() must serve the cache when no expiry is known");
    assertNoViolations();
  }

  @Test
  void tokenIsReExchangedBeforeExpiry() {
    AtomicInteger exchanges = new AtomicInteger();
    server.createContext(
        "/oauth/token",
        exchange ->
            respond(
                exchange,
                200,
                "{\"access_token\":\"tok_"
                    + exchanges.incrementAndGet()
                    + "\",\"expires_in\":100}"));

    AtomicLong clock = new AtomicLong(Duration.ofHours(1).toNanos());
    IntygaClient client =
        IntygaClient.builder()
            .gatewayUrl(baseUrl())
            .clientId("cid")
            .clientSecret("secret")
            .nanoClock(clock::get)
            .build();

    assertEquals("tok_1", client.token());
    // expires_in 100 → margin min(60, 10) = 10s → refresh at 90s. Just inside: still cached.
    clock.addAndGet(Duration.ofSeconds(89).toNanos());
    assertEquals("tok_1", client.token());
    assertEquals(1, exchanges.get(), "must not re-exchange inside the refresh margin");
    // At the margin: re-exchanged, well before the token actually expires at 100s.
    clock.addAndGet(Duration.ofSeconds(1).toNanos());
    assertEquals("tok_2", client.token());
    assertEquals("tok_2", client.token());
    assertEquals(2, exchanges.get(), "exactly one re-exchange at the refresh margin");
    assertNoViolations();
  }

  @Test
  void refreshMarginIsCappedAtSixtySeconds() {
    AtomicInteger exchanges = new AtomicInteger();
    server.createContext(
        "/oauth/token",
        exchange ->
            respond(
                exchange,
                200,
                "{\"access_token\":\"tok_"
                    + exchanges.incrementAndGet()
                    + "\",\"expires_in\":900}"));

    AtomicLong clock = new AtomicLong();
    IntygaClient client =
        IntygaClient.builder()
            .gatewayUrl(baseUrl())
            .clientId("cid")
            .clientSecret("secret")
            .nanoClock(clock::get)
            .build();

    assertEquals("tok_1", client.token());
    // 900/10 = 90s would refresh at 810s; the cap of 60s means 840s. Pin the cap, not the tenth.
    clock.addAndGet(Duration.ofSeconds(839).toNanos());
    assertEquals("tok_1", client.token());
    clock.addAndGet(Duration.ofSeconds(1).toNanos());
    assertEquals("tok_2", client.token());
    assertEquals(2, exchanges.get());
    assertNoViolations();
  }

  @Test
  void unauthorizedOnExchangedTokenRetriesOnceWithFreshExchange() {
    AtomicInteger exchanges = new AtomicInteger();
    AtomicInteger authorizeCalls = new AtomicInteger();
    server.createContext(
        "/oauth/token",
        exchange ->
            respond(
                exchange,
                200,
                "{\"access_token\":\"tok_"
                    + exchanges.incrementAndGet()
                    + "\",\"expires_in\":3600}"));
    server.createContext(
        "/authorize",
        exchange -> {
          int call = authorizeCalls.incrementAndGet();
          String auth = exchange.getRequestHeaders().getFirst("Authorization");
          if (call == 1) {
            // The gateway's clock says the first token is already dead (skew, a shortened TTL).
            expect("Bearer tok_1".equals(auth), "first authorize must carry the first exchange");
            respond(exchange, 401, "{\"error\":\"Invalid token: ERR_JWT_EXPIRED\"}");
          } else {
            expect(
                "Bearer tok_2".equals(auth), "retry must carry a FRESH exchange, not the old one");
            respond(exchange, 200, "{\"nonce\":\"n_retry\",\"status\":\"PENDING\"}");
          }
        });

    IntygaClient client =
        IntygaClient.builder().gatewayUrl(baseUrl()).clientId("cid").clientSecret("secret").build();
    AuthorizeResponse r = client.authorize("x", wipeOptions());

    assertEquals("n_retry", r.nonce());
    assertEquals(2, exchanges.get(), "401 must evict the cache and exchange again");
    assertEquals(2, authorizeCalls.get(), "the refused call is retried once");
    assertNoViolations();
  }

  @Test
  void persistentUnauthorizedIsRetriedExactlyOnceThenThrown() {
    AtomicInteger exchanges = new AtomicInteger();
    AtomicInteger authorizeCalls = new AtomicInteger();
    server.createContext(
        "/oauth/token",
        exchange ->
            respond(
                exchange,
                200,
                "{\"access_token\":\"tok_"
                    + exchanges.incrementAndGet()
                    + "\",\"expires_in\":900}"));
    server.createContext(
        "/authorize",
        exchange -> {
          authorizeCalls.incrementAndGet();
          respond(exchange, 401, "{\"error\":\"revoked\"}");
        });

    IntygaClient client =
        IntygaClient.builder().gatewayUrl(baseUrl()).clientId("cid").clientSecret("secret").build();
    GatewayRefusedException refused =
        assertThrows(GatewayRefusedException.class, () -> client.authorize("x", wipeOptions()));

    // A revoked key must surface as the refusal it is, not loop: one retry, then the 401 is thrown.
    assertEquals(401, refused.status());
    assertEquals(2, authorizeCalls.get(), "exactly one retry");
    assertEquals(2, exchanges.get(), "exactly one re-exchange");
    assertNoViolations();
  }

  @Test
  void explicitTokenIsNeverReExchanged() {
    AtomicInteger exchanges = new AtomicInteger();
    AtomicInteger authorizeCalls = new AtomicInteger();
    server.createContext(
        "/oauth/token",
        exchange -> {
          exchanges.incrementAndGet();
          respond(exchange, 200, "{\"access_token\":\"tok_never\",\"expires_in\":900}");
        });
    server.createContext(
        "/authorize",
        exchange -> {
          authorizeCalls.incrementAndGet();
          expect(
              "Bearer preminted".equals(exchange.getRequestHeaders().getFirst("Authorization")),
              "explicit token must be sent as given");
          respond(exchange, 401, "{\"error\":\"Invalid token: ERR_JWT_EXPIRED\"}");
        });

    IntygaClient client =
        IntygaClient.builder()
            .gatewayUrl(baseUrl())
            .token("preminted")
            // Credentials present too: they must still be ignored when an explicit token is set.
            .clientId("cid")
            .clientSecret("secret")
            .build();
    GatewayRefusedException refused =
        assertThrows(GatewayRefusedException.class, () -> client.authorize("x", wipeOptions()));

    assertEquals(401, refused.status());
    assertEquals(0, exchanges.get(), "there is nothing to re-exchange behind an explicit token");
    assertEquals(1, authorizeCalls.get(), "an explicit token is not retried");
    assertNoViolations();
  }

  @Test
  void consumeRebindingSendsBody() {
    // Strict body assertion, deliberately. The Go suite once used a mock that accepted any body
    // while production returned 400 on every call — single-use redemption was unreachable and the
    // tests stayed green.
    server.createContext(
        "/authorize/verify",
        exchange -> {
          JsonNode body = JSON.readTree(readBody(exchange));
          expect("n_1".equals(body.path("nonce").asText()), "consume: nonce missing");
          expect(
              "prod-db-cluster-01".equals(body.path("target").asText()),
              "consume: target missing");
          expect(
              "wipe_production".equals(body.path("actionType").asText()),
              "consume: actionType missing");
          expect(
              "prod-db-1".equals(body.path("params").path("database").asText()),
              "consume: params missing");
          respond(exchange, 200, "{\"ok\":true}");
        });

    IntygaClient client = IntygaClient.builder().gatewayUrl(baseUrl()).token("t").build();
    ConsumeResult r =
        client.consume(
            "n_1", "prod-db-cluster-01", "wipe_production", Map.of("database", "prod-db-1"));

    assertTrue(r.ok());
    assertNoViolations();
  }

  @Test
  void targetIsRequired() {
    // Point at a closed port: validation must reject before any I/O happens.
    IntygaClient client =
        IntygaClient.builder().gatewayUrl("http://127.0.0.1:1").token("t").build();

    IllegalArgumentException noTarget =
        assertThrows(
            IllegalArgumentException.class,
            () -> client.authorize("x", AuthorizeOptions.builder().build()));
    assertTrue(noTarget.getMessage().contains("target is required"));

    IllegalArgumentException blankTarget =
        assertThrows(
            IllegalArgumentException.class,
            () -> client.consume("n", "  ", "wipe_production", Map.of()));
    assertTrue(blankTarget.getMessage().contains("target"));
  }

  @Test
  void authorizeSendsTarget() {
    server.createContext(
        "/authorize",
        exchange -> {
          JsonNode body = JSON.readTree(readBody(exchange));
          expect(
              "prod-payments".equals(body.path("target").asText()),
              "authorize: target missing from body");
          respond(exchange, 200, "{\"nonce\":\"n_t\",\"status\":\"PENDING\"}");
        });

    IntygaClient client = IntygaClient.builder().gatewayUrl(baseUrl()).token("t").build();
    AuthorizeResponse r =
        client.authorize("x", AuthorizeOptions.builder().target("prod-payments").build());

    assertEquals("n_t", r.nonce());
    assertEquals(ApprovalStatus.PENDING, r.status());
    assertNoViolations();
  }

  @Test
  void requireApprovalCopiesOptionsAndSendsTtl() {
    // Regression for the field-drop bug the toBuilder() copy pattern exists for: everything the
    // caller set must reach the wire alongside the derived TTL. No other port tests this today.
    server.createContext(
        "/authorize",
        exchange -> {
          JsonNode body = JSON.readTree(readBody(exchange));
          expect(
              "prod-db-cluster-01".equals(body.path("target").asText()),
              "requireApproval dropped target");
          expect(
              "wipe_production".equals(body.path("actionType").asText()),
              "requireApproval dropped actionType");
          expect(
              "prod-db-1".equals(body.path("params").path("database").asText()),
              "requireApproval dropped params");
          expect(body.path("timeout").asInt() == 5, "requireApproval must send TTL = ceil(timeout)");
          respond(exchange, 200, "{\"nonce\":\"n_2\",\"status\":\"PENDING\"}");
        });
    server.createContext(
        "/authorize/n_2", exchange -> respond(exchange, 200, "{\"status\":\"APPROVED\"}"));

    IntygaClient client = IntygaClient.builder().gatewayUrl(baseUrl()).token("t").build();
    ApprovalResult r =
        client.requireApproval(
            "x",
            RequireApprovalOptions.builder()
                .authorize(wipeOptions())
                .timeout(Duration.ofSeconds(5))
                .interval(Duration.ofMillis(10))
                .build());

    assertEquals(ApprovalStatus.APPROVED, r.status());
    assertNoViolations();
  }

  @Test
  void deadlineHitReturnsExpired() {
    server.createContext(
        "/authorize",
        exchange -> respond(exchange, 200, "{\"nonce\":\"n_3\",\"status\":\"PENDING\"}"));
    server.createContext(
        "/authorize/n_3", exchange -> respond(exchange, 200, "{\"status\":\"PENDING\"}"));

    IntygaClient client = IntygaClient.builder().gatewayUrl(baseUrl()).token("t").build();
    ApprovalResult r =
        client.requireApproval(
            "x",
            RequireApprovalOptions.builder()
                .authorize(wipeOptions())
                .timeout(Duration.ofMillis(300))
                .interval(Duration.ofMillis(50))
                .build());

    // Expiry is an answer, not an error — the nonce still identifies which challenge went unanswered.
    assertEquals(ApprovalStatus.EXPIRED, r.status());
    assertEquals("n_3", r.nonce());
    assertNoViolations();
  }
}
