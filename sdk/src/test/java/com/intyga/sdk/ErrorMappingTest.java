package com.intyga.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The typed-exception surface, ported from sdk-python's errors model. The refusal-vs-outage split
 * is load-bearing (DIV &#167;5a: the offline path exists only for "could not ask"), so these tests
 * pin which exception type each failure mode produces — not just that "something throws".
 */
class ErrorMappingTest {

  private HttpServer server;

  @BeforeEach
  void setUp() throws IOException {
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

  private void respond(com.sun.net.httpserver.HttpExchange exchange, int status, String json)
      throws IOException {
    byte[] out = json.getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(status, out.length);
    exchange.getResponseBody().write(out);
    exchange.close();
  }

  @Test
  void gatewayRefusedCarriesStatusAndBody() {
    server.createContext(
        "/authorize", exchange -> respond(exchange, 403, "{\"error\":\"policy\"}"));

    IntygaClient client = IntygaClient.builder().gatewayUrl(baseUrl()).token("t").build();
    GatewayRefusedException e =
        assertThrows(
            GatewayRefusedException.class,
            () ->
                client.authorize(
                    "x", AuthorizeOptions.builder().target("prod-db-cluster-01").build()));

    assertEquals(403, e.status());
    assertEquals("POST /authorize failed: 403 {\"error\":\"policy\"}", e.getMessage());
  }

  @Test
  void gatewayUnreachableOnConnectFailure() {
    IntygaClient client =
        IntygaClient.builder().gatewayUrl("http://127.0.0.1:1").token("t").build();

    assertThrows(GatewayUnreachableException.class, () -> client.status("n"));
  }

  @Test
  void missingCredentialsIsATypedError() {
    IntygaClient client = IntygaClient.builder().gatewayUrl("http://127.0.0.1:1").build();

    IntygaException e = assertThrows(IntygaException.class, client::token);
    assertTrue(e.getMessage().contains("provide token, or clientId + clientSecret"));
  }

  @Test
  void requireApprovalOrThrowThrowsOnDenied() {
    server.createContext(
        "/authorize",
        exchange -> respond(exchange, 200, "{\"nonce\":\"n_d\",\"status\":\"PENDING\"}"));
    server.createContext(
        "/authorize/n_d", exchange -> respond(exchange, 200, "{\"status\":\"DENIED\"}"));

    IntygaClient client = IntygaClient.builder().gatewayUrl(baseUrl()).token("t").build();
    ApprovalRefusedException e =
        assertThrows(
            ApprovalRefusedException.class,
            () ->
                client.requireApprovalOrThrow(
                    "Wire 5000 EUR to acme",
                    RequireApprovalOptions.builder()
                        .authorize(
                            AuthorizeOptions.builder()
                                .target("agent-payments-prod")
                                .actionType("wire_transfer")
                                .params(Map.of("amount", 5000, "to", "acme"))
                                .build())
                        .interval(Duration.ofMillis(10))
                        .build()));

    assertEquals(ApprovalStatus.DENIED, e.status());
    assertTrue(e.getMessage().contains("wire_transfer"));
  }
}
