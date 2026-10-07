package com.intyga.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.intyga.sdk.offline.OfflineApproval;
import com.intyga.sdk.offline.OfflineApprovalOptions;
import com.intyga.verify.ApprovalReceipt;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The client's offline fallback is reachable ONLY when the gateway could not be asked, and reports
 * OFFLINE_APPROVED; reconciliation clears a record only on a 2xx. An in-process {@link HttpServer},
 * as in {@link IntygaClientTest}; handler-side mismatches are collected and asserted afterwards.
 */
class OfflineClientTest {

  private static final ObjectMapper JSON = new ObjectMapper();

  @TempDir Path tmp;

  private HttpServer server;
  private ConcurrentLinkedQueue<String> violations;
  private AtomicInteger collected;
  private Path bundleDir;

  @BeforeEach
  void setUp() throws IOException {
    violations = new ConcurrentLinkedQueue<>();
    collected = new AtomicInteger();
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.start();
    bundleDir = OfflineApprovalTest.bundleDir(tmp);
  }

  @AfterEach
  void tearDown() {
    server.stop(0);
    assertEquals(List.of(), List.copyOf(violations));
  }

  private String baseUrl() {
    return "http://127.0.0.1:" + server.getAddress().getPort();
  }

  private IntygaClient client() {
    return IntygaClient.builder().gatewayUrl(baseUrl()).token("t").build();
  }

  private static void respond(HttpExchange exchange, int status, String body) throws IOException {
    byte[] out = body.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("content-type", "application/json");
    exchange.sendResponseHeaders(status, out.length);
    exchange.getResponseBody().write(out);
    exchange.close();
  }

  private OfflineApprovalOptions offline(boolean sign) {
    return OfflineApprovalOptions.builder()
        .bundleDir(bundleDir)
        .requesterDid("did:intyga:service:oncall")
        .asOf(OfflineApprovalTest.AS_OF)
        .warn(m -> {})
        .collectSignatures(ch -> {
          collected.incrementAndGet();
          if (!"db.restart".equals(ch.actionType()) || !OfflineApprovalTest.TARGET.equals(ch.target())) {
            violations.add("challenge built for the wrong action: " + ch.actionType() + " on " + ch.target());
          }
          return sign ? OfflineApprovalTest.aliceAndBob(ch.canonicalPayload()) : List.of();
        })
        .build();
  }

  private static AuthorizeOptions restart() {
    return AuthorizeOptions.builder()
        .target(OfflineApprovalTest.TARGET)
        .actionType("db.restart")
        .params(OfflineApprovalTest.PARAMS)
        .build();
  }

  private RequireApprovalOptions.Builder wait(AuthorizeOptions auth) {
    return RequireApprovalOptions.builder()
        .authorize(auth)
        .timeout(Duration.ofSeconds(10))
        .interval(Duration.ofMillis(1));
  }

  private void assertOfflineApproved(ApprovalResult r) {
    assertEquals(ApprovalStatus.OFFLINE_APPROVED, r.status());
    assertTrue(r.nonce().startsWith("off_"), r.nonce());
    assertEquals(1, collected.get());
    ApprovalReceipt receipt = ApprovalReceipt.parse(r.receipt());
    assertEquals(OfflineApprovalTest.TARGET, receipt.target());
    assertEquals(2, receipt.signatures().size());
    assertEquals(1, OfflineApproval.pendingApprovals(bundleDir, null).size());
  }

  // --- routed offline: the gateway could not be asked ---------------------------------------------

  @Test
  void a5xxWhenRaisingTheChallengeFallsBack() {
    server.createContext("/authorize", e -> respond(e, 503, "{\"error\":\"restarting\"}"));
    assertOfflineApproved(client().requireApproval("Restart the primary database",
        wait(restart()).offline(offline(true)).build()));
  }

  @Test
  void aConnectionFailureFallsBack() {
    String url = baseUrl();
    server.stop(0);
    IntygaClient c = IntygaClient.builder().gatewayUrl(url).token("t").build();
    assertOfflineApproved(c.requireApproval("Restart the primary database",
        wait(restart()).offline(offline(true)).build()));
  }

  @Test
  void repeatedPollingFailuresFallBack() {
    AtomicInteger polls = new AtomicInteger();
    server.createContext("/authorize", e -> respond(e, 200, "{\"nonce\":\"n1\",\"status\":\"PENDING\"}"));
    server.createContext("/authorize/n1", e -> {
      polls.incrementAndGet();
      respond(e, 502, "bad gateway");
    });
    assertOfflineApproved(client().requireApproval("Restart the primary database",
        wait(restart()).offline(offline(true)).build()));
    assertEquals(5, polls.get());
  }

  // --- never routed offline: a verdict, or not an outage at all -------------------------------------

  @Test
  void a4xxIsAVerdictNotAnOutage() {
    server.createContext("/authorize", e -> respond(e, 403, "{\"error\":\"RequirementUnavailable\"}"));
    GatewayRefusedException e = assertThrows(GatewayRefusedException.class, () -> client().requireApproval(
        "Restart the primary database", wait(restart()).offline(offline(true)).build()));
    assertEquals(403, e.status());
    assertEquals(0, collected.get());
  }

  @Test
  void repeated4xxPollsAreNotAnOutage() {
    server.createContext("/authorize", e -> respond(e, 200, "{\"nonce\":\"n2\",\"status\":\"PENDING\"}"));
    server.createContext("/authorize/n2", e -> respond(e, 404, "{}"));
    GatewayRefusedException e = assertThrows(GatewayRefusedException.class, () -> client().requireApproval(
        "Restart the primary database", wait(restart()).offline(offline(true)).build()));
    assertEquals(404, e.status());
    assertEquals(0, collected.get());
  }

  @Test
  void aStreakThatIncludesARefusalIsNotAnOutage() {
    AtomicInteger polls = new AtomicInteger();
    server.createContext("/authorize", e -> respond(e, 200, "{\"nonce\":\"n5\",\"status\":\"PENDING\"}"));
    server.createContext("/authorize/n5", e -> respond(e, polls.incrementAndGet() == 1 ? 404 : 503, "{}"));
    GatewayRefusedException e = assertThrows(GatewayRefusedException.class, () -> client().requireApproval(
        "Restart the primary database", wait(restart()).offline(offline(true)).build()));
    // The streak's first refusal, not its last error: [404, 503, 503, 503, 503] reports the 404.
    assertEquals(404, e.status());
    assertEquals(5, polls.get());
    assertEquals(0, collected.get());
  }

  /**
   * A raw HTTP/1.1 server driven by a script, for what {@link HttpServer} cannot do deterministically:
   * drop a connection before any response, or send headers and break the body off mid-read. One
   * request per connection ({@code Connection: close}); calls are counted per path.
   */
  static final class ScriptedGateway implements AutoCloseable {
    static final String DROP = "DROP";

    /** A full response. */
    static String reply(int status, String body) {
      return "HTTP/1.1 " + status + " X\r\ncontent-type: application/json\r\ncontent-length: "
          + body.getBytes(StandardCharsets.UTF_8).length + "\r\nconnection: close\r\n\r\n" + body;
    }

    /** Headers promising 1000 bytes, then 9 of them, then the connection closes. */
    static String brokenBody(int status) {
      return "HTTP/1.1 " + status + " X\r\ncontent-type: application/json\r\ncontent-length: 1000"
          + "\r\nconnection: close\r\n\r\n{\"nonce\":";
    }

    private final java.net.ServerSocket socket;
    private final java.util.function.BiFunction<String, Integer, String> script;
    private final Map<String, AtomicInteger> calls = new java.util.concurrent.ConcurrentHashMap<>();

    ScriptedGateway(java.util.function.BiFunction<String, Integer, String> script) throws IOException {
      this.socket = new java.net.ServerSocket(0, 50, java.net.InetAddress.getLoopbackAddress());
      this.script = script;
      Thread t = new Thread(this::serve, "scripted-gateway");
      t.setDaemon(true);
      t.start();
    }

    String url() {
      return "http://127.0.0.1:" + socket.getLocalPort();
    }

    int calls(String path) {
      return calls.computeIfAbsent(path, k -> new AtomicInteger()).get();
    }

    private void serve() {
      while (!socket.isClosed()) {
        try (java.net.Socket conn = socket.accept()) {
          java.io.InputStream in = conn.getInputStream();
          String head = readHead(in);
          if (head == null) {
            continue;
          }
          String path = head.split(" ")[1];
          java.util.regex.Matcher len = java.util.regex.Pattern
              .compile("(?im)^content-length:\\s*(\\d+)").matcher(head);
          if (len.find()) {
            in.readNBytes(Integer.parseInt(len.group(1)));
          }
          int n = calls.computeIfAbsent(path, k -> new AtomicInteger()).incrementAndGet();
          String action = script.apply(path, n);
          if (!DROP.equals(action)) {
            conn.getOutputStream().write(action.getBytes(StandardCharsets.UTF_8));
            conn.getOutputStream().flush();
          }
        } catch (IOException e) {
          // closed, or the client gave up on this connection
        }
      }
    }

    private static String readHead(java.io.InputStream in) throws IOException {
      StringBuilder b = new StringBuilder();
      int c;
      while ((c = in.read()) != -1) {
        b.append((char) c);
        if (b.length() >= 4 && b.substring(b.length() - 4).equals("\r\n\r\n")) {
          return b.toString();
        }
      }
      return null;
    }

    @Override
    public void close() throws IOException {
      socket.close();
    }
  }

  private IntygaClient client(ScriptedGateway gw) {
    return IntygaClient.builder().gatewayUrl(gw.url()).token("t").build();
  }

  @Test
  void aStreakEndingInATransportFailureStillReportsTheRefusal() throws IOException {
    // [404, 502, 502, 502, no answer]: the gateway refused once, so the wait ends with THAT refusal —
    // not with the transport failure that happened to come last, and never offline.
    try (ScriptedGateway gw = new ScriptedGateway((path, n) -> {
      if (path.equals("/authorize")) {
        return ScriptedGateway.reply(200, "{\"nonce\":\"n6\",\"status\":\"PENDING\"}");
      }
      return n == 1 ? ScriptedGateway.reply(404, "{}") : n <= 4 ? ScriptedGateway.reply(502, "{}") : ScriptedGateway.DROP;
    })) {
      GatewayRefusedException e = assertThrows(GatewayRefusedException.class, () -> client(gw).requireApproval(
          "Restart the primary database", wait(restart()).offline(offline(true)).build()));
      assertEquals(404, e.status());
      assertTrue(gw.calls("/authorize/n6") >= 5);
      assertEquals(0, collected.get());
    }
  }

  @Test
  void aStreakOfTransportFailuresAndFiveHundredsFallsBack() throws IOException {
    try (ScriptedGateway gw = new ScriptedGateway((path, n) -> {
      if (path.equals("/authorize")) {
        return ScriptedGateway.reply(200, "{\"nonce\":\"n7\",\"status\":\"PENDING\"}");
      }
      return n <= 4 ? ScriptedGateway.reply(502, "{}") : ScriptedGateway.DROP;
    })) {
      assertOfflineApproved(client(gw).requireApproval("Restart the primary database",
          wait(restart()).offline(offline(true)).build()));
    }
  }

  @Test
  void aConnectionDroppedBeforeAnyResponseIsUnreachable() throws IOException {
    try (ScriptedGateway gw = new ScriptedGateway((path, n) -> ScriptedGateway.DROP)) {
      assertThrows(GatewayUnreachableException.class, () -> client(gw).status("n"));
    }
  }

  @Test
  void anUnreadableBodyIsAnAnswerNotAnOutage() throws IOException {
    // Headers arrived, then the body broke off: the gateway answered. Never routed offline.
    try (ScriptedGateway gw = new ScriptedGateway((path, n) -> ScriptedGateway.brokenBody(200))) {
      IntygaException direct = assertThrows(IntygaException.class, () -> client(gw).status("n"));
      assertFalse(direct instanceof GatewayUnreachableException, direct.toString());
      assertTrue(direct.getMessage().contains("could not be read"), direct.getMessage());

      IntygaException e = assertThrows(IntygaException.class, () -> client(gw).requireApproval(
          "Restart the primary database", wait(restart()).offline(offline(true)).build()));
      assertFalse(e instanceof GatewayUnreachableException, e.toString());
      assertFalse(e instanceof OfflineApprovalFailedException, e.toString());
      assertEquals(0, collected.get());
    }
    // …including five of them while polling.
    try (ScriptedGateway gw = new ScriptedGateway((path, n) -> path.equals("/authorize")
        ? ScriptedGateway.reply(200, "{\"nonce\":\"n8\",\"status\":\"PENDING\"}")
        : ScriptedGateway.brokenBody(503))) {
      IntygaException e = assertThrows(IntygaException.class, () -> client(gw).requireApproval(
          "Restart the primary database", wait(restart()).offline(offline(true)).build()));
      assertFalse(e instanceof GatewayUnreachableException, e.toString());
      assertEquals(5, gw.calls("/authorize/n8"));
      assertEquals(0, collected.get());
    }
  }

  @Test
  void deniedAndExpiredAreAnswers() {
    server.createContext("/authorize", e -> respond(e, 200, "{\"nonce\":\"n3\",\"status\":\"PENDING\"}"));
    server.createContext("/authorize/n3", e -> respond(e, 200, "{\"status\":\"DENIED\"}"));
    assertEquals(ApprovalStatus.DENIED, client().requireApproval("Restart the primary database",
        wait(restart()).offline(offline(true)).build()).status());

    server.createContext("/authorize/n4", e -> respond(e, 200, "{\"status\":\"PENDING\"}"));
    server.removeContext("/authorize");
    server.createContext("/authorize", e -> respond(e, 200, "{\"nonce\":\"n4\",\"status\":\"PENDING\"}"));
    assertEquals(ApprovalStatus.EXPIRED, client().requireApproval("Restart the primary database",
        wait(restart()).timeout(Duration.ofMillis(50)).offline(offline(true)).build()).status());
    assertEquals(0, collected.get());
  }

  @Test
  void aMalformedSuccessIsNotAnOutage() {
    server.createContext("/authorize", e -> respond(e, 200, "<html>captive portal</html>"));
    IntygaException e = assertThrows(IntygaException.class, () -> client().requireApproval(
        "Restart the primary database", wait(restart()).offline(offline(true)).build()));
    assertFalse(e instanceof GatewayUnreachableException);
    assertEquals(0, collected.get());
  }

  @Test
  void agentContinuityNeverFallsBack() {
    server.createContext("/authorize", e -> respond(e, 503, "{}"));
    AuthorizeOptions agent = restart().toBuilder().agentContext(Map.of("nbf", "x")).build();
    IntygaException e = assertThrows(IntygaException.class, () -> client().requireApproval(
        "Restart the primary database", wait(agent).offline(offline(true)).build()));
    assertTrue(e.getMessage().contains("agent continuity"), e.getMessage());
    assertEquals(0, collected.get());
  }

  @Test
  void withoutOfflineOptionsAnOutageThrowsAsBefore() {
    server.createContext("/authorize", e -> respond(e, 503, "{}"));
    GatewayRefusedException e = assertThrows(GatewayRefusedException.class, () -> client().requireApproval(
        "Restart the primary database", wait(restart()).build()));
    assertEquals(503, e.status());
  }

  @Test
  void aFailedFallbackSaysSoAndKeepsTheCause() {
    server.createContext("/authorize", e -> respond(e, 503, "{}"));
    OfflineApprovalFailedException e = assertThrows(OfflineApprovalFailedException.class, () -> client()
        .requireApproval("Restart the primary database", wait(restart()).offline(offline(false)).build()));
    assertTrue(e.reason().contains("no signatures were collected"), e.reason());
    assertInstanceOf(GatewayRefusedException.class, e.getCause());
    assertEquals(List.of(), OfflineApproval.pendingApprovals(bundleDir, null));
  }

  @Test
  void requireApprovalOrThrowRefusesOfflineOptions() {
    assertThrows(IllegalArgumentException.class, () -> client().requireApprovalOrThrow(
        "Restart the primary database", wait(restart()).offline(offline(true)).build()));
  }

  // --- reconciliation --------------------------------------------------------------------------------

  @Test
  void reconcileClearsOnlyOnA2xx() throws IOException {
    server.createContext("/authorize", e -> respond(e, 503, "{}"));
    ApprovalResult r = client().requireApproval("Restart the primary database",
        wait(restart()).offline(offline(true)).build());
    assertEquals(ApprovalStatus.OFFLINE_APPROVED, r.status());

    AtomicInteger status = new AtomicInteger(500);
    List<JsonNode> bodies = new ArrayList<>();
    server.createContext("/offline-approval/reconcile", e -> {
      if (!"POST".equals(e.getRequestMethod())) {
        violations.add("reconcile must POST, got " + e.getRequestMethod());
      }
      if (!"Bearer t".equals(e.getRequestHeaders().getFirst("authorization"))) {
        violations.add("reconcile must use the client's ordinary authentication");
      }
      synchronized (bodies) {
        bodies.add(JSON.readTree(e.getRequestBody().readAllBytes()));
      }
      respond(e, status.get(), status.get() == 500 ? "{\"error\":\"down\"}" : "{\"ok\":true}");
    });

    ReconcileResult first = client().reconcileOfflineApprovals(bundleDir);
    assertEquals(new ReconcileResult(0, 1, first.reasons()), first);
    assertTrue(first.reasons().get(0).startsWith(r.nonce() + ": 500"), first.reasons().toString());
    assertEquals(1, OfflineApproval.pendingApprovals(bundleDir, null).size(), "kept after a 500");

    status.set(200);
    ReconcileResult second = client().reconcileOfflineApprovals(bundleDir);
    assertEquals(new ReconcileResult(1, 0, List.of()), second);
    assertEquals(List.of(), OfflineApproval.pendingApprovals(bundleDir, null), "cleared after a 2xx");

    JsonNode body = bodies.get(1);
    assertEquals(r.nonce(), body.get("nonce").textValue());
    assertEquals(OfflineApprovalTest.TARGET, body.get("target").textValue());
    assertEquals("db.restart", body.get("actionType").textValue());
    assertEquals("Restart the primary database", body.get("display").textValue());
    assertNotNull(body.get("usedAt").textValue());
    assertEquals(r.receipt().get("canonicalPayload"), body.get("receipt").get("canonicalPayload"));
    assertFalse(body.has("delegationNonce"), "omitted when no delegation applied, as JSON.stringify omits undefined");
  }

  @Test
  void reconcileKeepsRecordsWhenTheGatewayIsUnreachable() {
    server.createContext("/authorize", e -> respond(e, 503, "{}"));
    client().requireApproval("Restart the primary database", wait(restart()).offline(offline(true)).build());
    String url = baseUrl();
    server.stop(0);
    ReconcileResult r = IntygaClient.builder().gatewayUrl(url).token("t").build().reconcileOfflineApprovals(bundleDir);
    assertEquals(0, r.reported());
    assertEquals(1, r.failed());
    assertEquals(1, OfflineApproval.pendingApprovals(bundleDir, null).size());
  }

  @Test
  void reconcileCountsAnUnreadableRecordInsteadOfSkippingIt() throws IOException {
    server.createContext("/offline-approval/reconcile", e -> respond(e, 200, "{}"));
    java.nio.file.Path pending = java.nio.file.Files.createDirectories(bundleDir.resolve(".pending"));
    java.nio.file.Files.writeString(pending.resolve("off_broken.json"), "{truncated");
    ReconcileResult r = client().reconcileOfflineApprovals(bundleDir);
    assertEquals(0, r.reported());
    assertEquals(1, r.failed());
    assertEquals(List.of("off_broken.json: unreadable pending record — report it by hand"), r.reasons());
    assertTrue(java.nio.file.Files.exists(pending.resolve("off_broken.json")), "left for a human");
  }

  @Test
  void reconcileWithoutCredentialsThrowsUpFront() {
    IntygaClient noCreds = IntygaClient.builder().gatewayUrl(baseUrl()).build();
    assertThrows(IntygaException.class, () -> noCreds.reconcileOfflineApprovals(bundleDir));
  }
}
