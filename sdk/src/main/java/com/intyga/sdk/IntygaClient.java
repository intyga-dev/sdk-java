package com.intyga.sdk;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Talks to an Intyga gateway. Blocking, like the Go and Rust clients — wrap it in your own executor
 * (or a virtual thread) if you need async. Construct with {@link #builder()}; construction performs
 * no network I/O.
 */
public final class IntygaClient {

  // Not configurable per instance: no single gateway round-trip should take longer, and an
  // unbounded default request is how a poll loop hangs forever on a half-dead connection.
  private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);

  // How many back-to-back polling failures before requireApproval declares the gateway unreachable.
  private static final int MAX_POLL_ERRORS = 5;

  // Tree-model + own-final-records only. Polymorphic default typing (Jackson's CVE surface) is
  // never enabled. Unknown fields are ignored so a gateway that grows a response field does not
  // break deployed clients.
  private static final ObjectMapper JSON =
      new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

  private final String gatewayUrl;
  private final String token;
  private final String clientId;
  private final String clientSecret;
  private final HttpClient http;

  // The benign race (two threads exchanging concurrently, last write wins) matches the Go client.
  private volatile String cachedToken;

  private IntygaClient(Builder b) {
    if (b.gatewayUrl == null || b.gatewayUrl.isBlank()) {
      throw new IllegalArgumentException("gatewayUrl is required");
    }
    String url = b.gatewayUrl;
    while (url.endsWith("/")) {
      url = url.substring(0, url.length() - 1);
    }
    this.gatewayUrl = url;
    this.token = b.token;
    this.clientId = b.clientId;
    this.clientSecret = b.clientSecret;
    this.http =
        b.httpClient != null
            ? b.httpClient
            : HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(30)).build();
  }

  public static Builder builder() {
    return new Builder();
  }

  /**
   * Resolves a bearer token: the provided one, a cached exchange, or a fresh client-credentials
   * exchange (HTTP Basic at {@code POST /oauth/token}). The exchanged token is cached for the
   * client's lifetime — the gateway's {@code expires_in} is documented as unreliable, so no
   * proactive refresh is attempted; a 401 on a later call surfaces as {@link
   * GatewayRefusedException}.
   */
  public String token() {
    if (token != null && !token.isEmpty()) {
      return token;
    }
    String cached = cachedToken;
    if (cached != null) {
      return cached;
    }
    if (clientId == null || clientId.isEmpty() || clientSecret == null || clientSecret.isEmpty()) {
      throw new IntygaException("provide token, or clientId + clientSecret");
    }
    String basic =
        Base64.getEncoder()
            .encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
    HttpRequest req =
        HttpRequest.newBuilder(URI.create(gatewayUrl + "/oauth/token"))
            .timeout(REQUEST_TIMEOUT)
            .header("authorization", "Basic " + basic)
            .POST(HttpRequest.BodyPublishers.noBody())
            .build();
    HttpResponse<String> res = send(req);
    if (res.statusCode() < 200 || res.statusCode() >= 300) {
      throw new GatewayRefusedException(
          res.statusCode(), "token exchange failed: " + res.statusCode() + " " + res.body());
    }
    String exchanged = readJson(res.body(), TokenResponse.class, "token").accessToken();
    cachedToken = exchanged;
    return exchanged;
  }

  /** Creates an approval challenge and returns its nonce and initial status. */
  public AuthorizeResponse authorize(String actionDescription, AuthorizeOptions options) {
    requireTarget(
        options.target(),
        "target is required (DIV Target Isolation): "
            + "name the relying party / execution environment this approval is bound to");
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("target", options.target());
    body.put("actionDescription", actionDescription);
    // Empty string rather than JSON null when unset — the shape the Go client sends and the
    // gateway's schema accepts.
    body.put("actionType", options.actionType() == null ? "" : options.actionType());
    body.put("params", options.params());
    if (options.timeoutSeconds() > 0) {
      body.put("timeout", options.timeoutSeconds());
    }
    return doJson("POST", "/authorize", body, AuthorizeResponse.class, "authorize");
  }

  /** Polls a challenge's current state (non-blocking). */
  public ApprovalResult status(String nonce) {
    return doJson("GET", "/authorize/" + pathEscape(nonce), null, ApprovalResult.class, "status");
  }

  /**
   * Execution-time re-binding: after APPROVED, call this immediately before running the action so
   * the gateway confirms the approved signature matches the exact instruction and marks it
   * single-use. The same credential that called {@link #authorize} must consume — the gateway binds
   * the requester's identity from its token, never from the body.
   *
   * <p>{@code target} is REQUIRED by the gateway's schema. Omitting it was a 400 on every call in
   * an earlier Go client, which made single-use redemption unreachable entirely: the challenge
   * stayed APPROVED rather than CONSUMED, and stayed replayable by any holder of the same token
   * until it expired naturally.
   */
  public ConsumeResult consume(
      String nonce, String target, String actionType, Map<String, Object> params) {
    requireTarget(target, "consume requires the same target the approval was bound to");
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("nonce", nonce);
    body.put("target", target);
    body.put("actionType", actionType == null ? "" : actionType);
    body.put("params", params == null ? Map.of() : params);
    return doJson("POST", "/authorize/verify", body, ConsumeResult.class, "consume");
  }

  /**
   * The core zero-trust gate: call it immediately before a high-risk action. Creates the challenge
   * and blocks until the human approves/denies with their passkey, the wait times out, or the
   * gateway becomes unreachable.
   *
   * <p>A timed-out wait RETURNS a result with status {@link ApprovalStatus#EXPIRED} — expiry is an
   * answer, not an error. See {@link #requireApprovalOrThrow} for the throwing form.
   */
  public ApprovalResult requireApproval(String actionDescription, RequireApprovalOptions options) {
    Duration timeout = options.timeout();
    Duration interval = options.interval();

    // Forward the caller's options wholesale and override only the timeout (ceiled to seconds, so
    // the challenge cannot outlive the wait). Rebuilding options field-by-field silently drops
    // anything added to AuthorizeOptions later — which is how target would have gone missing here
    // even after being made required.
    AuthorizeOptions authOptions =
        options.authorize().toBuilder()
            .timeoutSeconds((int) ((timeout.toMillis() + 999) / 1000))
            .build();

    AuthorizeResponse authRes = authorize(actionDescription, authOptions);
    String nonce = authRes.nonce();

    long deadlineNanos = System.nanoTime() + timeout.toNanos();
    int consecutiveErrors = 0;
    while (true) {
      // A human approval can outlast a transient 502 or socket hangup — don't discard the whole
      // wait over one bad poll. Only give up once the gateway looks genuinely unreachable, and
      // rethrow the typed exception so refusal-vs-outage survives to the caller.
      try {
        ApprovalResult r = status(nonce);
        consecutiveErrors = 0;
        if (r.status() != ApprovalStatus.PENDING) {
          return r.withNonce(nonce);
        }
      } catch (IntygaException e) {
        consecutiveErrors++;
        if (consecutiveErrors >= MAX_POLL_ERRORS) {
          throw e;
        }
      }

      if (System.nanoTime() > deadlineNanos) {
        return new ApprovalResult(ApprovalStatus.EXPIRED, null, null, nonce);
      }
      try {
        Thread.sleep(interval.toMillis());
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new GatewayUnreachableException("interrupted while waiting for approval", e);
      }
    }
  }

  /**
   * {@link #requireApproval}, except any outcome other than APPROVED throws {@link
   * ApprovalRefusedException}. This is the one-line gate for framework tool methods and request
   * handlers: a refusal propagates as an exception and can never be mistaken for a result. On
   * success the returned result still carries the nonce and receipt, so the caller can hand the
   * receipt to an offline verifier and then {@link #consume} it.
   */
  public ApprovalResult requireApprovalOrThrow(
      String actionDescription, RequireApprovalOptions options) {
    ApprovalResult r = requireApproval(actionDescription, options);
    if (r.status() != ApprovalStatus.APPROVED) {
      String actionType = options.authorize().actionType();
      String what = actionType == null || actionType.isEmpty() ? actionDescription : actionType;
      throw new ApprovalRefusedException(
          r.status(), "'" + what + "' was not approved: " + r.status());
    }
    return r;
  }

  /**
   * Public witness lookup: has this document hash been signed, by whom, and when? The endpoint is
   * public, but the auth header is sent anyway to keep behaviour uniform with the other methods
   * (and the Go/Rust clients).
   *
   * <p>This asks the GATEWAY what it recorded — it does NOT verify a receipt's signature. For that,
   * use {@code com.intyga.verify.Verify.verifyApprovalReceipt}, which trusts nothing the gateway
   * says.
   */
  public WitnessLookupResult verify(String documentHash) {
    return doJson(
        "GET", "/verify/" + pathEscape(documentHash), null, WitnessLookupResult.class, "verify");
  }

  private static void requireTarget(String target, String message) {
    if (target == null || target.trim().isEmpty()) {
      throw new IllegalArgumentException(message);
    }
  }

  // URLEncoder is form-encoding: it emits "+" for space, which a path segment reads as a literal
  // plus. Undo that one divergence to get RFC 3986 path-segment escaping.
  private static String pathEscape(String segment) {
    return URLEncoder.encode(segment, StandardCharsets.UTF_8).replace("+", "%20");
  }

  private <T> T doJson(String method, String path, Object body, Class<T> type, String op) {
    String bearer = token();
    HttpRequest.Builder builder =
        HttpRequest.newBuilder(URI.create(gatewayUrl + path))
            .timeout(REQUEST_TIMEOUT)
            .header("authorization", "Bearer " + bearer);
    if (body != null) {
      builder
          .header("content-type", "application/json")
          .method(method, HttpRequest.BodyPublishers.ofString(writeJson(body)));
    } else {
      builder.method(method, HttpRequest.BodyPublishers.noBody());
    }
    HttpResponse<String> res = send(builder.build());
    if (res.statusCode() < 200 || res.statusCode() >= 300) {
      throw new GatewayRefusedException(
          res.statusCode(),
          method + " " + path + " failed: " + res.statusCode() + " " + res.body());
    }
    return readJson(res.body(), type, op);
  }

  private HttpResponse<String> send(HttpRequest req) {
    try {
      return http.send(req, HttpResponse.BodyHandlers.ofString());
    } catch (IOException e) {
      throw new GatewayUnreachableException(
          req.method() + " " + req.uri() + ": gateway unreachable: " + e.getMessage(), e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new GatewayUnreachableException("interrupted while calling the gateway", e);
    }
  }

  private static String writeJson(Object value) {
    try {
      return JSON.writeValueAsString(value);
    } catch (IOException e) {
      throw new IntygaException("could not serialize request body: " + e.getMessage(), e);
    }
  }

  private static <T> T readJson(String body, Class<T> type, String op) {
    try {
      return JSON.readValue(body, type);
    } catch (IOException e) {
      throw new IntygaException("bad " + op + " response: " + e.getMessage(), e);
    }
  }

  private record TokenResponse(
      @com.fasterxml.jackson.annotation.JsonProperty("access_token") String accessToken) {}

  /** Configures and constructs an {@link IntygaClient}. */
  public static final class Builder {
    private String gatewayUrl;
    private String token;
    private String clientId;
    private String clientSecret;
    private HttpClient httpClient;

    private Builder() {}

    /** Base URL of the gateway, e.g. {@code https://api.intyga.com}. Required. */
    public Builder gatewayUrl(String gatewayUrl) {
      this.gatewayUrl = gatewayUrl;
      return this;
    }

    /** A pre-minted bearer token (agent or human). When set, clientId/clientSecret are ignored. */
    public Builder token(String token) {
      this.token = token;
      return this;
    }

    /** Exchanged for a bearer token via client-credentials when no token is provided. */
    public Builder clientId(String clientId) {
      this.clientId = clientId;
      return this;
    }

    public Builder clientSecret(String clientSecret) {
      this.clientSecret = clientSecret;
      return this;
    }

    /**
     * Optional override, e.g. to route through a proxy or add instrumentation. Per-request
     * timeouts stay at the client's fixed 30s regardless.
     */
    public Builder httpClient(HttpClient httpClient) {
      this.httpClient = httpClient;
      return this;
    }

    public IntygaClient build() {
      return new IntygaClient(this);
    }
  }
}
