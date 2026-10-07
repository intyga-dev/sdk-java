package com.intyga.sdk;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.intyga.sdk.offline.OfflineAction;
import com.intyga.sdk.offline.OfflineApproval;
import com.intyga.sdk.offline.OfflineApprovalOptions;
import com.intyga.sdk.offline.OfflineApprovalResult;
import com.intyga.sdk.offline.PendingApproval;
import com.intyga.sdk.offline.PendingApprovals;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;

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

  // An exchanged token is re-exchanged this long before the expiry the gateway reported, capped at
  // a tenth of the lifetime so a short-lived token is not refreshed on every call. 60s absorbs the
  // clock skew and request latency a poll loop actually sees; every port uses the same margin.
  private static final long MAX_REFRESH_MARGIN_NANOS = Duration.ofSeconds(60).toNanos();

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
  private final LongSupplier nanoClock;

  // The benign race (two threads exchanging concurrently, last write wins) matches the Go client.
  // Invalidation on a 401 is a compare-and-set against the exact entry that was refused, so one
  // thread's stale 401 cannot discard a token another thread has just exchanged.
  private final AtomicReference<Cached> cached = new AtomicReference<>();

  /**
   * One exchanged token and when to stop serving it. {@code refreshAtNanos} is on the injected
   * nano clock, already net of the refresh margin; it is meaningless (and ignored) when the gateway
   * reported no {@code expires_in}, in which case the entry is served until a 401 evicts it.
   */
  private record Cached(String token, boolean expiryKnown, long refreshAtNanos) {
    boolean fresh(long nowNanos) {
      // Subtraction, not comparison: System.nanoTime() may be negative and wraps.
      return !expiryKnown || nowNanos - refreshAtNanos < 0;
    }
  }

  private IntygaClient(Builder b) {
    if (b.gatewayUrl == null || b.gatewayUrl.isBlank()) {
      throw new IllegalArgumentException("gatewayUrl is required");
    }
    requireSecureGatewayUrl(b.gatewayUrl);
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
    this.nanoClock = b.nanoClock != null ? b.nanoClock : System::nanoTime;
  }

  public static Builder builder() {
    return new Builder();
  }

  /**
   * Refuses a gateway URL that is not {@code https://}, except {@code http://} to a loopback host
   * ({@code localhost}, {@code 127.0.0.0/8}, {@code ::1}) for local development: every request
   * carries a bearer token or client secret. The same rule every Intyga client applies (TypeScript,
   * Go, Rust, Python) — change them together.
   */
  static void requireSecureGatewayUrl(String raw) {
    URI uri;
    try {
      uri = new URI(raw);
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException("gatewayUrl is not a valid URL: " + raw);
    }
    String scheme = uri.getScheme();
    String host = uri.getHost();
    if (scheme == null || host == null || host.isEmpty()) {
      throw new IllegalArgumentException("gatewayUrl is not a valid absolute URL: " + raw);
    }
    if ("https".equalsIgnoreCase(scheme)) {
      return;
    }
    if ("http".equalsIgnoreCase(scheme) && isLoopbackHost(host)) {
      return;
    }
    throw new IllegalArgumentException(
        "gatewayUrl must use https:// (got "
            + scheme
            + "://"
            + host
            + "): Intyga clients send credentials on every request and refuse plain http except"
            + " to a loopback host (localhost, 127.0.0.0/8, ::1) for local development");
  }

  /** {@code host} as {@link URI#getHost()} returns it: IPv6 literals keep their brackets. */
  private static boolean isLoopbackHost(String host) {
    if (host.equalsIgnoreCase("localhost")) {
      return true;
    }
    if (host.startsWith("[") && host.endsWith("]")) {
      try {
        // A bracketed literal is parsed, never resolved: getByName does no DNS lookup for it.
        InetAddress addr = InetAddress.getByName(host.substring(1, host.length() - 1));
        return addr instanceof java.net.Inet6Address && addr.isLoopbackAddress();
      } catch (UnknownHostException e) {
        return false;
      }
    }
    String[] octets = host.split("\\.", -1);
    if (octets.length != 4) {
      return false;
    }
    for (String o : octets) {
      if (!o.matches("[0-9]{1,3}") || Integer.parseInt(o) > 255) {
        return false;
      }
    }
    return octets[0].equals("127");
  }

  /**
   * Resolves a bearer token: the provided one, a cached exchange that is still fresh, or a fresh
   * client-credentials exchange (HTTP Basic at {@code POST /oauth/token}).
   *
   * <p>An exchanged token is cached together with the {@code expires_in} the gateway reports — the
   * TTL it actually signed — and served until {@code min(60s, expires_in / 10)} before that expiry,
   * then exchanged again. So a long-lived client, or a {@link #requireApproval} wait that outlasts
   * the token, keeps working across rotation with no help from the caller. A response with no
   * {@code expires_in} is cached for the life of the client. Independently of the clock, a 401 on
   * an exchanged token evicts it and the request is retried exactly once with a fresh exchange
   * (clock skew, or a gateway that shortened its TTL); a second 401 surfaces as {@link
   * GatewayRefusedException}. A 401 on an explicit {@link Builder#token} is never retried — there
   * is nothing to re-exchange.
   */
  public String token() {
    if (token != null && !token.isEmpty()) {
      return token;
    }
    Cached c = cached.get();
    if (c != null && c.fresh(nanoClock.getAsLong())) {
      return c.token();
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
    TokenResponse parsed = readJson(res.body(), TokenResponse.class, "token");
    String exchanged = parsed.accessToken();
    cached.set(cacheEntry(exchanged, parsed.expiresIn(), nanoClock.getAsLong()));
    return exchanged;
  }

  // A missing, non-finite or non-positive expires_in is "no expiry known": the token is served
  // until a 401 evicts it — the pre-refresh behaviour — rather than re-exchanged on every call. So
  // is a lifetime too long to add to the nano clock without wrapping (decades); it is unbounded in
  // practice and the 401 path still covers it.
  private static Cached cacheEntry(String token, Double expiresIn, long nowNanos) {
    if (expiresIn == null || !Double.isFinite(expiresIn) || expiresIn <= 0) {
      return new Cached(token, false, 0L);
    }
    double lifetime = expiresIn * 1_000_000_000.0;
    if (lifetime >= Long.MAX_VALUE / 4.0) {
      return new Cached(token, false, 0L);
    }
    long lifetimeNanos = (long) lifetime;
    long marginNanos = Math.min(MAX_REFRESH_MARGIN_NANOS, lifetimeNanos / 10);
    return new Cached(token, true, nowNanos + lifetimeNanos - marginNanos);
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
    if (options.actionType() != null) {
      body.put("actionType", options.actionType());
    }
    body.put("params", options.params());
    if (options.agentContext() != null) body.put("agentContext", options.agentContext());
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
   *
   * <p>With per-call {@link RequireApprovalOptions.Builder#offline offline} options, a gateway that
   * could not be ASKED — connection failure, timeout, a 5xx, or five consecutive polling failures —
   * falls back to an offline approval (DIV §5a), which returns
   * {@link ApprovalStatus#OFFLINE_APPROVED}, never {@code APPROVED}. A 4xx, DENIED or EXPIRED is a
   * verdict and is never routed offline; neither is an agent-continuity request, nor an interrupt.
   * Without offline options a transport failure throws exactly as it always did.
   *
   * @throws OfflineApprovalFailedException when the fallback ran and did not complete
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

    long deadlineNanos = System.nanoTime() + timeout.toNanos();
    AuthorizeResponse authRes;
    try {
      authRes = authorize(actionDescription, authOptions);
    } catch (IntygaException e) {
      // Could not even raise the challenge — the clearest "gateway is unreachable" signal there is,
      // unless the gateway in fact answered, which offlineFallback rethrows rather than routing.
      return offlineFallback(actionDescription, options,
          "could not reach Intyga to request approval: " + e.getMessage(), e);
    }
    String nonce = authRes.nonce();

    int consecutiveErrors = 0;
    // The first failure in the current streak that was NOT a "could not ask" one. The fallback needs
    // five consecutive failures OF THOSE KINDS (docs/OFFLINE-APPROVAL-SDK.md): a streak that includes
    // a refusal is a gateway that answered, so it ends the wait with THAT error — not with whatever
    // transport failure happened to come last, which would misreport a verdict as an outage.
    IntygaException streakRefusal = null;
    while (true) {
      if (System.nanoTime() - deadlineNanos >= 0)
        return new ApprovalResult(ApprovalStatus.EXPIRED, null, null, nonce, authRes.agentContext());
      // A human approval can outlast a transient 502 or socket hangup — don't discard the whole
      // wait over one bad poll. Only give up once the gateway looks genuinely unreachable, and
      // rethrow the typed exception so refusal-vs-outage survives to the caller.
      try {
        ApprovalResult r = status(nonce);
        if (System.nanoTime() - deadlineNanos >= 0)
          return new ApprovalResult(ApprovalStatus.EXPIRED, null, null, nonce, authRes.agentContext());
        consecutiveErrors = 0;
        streakRefusal = null;
        if (r.status() != ApprovalStatus.PENDING) {
          return r.withChallenge(nonce, authRes.agentContext());
        }
      } catch (IntygaException e) {
        consecutiveErrors++;
        if (streakRefusal == null && !couldNotAsk(e)) {
          streakRefusal = e;
        }
        if (consecutiveErrors >= MAX_POLL_ERRORS) {
          if (streakRefusal != null) {
            throw streakRefusal;
          }
          // The gateway went away mid-wait: the same situation as failing to raise the challenge,
          // so the same (opt-in) fallback applies — and, as there, only because we could not ASK.
          return offlineFallback(actionDescription, options,
              "polling failed after " + MAX_POLL_ERRORS + " consecutive errors: " + e.getMessage(), e);
        }
      }

      if (System.nanoTime() - deadlineNanos >= 0) {
        return new ApprovalResult(ApprovalStatus.EXPIRED, null, null, nonce, authRes.agentContext());
      }
      try {
        java.util.concurrent.TimeUnit.NANOSECONDS.sleep(Math.max(0, Math.min(interval.toNanos(), deadlineNanos - System.nanoTime())));
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
    // An offline approval reports OFFLINE_APPROVED, which this method's contract would turn into
    // ApprovalRefusedException AFTER humans signed and the nonce was redeemed. Refuse the
    // combination up front: handling an offline approval must be explicit at the call site.
    if (options.offline() != null) {
      throw new IllegalArgumentException(
          "requireApprovalOrThrow does not take offline options: an offline approval returns"
              + " OFFLINE_APPROVED, which it would throw away — use requireApproval and handle"
              + " OFFLINE_APPROVED explicitly");
    }
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
   * DIV §5a exists for the case where the gateway could not be ASKED. Everything else rethrows the
   * original exception: a 4xx is the gateway's verdict (403 in particular is its own fail-closed
   * "cannot resolve the approval requirement"), and treating a refusal as unreachability would turn
   * a policy denial into a different approval route. A 5xx is infrastructure failing — exactly the
   * "could not ask" §5a is written for. Anything that is not a transport outcome at all (a malformed
   * response body, missing credentials, an interrupt) is not an outage and is not routed either.
   */
  private ApprovalResult offlineFallback(
      String actionDescription, RequireApprovalOptions options, String cause, IntygaException e) {
    OfflineApprovalOptions offline = options.offline();
    if (offline == null || !couldNotAsk(e)) {
      throw e;
    }
    AuthorizeOptions auth = options.authorize();
    if (auth.agentContext() != null) {
      throw new IntygaException(
          "agent continuity requests cannot fall back to an unchained offline proof", e);
    }
    OfflineApprovalResult r =
        OfflineApproval.useOfflineApproval(
            new OfflineAction(
                auth.target(),
                auth.actionType() == null ? "" : auth.actionType(),
                actionDescription,
                auth.params()),
            offline);
    if (!r.ok()) {
      throw new OfflineApprovalFailedException(
          cause + " — and the offline approval did not complete: " + r.reason(), r.reason(), e);
    }
    return new ApprovalResult(
        ApprovalStatus.OFFLINE_APPROVED, null, OfflineApproval.receiptJson(r.receipt()), r.nonce(), null);
  }

  private static boolean couldNotAsk(IntygaException e) {
    if (e instanceof GatewayRefusedException refused) {
      return refused.status() >= 500;
    }
    return e instanceof GatewayUnreachableException
        && !(e.getCause() instanceof InterruptedException)
        && !Thread.currentThread().isInterrupted();
  }

  /** {@link #reconcileOfflineApprovals(Path, Path)} with the default buffer, {@code <bundleDir>/.pending}. */
  public ReconcileResult reconcileOfflineApprovals(Path bundleDir) {
    return reconcileOfflineApprovals(bundleDir, null);
  }

  /**
   * Report offline approvals that happened while the gateway was unreachable (DIV §5a.7): each
   * buffered record is POSTed to {@code /offline-approval/reconcile} with this client's ordinary
   * authentication, full receipt included so the gateway RE-VERIFIES it rather than taking our
   * word for it — we are reporting on ourselves.
   *
   * <p>Call it on reconnect: a scheduled retry, a health-check hook, service start. Until reported,
   * an approval exists only on this relying party's disk, indistinguishable from an unauthorized
   * action. A record is cleared ONLY on a 2xx; a refusal or a network failure leaves it queued. A
   * buffered file that cannot be read is counted as a failure (with its name), never skipped.
   *
   * @param bufferDir null means {@code <bundleDir>/.pending}
   * @throws IntygaException when no credentials are configured — thrown up front, rather than
   *     counted as one failure per buffered approval
   */
  public ReconcileResult reconcileOfflineApprovals(Path bundleDir, Path bufferDir) {
    token();
    int reported = 0;
    int failed = 0;
    List<String> reasons = new ArrayList<>();
    PendingApprovals pending = OfflineApproval.readPendingApprovals(bundleDir, bufferDir);
    // Counted, never skipped: an unreported approval is indistinguishable from an unauthorized one,
    // and a record nobody can read is still an approval nobody has reported.
    for (String name : pending.unreadable()) {
      failed++;
      reasons.add(name + ": unreadable pending record — report it by hand");
    }
    for (PendingApproval use : pending.records()) {
      // Absent fields are omitted, as JSON.stringify omits undefined ones (no delegation, usually).
      Map<String, Object> body = new LinkedHashMap<>();
      body.put("nonce", use.nonce());
      putIfSet(body, "usedAt", use.usedAt());
      putIfSet(body, "target", use.target());
      putIfSet(body, "actionType", use.actionType());
      putIfSet(body, "display", use.display());
      putIfSet(body, "receipt", use.receipt());
      putIfSet(body, "delegationNonce", use.delegationNonce());
      try {
        HttpResponse<String> res = sendAuthed("POST", "/offline-approval/reconcile", body, false);
        if (res.statusCode() >= 200 && res.statusCode() < 300) {
          OfflineApproval.clearPendingApproval(use.nonce(), bundleDir, bufferDir);
          reported++;
        } else {
          failed++;
          reasons.add(use.nonce() + ": " + res.statusCode() + " " + res.body());
        }
      } catch (IntygaException e) {
        failed++;
        reasons.add(use.nonce() + ": " + e.getMessage());
      }
    }
    return new ReconcileResult(reported, failed, List.copyOf(reasons));
  }

  private static void putIfSet(Map<String, Object> body, String name, Object value) {
    if (value != null) {
      body.put(name, value);
    }
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
    HttpResponse<String> res = sendAuthed(method, path, body, op.equals("verify"));
    if (res.statusCode() < 200 || res.statusCode() >= 300) {
      throw new GatewayRefusedException(
          res.statusCode(),
          method + " " + path + " failed: " + res.statusCode() + " " + res.body());
    }
    return readJson(res.body(), type, op);
  }

  /**
   * One request, authenticated unless {@code anonymous}. A 401 on a token WE exchanged means it
   * aged out (clock skew, a shortened gateway TTL) — evict it and re-exchange, exactly once. An
   * explicit token is never retried: there is nothing to re-exchange, and looping on a revoked
   * credential would only hide the refusal.
   */
  private HttpResponse<String> sendAuthed(String method, String path, Object body, boolean anonymous) {
    return sendAuthed(method, path, body, anonymous, false);
  }

  private HttpResponse<String> sendAuthed(
      String method, String path, Object body, boolean anonymous, boolean retried) {
    String bearer = anonymous ? null : token();
    HttpRequest.Builder builder =
        HttpRequest.newBuilder(URI.create(gatewayUrl + path))
            .timeout(REQUEST_TIMEOUT);
    if (bearer != null) builder.header("authorization", "Bearer " + bearer);
    if (body != null) {
      builder
          .header("content-type", "application/json")
          .method(method, HttpRequest.BodyPublishers.ofString(writeJson(body)));
    } else {
      builder.method(method, HttpRequest.BodyPublishers.noBody());
    }
    HttpResponse<String> res = send(builder.build());
    if (res.statusCode() == 401 && bearer != null && !retried && usesExchangedToken()) {
      evictIfCurrent(bearer);
      return sendAuthed(method, path, body, anonymous, true);
    }
    return res;
  }

  private boolean usesExchangedToken() {
    return token == null || token.isEmpty();
  }

  // Drop the cache only if it still holds the token that was refused: if another thread has
  // already exchanged a fresh one, this stale 401 must not throw that away.
  private void evictIfCurrent(String refused) {
    Cached c = cached.get();
    if (c != null && c.token().equals(refused)) {
      cached.compareAndSet(c, null);
    }
  }

  /**
   * One exchange. An I/O failure BEFORE the response headers means the gateway could not be asked
   * ({@link GatewayUnreachableException}). One AFTER them — the body broke off mid-read — means it
   * answered and the answer was unreadable: a plain {@link IntygaException}, never routed to the
   * DIV §5a offline path (docs/OFFLINE-APPROVAL-SDK.md). The body handler's {@code apply} runs
   * exactly when the headers arrive, so it marks the boundary; the body is still read by {@code
   * ofString}, so timeouts behave as before.
   */
  private HttpResponse<String> send(HttpRequest req) {
    AtomicBoolean answered = new AtomicBoolean();
    HttpResponse.BodyHandler<String> handler =
        info -> {
          answered.set(true);
          return HttpResponse.BodyHandlers.ofString().apply(info);
        };
    try {
      return http.send(req, handler);
    } catch (IOException e) {
      if (answered.get()) {
        throw new IntygaException(
            req.method() + " " + req.uri() + ": the gateway answered but its response body could not"
                + " be read: " + e.getMessage(), e);
      }
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

  // expires_in is nullable on purpose: a gateway (or proxy) that omits it must not NPE the
  // exchange — it just yields a token with no known expiry.
  private record TokenResponse(
      @com.fasterxml.jackson.annotation.JsonProperty("access_token") String accessToken,
      @com.fasterxml.jackson.annotation.JsonProperty("expires_in") Double expiresIn) {}

  /** Configures and constructs an {@link IntygaClient}. */
  public static final class Builder {
    private String gatewayUrl;
    private String token;
    private String clientId;
    private String clientSecret;
    private HttpClient httpClient;
    private LongSupplier nanoClock;

    private Builder() {}

    /**
     * Base URL of the gateway, e.g. {@code https://api.intyga.com}. Required, and must be {@code
     * https://}; {@code http://} is accepted only for a loopback host, for local development.
     * {@link #build()} throws {@link IllegalArgumentException} otherwise.
     */
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

    /**
     * Test seam, package-private on purpose: the monotonic clock the token cache ages against
     * (defaults to {@link System#nanoTime()}). It drives ONLY the cache — the {@link
     * IntygaClient#requireApproval} deadline stays on the real clock, so a frozen test clock can
     * never turn a poll loop unbounded.
     */
    Builder nanoClock(LongSupplier nanoClock) {
      this.nanoClock = nanoClock;
      return this;
    }

    public IntygaClient build() {
      return new IntygaClient(this);
    }
  }
}
