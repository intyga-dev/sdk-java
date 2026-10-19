package com.intyga.sdk;

import com.intyga.sdk.offline.P256;
import com.intyga.verify.ExecutionEvidence;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Map;

/**
 * DEWP §4.7 execution evidence — the evidence source's side. An evidence source (a protection relay,
 * a meter, a measured-boot attester) is a party independent of the service that executed an approved
 * action. It observes the effect and signs a statement; your service relays it with
 * {@link IntygaClient#submitEvidence}. The service never signs one itself: it does not hold the
 * source's key.
 */
public final class EvidenceSource {
  private static final DateTimeFormatter DEWP_TIMESTAMP =
      DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);

  private EvidenceSource() {}

  /**
   * As {@link #buildExecutionEvidence(String, String, String, String, Map, long, String, String)} with
   * {@code observedAt} now and {@code sampledAt} equal to it.
   */
  public static String buildExecutionEvidence(String approvalPayload, String nonce, String source, String verdict,
      Map<String, Object> observation, long sequence) {
    return buildExecutionEvidence(approvalPayload, nonce, source, verdict, observation, sequence, null, null);
  }

  /**
   * The canonical statement bytes for one observation (DEWP §4.7.2). {@code approvalPayload} is the
   * approved DIV Intent Payload ({@code receipt.canonicalPayload}); its SHA-256 binds the statement to
   * exactly those bytes. {@code verdict} is {@code confirmed} or {@code contradicted}.
   *
   * <p>{@code sequence} is the source's own gapless counter of statements it has signed for this log
   * — one counter per log, incremented by exactly one per statement, never reused (rule 12). It is
   * what lets a verifier see a statement that was withheld. Keep it durable: a source that restarts
   * from 1 signs a divergence.
   *
   * @param sampledAt when the measurement was taken (rule 11), in the DEWP §4.3 form; null means
   *     {@code observedAt}. The evidence window is evaluated on it.
   * @param observedAt when the source produced the statement, in the DEWP §4.3 form; null means now.
   * @throws IllegalArgumentException on input a verifier would refuse (a non-portable number, more
   *     than 64 levels, {@code sampledAt} later than {@code observedAt}, a sequence below 1, …)
   */
  public static String buildExecutionEvidence(String approvalPayload, String nonce, String source, String verdict,
      Map<String, Object> observation, long sequence, String sampledAt, String observedAt) {
    if (approvalPayload == null) {
      throw new IllegalArgumentException("approvalPayload is required: the approved DIV Intent Payload");
    }
    String observed = observedAt != null ? observedAt : DEWP_TIMESTAMP.format(Instant.now());
    return ExecutionEvidence.canonicalStatement(new ExecutionEvidence.Statement(nonce,
        ExecutionEvidence.payloadSha256(approvalPayload), observation == null ? Map.of() : observation,
        observed, sampledAt != null ? sampledAt : observed, sequence, source, verdict));
  }

  /**
   * ES256 (P-256, IEEE P1363) signature over statement bytes, base64 — what
   * {@link IntygaClient#submitEvidence} relays.
   *
   * @throws IllegalArgumentException when the key is not an EC P-256 private key
   */
  public static String signExecutionEvidence(String statement, PrivateKey privateKey) {
    if (statement == null) {
      throw new IllegalArgumentException("statement is required");
    }
    PrivateKey key;
    try {
      key = P256.requireP256(privateKey);
    } catch (P256.KeyRefusal e) {
      throw new IllegalArgumentException("evidence statements are signed with an EC P-256 (prime256v1) key", e);
    }
    try {
      return Base64.getEncoder().encodeToString(P256.sign(key, statement.getBytes(StandardCharsets.UTF_8)));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("could not sign with this key: " + e.getMessage(), e);
    }
  }

  /**
   * As {@link #signExecutionEvidence(String, PrivateKey)}, from a PEM key: PKCS#8 {@code PRIVATE KEY}
   * or SEC1 {@code EC PRIVATE KEY} (what {@code openssl ecparam -genkey} writes). Encrypted keys are
   * refused: decrypt them first.
   */
  public static String signExecutionEvidence(String statement, String pemPrivateKey) {
    try {
      return signExecutionEvidence(statement, P256.parsePem(pemPrivateKey));
    } catch (P256.KeyRefusal e) {
      throw new IllegalArgumentException("could not read the private key: " + e.getMessage(), e);
    }
  }

  /**
   * As {@link #signExecutionEvidence(String, PrivateKey)}, from the bytes of a key file: PEM when they
   * contain a PEM header, otherwise DER PKCS#8.
   */
  public static String signExecutionEvidence(String statement, byte[] keyFile) {
    try {
      return signExecutionEvidence(statement, P256.parse(keyFile));
    } catch (P256.KeyRefusal e) {
      throw new IllegalArgumentException("could not read the private key: " + e.getMessage(), e);
    }
  }
}
