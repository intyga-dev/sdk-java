package com.intyga.sdk;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.intyga.sdk.offline.TrustBundle;
import com.intyga.sdk.offline.TrustBundleResult;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import org.junit.jupiter.api.Test;

final class TrustBundleTenantBindingTest {
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final JsonNode V;
  static {
    try {
      V = JSON.readTree(Files.readString(Path.of("vectors/offline-approval-vectors.json")));
    } catch (Exception e) {
      throw new ExceptionInInitializerError(e);
    }
  }
  private static String unsigned(BigInteger value) {
    byte[] bytes = value.toByteArray();
    int offset = bytes.length > 1 && bytes[0] == 0 ? 1 : 0;
    return Base64.getUrlEncoder().withoutPadding().encodeToString(java.util.Arrays.copyOfRange(bytes, offset, bytes.length));
  }

  private static String token(ObjectNode payload, KeyPair keyPair) throws Exception {
    Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    String header = encoder.encodeToString("{\"alg\":\"RS256\"}".getBytes(StandardCharsets.UTF_8));
    String body = encoder.encodeToString(JSON.writeValueAsBytes(payload));
    String input = header + "." + body;
    Signature signer = Signature.getInstance("SHA256withRSA");
    signer.initSign(keyPair.getPrivate());
    signer.update(input.getBytes(StandardCharsets.US_ASCII));
    return input + "." + encoder.encodeToString(signer.sign());
  }

  @Test void verifiedBundleRequiresNonEmptySignedTenant() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    KeyPair pair = generator.generateKeyPair();
    RSAPublicKey publicKey = (RSAPublicKey) pair.getPublic();
    ObjectNode jwk = JSON.createObjectNode();
    jwk.put("kty", "RSA");
    jwk.put("n", unsigned(publicKey.getModulus()));
    jwk.put("e", unsigned(publicKey.getPublicExponent()));

    for (JsonNode tenant : new JsonNode[] {null, JSON.getNodeFactory().textNode("")}) {
      ObjectNode payload = V.get("bundle").deepCopy();
      if (tenant == null) payload.remove("tenantId"); else payload.set("tenantId", tenant);
      TrustBundleResult result = TrustBundle.verify(token(payload, pair), jwk, Instant.parse("2026-10-10T12:00:00Z"));
      assertFalse(result.ok());
      assertTrue(result.reason().contains("non-empty tenantId"), result.reason());
    }
  }
}
