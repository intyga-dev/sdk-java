package com.intyga.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Drives the shared cross-language DEWP ledger vectors (packages/mcp-schemas/vectors/ledger-vectors.json),
 * the same file the TS/Go/Rust/Python suites consume, so every language's ledger verifier stays
 * byte-identical.
 */
class LedgerVectorsTest {

  private static JsonNode load() {
    try {
      return Records.JSON.readTree(
          Files.readString(Path.of("vectors", "ledger-vectors.json")));
    } catch (IOException e) {
      throw new IllegalStateException("read ledger vectors: " + e.getMessage(), e);
    }
  }

  private static List<Ledger.LedgerProofStep> steps(JsonNode node) {
    return Records.JSON.convertValue(node, new TypeReference<List<Ledger.LedgerProofStep>>() {});
  }

  @Test
  void ledgerPrimitives() {
    JsonNode v = load();
    for (JsonNode c : v.get("sha256Hex")) {
      assertEquals(c.get("expected").asText(), Ledger.sha256Hex(c.get("input").asText()));
    }
    for (JsonNode c : v.get("hashLeaf")) {
      assertEquals(c.get("expected").asText(), Ledger.hashLeaf(c.get("input").asText()));
    }
    for (JsonNode c : v.get("hashPair")) {
      assertEquals(
          c.get("expected").asText(),
          Ledger.hashPair(c.get("left").asText(), c.get("right").asText()));
    }
    assertEquals(v.get("emptyRoot").asText(), Ledger.emptyRoot());
    for (JsonNode c : v.get("merkleRoots")) {
      List<String> leaves =
          Records.JSON.convertValue(c.get("leaves"), new TypeReference<List<String>>() {});
      assertEquals(
          c.get("expected").asText(), Ledger.merkleRoot(leaves), "merkleRoot[" + c.get("name").asText() + "]");
    }
  }

  @Test
  void ledgerLeafPreimage() {
    JsonNode v = load();
    for (JsonNode c : v.get("leafPreimage")) {
      Ledger.AuditLeaf row = Records.JSON.convertValue(c.get("row"), Ledger.AuditLeaf.class);
      String name = c.get("name").asText();
      assertEquals(c.get("canonical").asText(), Ledger.canonicalPreimage(row), "canonical[" + name + "]");
      assertEquals(c.get("leafHash").asText(), Ledger.leafHash(row), "leafHash[" + name + "]");
    }
  }

  @Test
  void ledgerInclusionAndAnchor() {
    JsonNode v = load();
    JsonNode inc = v.get("inclusion");
    String dailyRoot = inc.get("dailyRoot").asText();
    Ledger.InclusionProof proof = new Ledger.InclusionProof(
        inc.get("leaf").asText(),
        inc.get("blockRoot").asText(),
        steps(inc.get("blockProof")),
        inc.get("leafIndex").asInt(),
        inc.get("blockLeafCount").asInt(),
        steps(inc.get("checkpointProof")),
        inc.get("checkpointLeafIndex").asInt(),
        inc.get("checkpointLeafCount").asInt(),
        dailyRoot);

    assertTrue(Ledger.verifyInclusionProof(proof, dailyRoot),
        "inclusion proof did not verify against its daily root");
    assertFalse(
        Ledger.verifyInclusionProof(
            proof, "0000000000000000000000000000000000000000000000000000000000000000"),
        "inclusion proof verified against a wrong root");

    // A proof stripped of its position no longer establishes inclusion (DEWP §3 invariant 3).
    Ledger.InclusionProof positionless = new Ledger.InclusionProof(
        proof.leaf(), proof.blockRoot(), proof.blockProof(), proof.leafIndex(), 0,
        proof.checkpointProof(), proof.checkpointLeafIndex(), proof.checkpointLeafCount(),
        proof.checkpointRoot());
    assertFalse(Ledger.verifyInclusionProof(positionless, dailyRoot),
        "a proof that cannot say where its leaf sits must not verify");

    Ledger.AnchorInput anchor =
        Records.JSON.convertValue(v.get("anchor").get("input"), Ledger.AnchorInput.class);
    assertEquals(v.get("anchor").get("digestHex").asText(), Ledger.anchorDigestHex(anchor));
  }

  /**
   * The §5.2 trap: signing (or verifying against) the digest's 64-char hex text instead of its raw
   * 32 bytes still matches every digest vector, and fails here.
   */
  @Test
  void ledgerSignedAnchorVectors() {
    JsonNode v = load();
    JsonNode suite = v.get("signedAnchor");
    assertTrue(suite != null && suite.get("cases").size() > 0,
        "ledger-vectors.json carries no signedAnchor cases");
    String spki = suite.get("signerKey").get("spkiB64").asText();
    for (JsonNode c : suite.get("cases")) {
      Ledger.SignedAnchor anchor =
          Records.JSON.convertValue(c.get("anchor"), Ledger.SignedAnchor.class);
      String name = c.get("name").asText();
      if (c.hasNonNull("digestHex")) {
        assertEquals(c.get("digestHex").asText(), Ledger.anchorDigestHex(anchor.anchorInput()),
            name + ": anchorDigestHex");
      }
      assertEquals(c.get("expectOk").asBoolean(), Ledger.verifyAnchorSignature(anchor, spki),
          name + ": verifyAnchorSignature");
    }
  }

  /** The duplicate-last padding forgeries every conformant verifier MUST refuse (DEWP §11.1). */
  @Test
  void ledgerInclusionNegativeVectors() {
    JsonNode v = load();
    JsonNode cases = v.get("inclusionNegative");
    assertTrue(cases != null && cases.size() > 0,
        "ledger-vectors.json carries no inclusionNegative cases");
    for (JsonNode c : cases) {
      JsonNode b = c.get("bounds");
      boolean got = Ledger.verifyMerkleProof(
          c.get("leaf").asText(),
          steps(c.get("proof")),
          c.get("root").asText(),
          new Ledger.ProofBounds(b.get("index").asInt(), b.get("leafCount").asInt()));
      assertEquals(c.get("expected").asBoolean(), got,
          c.get("name").asText() + ": " + c.get("reason").asText());
    }
  }
}
