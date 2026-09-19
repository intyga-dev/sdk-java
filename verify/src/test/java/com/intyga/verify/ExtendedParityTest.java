package com.intyga.verify;

import static org.junit.jupiter.api.Assertions.*;
import java.util.List;
import org.junit.jupiter.api.Test;

final class ExtendedParityTest {
  @Test void platformCanonicalIsStableAndApprovalDoorRefusesIt() {
    String c = Verify.canonicalPlatformIntentPayload("a".repeat(64), "pay.example", "customer-7",
        "2026-09-15T10:00:00Z", "2026-09-15T10:05:00Z", "nonce-1");
    assertTrue(c.contains("\"type\":\"div-platform-intent\""));
    ApprovalReceipt r = new ApprovalReceipt(c,null,null,"",java.util.Map.of(),null,null,null,null,null,null,null,null,"");
    assertFalse(Verify.verifyApprovalReceipt(r, new Expected("target","nonce-1","x",java.util.Map.of(),ApproverTrustAnchor.ofPublicKeys(List.of("x"))), VerifyOptions.defaults()).ok());
  }

  @Test void authorityCanonicalSortsSetFields() {
    ApprovalRequirement req = new ApprovalRequirement(2,false,List.of("z","a"),true,"human");
    RequesterIdentity who = new RequesterIdentity("did:requester",null);
    String a = Verify.canonicalAgentAuthorityPayload("prod",List.of("write","read"),"scope","did:agent",who,req,"n","2026-01-01T00:00:00Z","2027-01-01T00:00:00Z");
    String b = Verify.canonicalAgentAuthorityPayload("prod",List.of("read","write"),"scope","did:agent",who,req,"n","2026-01-01T00:00:00Z","2027-01-01T00:00:00Z");
    assertEquals(a,b); assertTrue(a.contains("\"actionPatterns\":[\"read\",\"write\"]"));
  }

  @Test void checkpointChainDetectsEditAndLegacyIsUnverified() {
    String h = Ledger.chainHash("", "a".repeat(64), "1", "10", 10, "2026-09-15T00:00:00Z");
    var good = new Ledger.RootsChainEntry("1","10",10,"a".repeat(64),"2026-09-15T00:00:00Z","",h);
    assertTrue(Ledger.verifyRootsChain(List.of(good)).ok());
    var edited = new Ledger.RootsChainEntry("1","10",9,"a".repeat(64),"2026-09-15T00:00:00Z","",h);
    assertFalse(Ledger.verifyRootsChain(List.of(edited)).ok());
    var legacy = new Ledger.RootsChainEntry("1","10",10,"a".repeat(64),"2026-09-15T00:00:00Z",null,null);
    assertTrue(Ledger.verifyRootsChain(List.of(legacy)).unchained());
    assertFalse(Ledger.verifyRootsChain(List.of(legacy)).ok());
  }

  @Test void unknownAnchorAlgorithmFailsClosed() {
    var a = new Ledger.SignedAnchor("a".repeat(64),"2026-09-15T00:00:00Z","did:x","UNKNOWN","k","AA==");
    assertFalse(Ledger.verifyAnchorSignature(a, (java.security.PublicKey) null));
  }
}
