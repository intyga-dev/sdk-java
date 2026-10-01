package com.intyga.verify;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
import java.nio.file.*;
import java.util.*;
class AuditSignaturesTest {
 @Test void sharedAuditSignatureVectors() throws Exception {
  var vectors=Records.JSON.readTree(Files.readString(Path.of("vectors/audit-signature-vectors.json")));
  for (var v:vectors.path("cases")) {
   var b=Dewp.ProofBundle.parse(v.path("bundle"));
   var policy=v.path("policy").isNull()?null:Records.JSON.treeToValue(v.path("policy"),AuditSignatures.Policy.class);
   var opts=new Dewp.BundleOptions(v.path("root").asText(),null,null,null,null,null,null,null,null,policy,false);
   var got=Dewp.verifyBundle(b,opts);assertTrue(got.ok(),v.path("name")+got.notes().toString());
   assertEquals(v.path("status").asText(),got.signature().status(),v.path("name").asText());assertEquals(v.path("trusted").asBoolean(),got.signature().trusted());
   var strict=new Dewp.BundleOptions(v.path("root").asText(),null,null,null,null,null,null,null,null,policy,true);
   assertEquals(v.path("strictOk").asBoolean(),Dewp.verifyBundle(b,strict).ok(),v.path("name").asText());
   var evidence=Records.JSON.createObjectNode();evidence.put("kind",Dewp.EVIDENCE_BUNDLE_KIND);evidence.put("version","1.0");evidence.putObject("tenant").put("id","test-tenant");
   var entry=evidence.putArray("entries").addObject();entry.set("event",v.path("bundle").path("event"));entry.set("proof",v.path("bundle").path("proof"));
   evidence.putArray("checkpoints").addObject().put("id","cp").put("root",v.path("root").asText()).put("seqStart","1").put("seqEnd","1");
   var eb=Records.JSON.treeToValue(evidence,Dewp.EvidenceBundle.class);
   var eo=new Dewp.EvidenceOptions(Set.of(v.path("root").asText()),null,null,null,null,null,null,null,null,null,policy,false);
   var bulk=Dewp.verifyEvidenceBundle(eb,eo);assertTrue(bulk.ok(),v.path("name")+bulk.failed().toString());assertEquals(v.path("status").asText(),bulk.signatures().checks().get(0).status());
   var es=new Dewp.EvidenceOptions(Set.of(v.path("root").asText()),null,null,null,null,null,null,null,null,null,policy,true);
   assertEquals(v.path("strictOk").asBoolean(),Dewp.verifyEvidenceBundle(eb,es).ok(),v.path("name").asText());
  }
 }
}
