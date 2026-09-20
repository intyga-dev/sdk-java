package com.intyga.verify;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.time.format.DateTimeFormatter;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.Map;
import java.util.LinkedHashMap;

/**
 * Offline verification of DIV approval receipts: recompute the canonical payload from the caller's
 * OWN parameters, confirm it byte-matches what was signed, and verify the human's ES256 or WebAuthn
 * signature against a key the caller resolved — no Intyga secret, no network.
 */
public final class Verify {

  private static final DateTimeFormatter AGENT_TIME = DateTimeFormatter
      .ofPattern("uuuu-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);

  private static boolean agentDigest(Object value) {
    return value instanceof String s && s.matches("sha256:[0-9a-f]{64}");
  }

  private static boolean agentMoney(Object value) {
    if (!(value instanceof Map<?, ?> m)) return false;
    return m.get("amount") instanceof String amount
        && amount.matches("(?:0|[1-9][0-9]{0,29})(?:\\.[0-9]{1,9})?")
        && m.get("currency") instanceof String currency && currency.matches("[A-Z]{3}");
  }

  private static String validateAgentContext(Map<String, Object> context, String exp, String sigAlg) {
    if (!(context.get("action") instanceof Map<?, ?> action)
        || !("reversible".equals(action.get("reversibility")) || "irreversible".equals(action.get("reversibility"))))
      return "invalid agent action reversibility";
    if (!(context.get("agent") instanceof Map<?, ?> agent)
        || !(agent.get("label") instanceof String label) || label.isEmpty() || label.length() > 200
        || !agentDigest(agent.get("configDigest"))) return "invalid agent identity or configuration digest";
    if (!(context.get("session") instanceof Map<?, ?> session)) return "invalid agent session identity or sequence";
    if (!Normalizer.isNormalized(label, Normalizer.Form.NFC)
        || !(session.get("id") instanceof String id) || !Normalizer.isNormalized(id, Normalizer.Form.NFC))
      return "agent labels and session identifiers must be NFC";
    if (!agent.containsKey("delegatedBy") || (agent.get("delegatedBy") != null && !agentDigest(agent.get("delegatedBy"))))
      return "invalid parent authority digest";
    if (!agentDigest(session.get("id")) || !(session.get("seq") instanceof String seq)
        || !seq.matches("[1-9][0-9]{0,17}")) return "invalid agent session identity or sequence";
    Object prev = session.get("prev");
    if (!session.containsKey("prev") || ("1".equals(seq)) != (prev == null) || (prev != null && !agentDigest(prev)))
      return "invalid agent session predecessor";
    Object amount = action.get("amount"), aggregate = session.get("aggregate");
    if (!action.containsKey("amount") || !session.containsKey("aggregate")) return "invalid agent monetary amount";
    if ((amount != null && !agentMoney(amount)) || (aggregate != null && !agentMoney(aggregate)))
      return "invalid agent monetary amount";
    if ((amount == null) != (aggregate == null)
        || (amount instanceof Map<?, ?> a && aggregate instanceof Map<?, ?> b
            && !Objects.equals(a.get("currency"), b.get("currency"))))
      return "agent monetary amount and aggregate disagree";
    try {
      if (!(context.get("nbf") instanceof String nbf)
          || !nbf.matches("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z")
          || !exp.matches("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z"))
        return "agent intent must use canonical UTC times within five minutes";
      Instant from = Instant.parse(nbf), to = Instant.parse(exp);
      if (!AGENT_TIME.format(from).equals(nbf) || !AGENT_TIME.format(to).equals(exp)
          || !to.isAfter(from) || Duration.between(from, to).toMillis() > 300_000)
        return "agent intent must use canonical UTC times within five minutes";
    } catch (RuntimeException e) { return "agent intent must use canonical UTC times within five minutes"; }
    if ("irreversible".equals(action.get("reversibility")) && "AUTO_APPROVED".equals(sigAlg))
      return "irreversible agent action requires a human signature";
    return null;
  }

  /** Byte-identical DIV §5c canonical platform intent. */
  public static String canonicalPlatformIntentPayload(
      String payloadHash, String rpId, String subjectExternalId,
      String signedAt, String expiresAt, String nonce) {
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("v", Div.VERSION); m.put("type", Div.PLATFORM_INTENT_TYPE); m.put("hashAlg", "SHA-256");
    m.put("payloadHash", payloadHash); m.put("rpId", rpId);
    m.put("subject", Map.of("externalId", subjectExternalId));
    m.put("signedAt", signedAt); m.put("expiresAt", expiresAt); m.put("nonce", nonce);
    return Canonical.stableStringify(m);
  }

  /** Byte-identical DIV §5b canonical authority statement. Set-valued fields are sorted. */
  public static String canonicalAgentAuthorityPayload(
      String target, List<String> actionPatterns, String display, String agentDid,
      RequesterIdentity requester, ApprovalRequirement requirement,
      String nonce, String sealedAt, String expiresAt) {
    return canonicalAgentAuthorityPayload(target, actionPatterns, display, agentDid, requester,
        requirement, nonce, sealedAt, expiresAt, null);
  }

  public static String canonicalAgentAuthorityPayload(
      String target, List<String> actionPatterns, String display, String agentDid,
      RequesterIdentity requester, ApprovalRequirement requirement,
      String nonce, String sealedAt, String expiresAt, String parentReceiptHash) {
    List<String> patterns = new ArrayList<>(actionPatterns); Collections.sort(patterns);
    List<String> aaguids = new ArrayList<>(requirement.allowedAaguids()); Collections.sort(aaguids);
    Map<String, Object> req = new LinkedHashMap<>();
    req.put("requiredApprovals", requirement.requiredApprovals());
    req.put("requireHardwareKey", requirement.requireHardwareKey());
    req.put("allowedAaguids", aaguids); req.put("requesterCannotApprove", requirement.requesterCannotApprove());
    req.put("signerClass", requirement.signerClass());
    Map<String, Object> requesterMap = new LinkedHashMap<>(); requesterMap.put("did", requester.did());
    RequesterAttestation a = requester.attestation();
    requesterMap.put("attestation", a == null ? null : Map.of("method", a.method(), "issuer", a.issuer(), "subject", a.subject()));
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("v", Div.VERSION); m.put("type", Div.AGENT_AUTHORITY_TYPE); m.put("target", target);
    m.put("actionPatterns", patterns); m.put("display", display); m.put("agent", Map.of("did", agentDid));
    m.put("parentReceiptHash", parentReceiptHash);
    m.put("requester", requesterMap); m.put("requirement", req); m.put("nonce", nonce);
    m.put("sealedAt", sealedAt); m.put("expiresAt", expiresAt);
    return Canonical.stableStringify(m);
  }

  /** Verify a DIV §5c hash-only receipt. Every accepted witness is WebAuthn-bound to the RP. */
  public static PlatformVerification verifyPlatformReceipt(
      PlatformReceipt receipt, PlatformExpected expected, VerifyOptions opts) {
    try {
      return verifyPlatformReceiptChecked(receipt, expected, opts == null ? VerifyOptions.defaults() : opts);
    } catch (RuntimeException e) {
      return PlatformVerification.refuse("malformed receipt or verification input");
    }
  }

  private static PlatformVerification verifyPlatformReceiptChecked(
      PlatformReceipt receipt, PlatformExpected expected, VerifyOptions opts) {
    com.fasterxml.jackson.databind.JsonNode p;
    try { p = Records.JSON.readTree(receipt.canonicalPayload()); }
    catch (Exception e) { return PlatformVerification.refuse("canonicalPayload is not valid JSON"); }
    if (p.path("v").asInt(-1) != Div.VERSION) return PlatformVerification.refuse("unsupported DIV payload version");
    String type = p.path("type").asText("");
    if (!Div.PLATFORM_INTENT_TYPE.equals(type)) {
      return PlatformVerification.refuse(Div.INTENT_TYPE.equals(type) || Div.OFFLINE_INTENT_TYPE.equals(type)
          ? "this is an ordinary approval receipt — verify it with verifyApprovalReceipt"
          : "payload is not a div-platform-intent");
    }
    if (expected == null || expected.approvers() == null) return PlatformVerification.refuse("expected.approvers is required");
    if (isEmpty(expected.nonce())) return PlatformVerification.refuse("expected.nonce is required");
    if (!p.path("nonce").asText("").equals(expected.nonce())) return PlatformVerification.refuse("receipt is for a different challenge");
    if (expected.payloadHash() == null || !expected.payloadHash().matches("[0-9a-f]{64}"))
      return PlatformVerification.refuse("expected.payloadHash must be the 64-character lowercase hex SHA-256 you recomputed yourself");
    if (isEmpty(expected.rpId())) return PlatformVerification.refuse("expected.rpId is required");
    if (opts.expectedRpId() != null && !opts.expectedRpId().equals(expected.rpId()))
      return PlatformVerification.refuse("opts.expectedRpId conflicts with expected.rpId — pass the RP ID once");
    String signedAt = p.path("signedAt").asText(""); String expiresAt = p.path("expiresAt").asText("");
    String subject = p.path("subject").path("externalId").asText("");
    if (isEmpty(signedAt)) return PlatformVerification.refuse("receipt missing signedAt");
    if (isEmpty(expiresAt)) return PlatformVerification.refuse("receipt missing expiresAt");
    if (isEmpty(subject)) return PlatformVerification.refuse("receipt missing subject.externalId");
    if (expected.subjectExternalId() != null && !expected.subjectExternalId().equals(subject))
      return PlatformVerification.refuse("receipt was signed by a different subject");
    String canonical = canonicalPlatformIntentPayload(expected.payloadHash(), expected.rpId(), subject, signedAt, expiresAt, expected.nonce());
    if (!canonical.equals(receipt.canonicalPayload())) return PlatformVerification.refuse("payloadHash/rpId do not match what was signed");
    Instant signed; Instant expiry;
    try { signed = Instant.parse(signedAt); } catch (Exception e) { return PlatformVerification.refuse("signedAt is not a valid RFC3339 timestamp"); }
    try { expiry = Instant.parse(expiresAt); } catch (Exception e) { return PlatformVerification.refuse("expiresAt is not a valid RFC3339 timestamp"); }
    if (expiry.isBefore(signed)) return PlatformVerification.refuse("receipt expires before it was signed");
    Instant now = opts.asOf() == null ? Instant.now() : opts.asOf();
    long skew = opts.clockSkewSeconds() == null ? Div.DEFAULT_CLOCK_SKEW_SECONDS : opts.clockSkewSeconds();
    if (signed.isAfter(now.plusSeconds(skew))) return PlatformVerification.refuse("receipt is signed in the future (DIV §5c.3)");
    if (!opts.allowExpired() && now.isAfter(expiry.plusSeconds(skew))) return PlatformVerification.refuse("proof has expired");
    if ("AUTO_APPROVED".equals(receipt.sigAlg())) return PlatformVerification.refuse("a platform receipt cannot be auto-approved");
    ApprovalReceipt ar = new ApprovalReceipt(receipt.canonicalPayload(), null, null, "", Map.of(), receipt.signatures(),
        receipt.signerDid(), receipt.signerPublicKey(), receipt.signature(), receipt.sigAlg(), receipt.authenticatorData(),
        receipt.clientDataJSON(), null, receipt.verificationCode());
    List<ApprovalWitness> ws = witnessesOf(ar);
    if (ws.isEmpty()) return PlatformVerification.refuse("receipt missing signature material");
    if (ws.size() > Div.MAX_WITNESSES) return PlatformVerification.refuse("receipt carries too many witnesses");
    VerifyOptions effective = VerifyOptions.builder().expectedOrigin(opts.expectedOrigin()).expectedRpId(expected.rpId())
        .requireUserVerification(opts.requireUserVerification() == null || opts.requireUserVerification())
        .allowCrossOrigin(opts.allowCrossOrigin()).asOf(now).clockSkewSeconds((int) skew).build();
    Set<String> verified = new LinkedHashSet<>(); List<String> failures = new ArrayList<>();
    for (ApprovalWitness w : ws) {
      if (!"WEBAUTHN".equals(w.sigAlg())) { failures.add("signer " + w.signerDid() + " used a bare key; platform receipts are WebAuthn-only"); continue; }
      ApproverTrustAnchor.Candidates cs = expected.approvers().candidatesRestricted(w.signerDid(), w.signerPublicKey(), null);
      if (cs.error() != null) { failures.add(cs.error()); continue; }
      boolean ok = false; String last = "signature does not verify against any trusted subject key";
      for (ApproverTrustAnchor.Candidate c : cs.list()) { last = verifyWitness(w, c.key(), ar, effective); if (last.isEmpty()) { verified.add(c.identity()); ok = true; break; } }
      if (!ok) failures.add(last);
    }
    if (verified.isEmpty()) return PlatformVerification.refuse("no valid subject signature" + foldFailures(failures));
    List<String> signers = new ArrayList<>(verified); Collections.sort(signers);
    return new PlatformVerification(true, null, signers);
  }

  /** Verify a quorum-sealed DIV §5b authority. It never verifies as an approval. */
  public static AgentAuthorityVerification verifyAgentAuthority(
      ApprovalReceipt receipt, AgentAuthorityExpected expected, VerifyOptions opts) {
    try {
      return verifyAgentAuthorityChecked(receipt, expected, opts == null ? VerifyOptions.defaults() : opts);
    } catch (RuntimeException e) {
      return AgentAuthorityVerification.refuse("malformed receipt or verification input");
    }
  }

  private static AgentAuthorityVerification verifyAgentAuthorityChecked(
      ApprovalReceipt receipt, AgentAuthorityExpected expected, VerifyOptions opts) {
    com.fasterxml.jackson.databind.JsonNode p;
    try { p = Records.JSON.readTree(receipt.canonicalPayload()); }
    catch (Exception e) { return AgentAuthorityVerification.refuse("canonicalPayload is not valid JSON"); }
    if (p.path("v").asInt(-1) != Div.VERSION) return AgentAuthorityVerification.refuse("unsupported DIV payload version");
    if (!Div.AGENT_AUTHORITY_TYPE.equals(p.path("type").asText())) return AgentAuthorityVerification.refuse("payload is not a div-agent-authority");
    List<String> patterns = new ArrayList<>();
    if (!p.path("actionPatterns").isArray()) return AgentAuthorityVerification.refuse("authority is missing a valid actionPatterns set");
    for (com.fasterxml.jackson.databind.JsonNode n : p.path("actionPatterns")) { if (!n.isTextual() || n.asText().isEmpty()) return AgentAuthorityVerification.refuse("authority is missing a valid actionPatterns set"); patterns.add(n.asText()); }
    if (patterns.isEmpty()) return AgentAuthorityVerification.refuse("authority is missing a valid actionPatterns set");
    com.fasterxml.jackson.databind.JsonNode parentNode = p.get("parentReceiptHash");
    if (parentNode == null) return AgentAuthorityVerification.refuse("authority is missing parentReceiptHash");
    String parentReceiptHash = null;
    if (!parentNode.isNull()) {
      if (!parentNode.isTextual() || !parentNode.asText().matches("sha256:[0-9a-f]{64}"))
        return AgentAuthorityVerification.refuse("authority has invalid parentReceiptHash");
      parentReceiptHash = parentNode.asText();
    }
    String sealedAt = p.path("sealedAt").asText(""); String expiresAt = p.path("expiresAt").asText(""); String nonce = p.path("nonce").asText("");
    Instant sealed; Instant expiry;
    try { sealed = Instant.parse(sealedAt); } catch (Exception e) { return AgentAuthorityVerification.refuse("sealedAt is not a valid RFC3339 timestamp"); }
    try { expiry = Instant.parse(expiresAt); } catch (Exception e) { return AgentAuthorityVerification.refuse("expiresAt is not a valid RFC3339 timestamp"); }
    if (expiry.isBefore(sealed)) return AgentAuthorityVerification.refuse("authority expires before it was sealed");
    Instant now = opts.asOf() == null ? Instant.now() : opts.asOf(); long skew = opts.clockSkewSeconds() == null ? Div.DEFAULT_CLOCK_SKEW_SECONDS : opts.clockSkewSeconds();
    if (sealed.isAfter(now.plusSeconds(skew))) return AgentAuthorityVerification.refuse("authority is sealed in the future (DIV §5b.2)");
    if (!opts.allowExpired() && now.isAfter(expiry.plusSeconds(skew))) return AgentAuthorityVerification.refuse("authority has expired");
    if (receipt.requester() == null) return AgentAuthorityVerification.refuse("authority missing requester");
    ApprovalRequirement requirement;
    try { requirement = Records.JSON.treeToValue(p.path("requirement"), ApprovalRequirement.class); }
    catch (Exception e) { return AgentAuthorityVerification.refuse("authority payload is missing the signed approval requirement"); }
    if (requirement == null || requirement.requiredApprovals() < 1) return AgentAuthorityVerification.refuse(INVALID_QUORUM_REASON);
    String classProblem = checkSignerClass(requirement); if (classProblem != null) return AgentAuthorityVerification.refuse(classProblem);
    if (expected == null || isEmpty(expected.target()) || isEmpty(expected.agentDid()) || expected.approvers() == null)
      return AgentAuthorityVerification.refuse("expected target, agentDid and approvers are required");
    String rebuilt = canonicalAgentAuthorityPayload(expected.target(), patterns, receipt.actionDescription(), expected.agentDid(), receipt.requester(), requirement, nonce, sealedAt, expiresAt, parentReceiptHash);
    if (!rebuilt.equals(receipt.canonicalPayload())) return AgentAuthorityVerification.refuse("target/agent/actionPatterns do not match what was sealed");
    if ("AUTO_APPROVED".equals(receipt.sigAlg())) return AgentAuthorityVerification.refuse("an agent authority cannot be auto-approved");
    List<ApprovalWitness> ws = witnessesOf(receipt); if (ws.isEmpty()) return AgentAuthorityVerification.refuse("authority missing signature material");
    if (ws.size() > Div.MAX_WITNESSES) return AgentAuthorityVerification.refuse("authority carries too many witnesses");
    if (requirement.requesterCannotApprove() && expected.approvers().isKeySetMode())
      return AgentAuthorityVerification.refuse("requesterCannotApprove requires a DID-mode trust anchor");
    Set<String> verified = new LinkedHashSet<>(); List<String> failures = new ArrayList<>();
    for (ApprovalWitness w : ws) {
      ApproverTrustAnchor.Candidates cs = expected.approvers().candidatesRestricted(w.signerDid(), w.signerPublicKey(), null);
      if (cs.error() != null) { failures.add(cs.error()); continue; }
      String matched = null; String last = "signature does not verify against any trusted approver key";
      for (ApproverTrustAnchor.Candidate c : cs.list()) { last = verifyWitness(w, c.key(), receipt, opts); if (last.isEmpty()) { matched = c.identity(); break; } }
      if (matched == null) { failures.add(last); continue; }
      if (requirement.requireHardwareKey() && !"WEBAUTHN".equals(w.sigAlg())) { failures.add("hardware-backed WebAuthn credential required"); continue; }
      if (requirement.requesterCannotApprove() && Objects.equals(w.signerDid(), receipt.requester().did())) { failures.add("four-eyes: requester cannot seal their own authority"); continue; }
      verified.add(matched);
    }
    if (verified.size() < requirement.requiredApprovals()) return AgentAuthorityVerification.refuse("authority quorum not met: " + verified.size() + " of " + requirement.requiredApprovals() + foldFailures(failures));
    List<String> signers = new ArrayList<>(verified); Collections.sort(signers);
    List<String> scope = new ArrayList<>(new LinkedHashSet<>(patterns)); Collections.sort(scope);
    return new AgentAuthorityVerification(true, null, new VerifiedAgentAuthority(expected.agentDid(), expected.target(), scope, nonce, signers, sealedAt, expiresAt, parentReceiptHash));
  }

  /** Just enough of the DIV Intent Payload to gate version/type and read nonce/expiry back. */
  private record CanonicalFields(
      @JsonProperty("v") Integer v,
      String type,
      String nonce,
      String expiresAt,
      String exp,
      com.fasterxml.jackson.databind.JsonNode agent,
      String challengedAt,
      String sealedAt,
      List<String> delegatedTo,
      Integer delegatedQuorum,
      ApprovalRequirement requirement) {}

  /**
   * Verifies an {@link ApprovalReceipt} offline. A WEBAUTHN receipt additionally requires
   * {@code opts.expectedOrigin} and {@code opts.expectedRpId}.
   */
  public static VerifyResult verifyApprovalReceipt(
      ApprovalReceipt receipt, Expected expected, VerifyOptions opts) {
    if (isEmpty(receipt.canonicalPayload())) {
      return VerifyResult.refuse("missing canonicalPayload");
    }

    CanonicalFields fields;
    try {
      fields = Records.JSON.readValue(receipt.canonicalPayload(), CanonicalFields.class);
    } catch (Exception e) {
      return VerifyResult.refuse("canonicalPayload is not valid JSON");
    }
    if (fields.v() == null || fields.v() != Div.VERSION) {
      return VerifyResult.refuse("unsupported DIV payload version");
    }
    // A DELEGATION authorizes nothing (DIV §5a.5). Refused here unconditionally — there is
    // deliberately NO option that would let one through, because a delegation that could authorize
    // its own action would be exactly the pre-signed bearer capability the design exists to avoid.
    if (Div.DELEGATION_TYPE.equals(fields.type())) {
      return VerifyResult.refuse(
          "this is a delegation, which authorizes no action on its own — verify it with"
              + " VerifyDelegation and pass the result as opts.Delegation, together with an offline"
              + " approval signed by the delegated operators");
    }
    boolean offline = Div.OFFLINE_INTENT_TYPE.equals(fields.type());
    if (!offline && !Div.INTENT_TYPE.equals(fields.type())) {
      return VerifyResult.refuse("payload is not a div-intent-verification");
    }
    if (offline && !opts.allowOffline()) {
      return VerifyResult.refuse(
          "this is an offline approval; set AllowOffline at the specific call site permitted to run under one");
    }
    // A delegation only ever substitutes the approver set for an OFFLINE proof. Accepting it
    // against an ordinary gateway-mediated receipt would silently replace the quorum the gateway
    // enforced.
    if (opts.delegation() != null && !offline) {
      return VerifyResult.refuse("a delegation can only substitute the approver set for an offline approval");
    }
    // Naming the redeemed nonce is the caller's responsibility (DIV §5 steps 10-11), so an omitted
    // one refuses instead of being coerced to "" — coercion would let a payload carrying an empty
    // nonce satisfy a caller that never issued a challenge at all.
    if (isEmpty(expected.nonce())) {
      return VerifyResult.refuse(
          "expected.Nonce is required — it must be the challenge YOU issued (DIV §5 step 10)");
    }
    if (!Objects.equals(nz(fields.nonce()), expected.nonce())) {
      return VerifyResult.refuse("receipt is for a different challenge");
    }

    // NOTE: the AUTO_APPROVED decision deliberately does NOT live here. Accepting it before the
    // canonical payload has been recomputed would attest a receipt on the strength of a matching
    // nonce alone — see the block after the expiry check below.

    if (receipt.requester() == null) {
      return VerifyResult.refuse("receipt missing requester");
    }
    boolean agentIntent = fields.agent() != null;
    if (agentIntent != (expected.agentContext() != null))
      return VerifyResult.refuse("agent receipt requires independently asserted PEP context");
    String expiresAt = agentIntent ? fields.exp() : fields.expiresAt();
    if (isEmpty(expiresAt)) {
      return VerifyResult.refuse("receipt missing expiration");
    }
    if (agentIntent) {
      String contextProblem = validateAgentContext(expected.agentContext(), expiresAt, receipt.sigAlg());
      if (contextProblem != null) return VerifyResult.refuse("invalid independently asserted agent context: " + contextProblem);
      Object nestedAgent = expected.agentContext().get("agent");
      if (nestedAgent instanceof Map<?, ?> agentMap && agentMap.get("delegatedBy") != null)
        return VerifyResult.refuse("delegated agent receipt requires a trusted root-to-leaf authority chain");
      try {
        Object rawNbf = expected.agentContext().get("nbf");
        if (!(rawNbf instanceof String nbf)) return VerifyResult.refuse("invalid agent nbf");
        Instant from = Instant.parse(nbf), to = Instant.parse(expiresAt);
        Instant now = opts.asOf() == null ? Instant.now() : opts.asOf();
        long skew = opts.clockSkewSeconds() == null ? Div.DEFAULT_CLOCK_SKEW_SECONDS : opts.clockSkewSeconds();
        if (from.isAfter(now.plusSeconds(skew))) return VerifyResult.refuse("agent approval is not valid yet");
      } catch (RuntimeException e) { return VerifyResult.refuse("invalid agent validity window"); }
    }
    // Both fail closed, as verifyDelegation already does for the target: an absent target would be
    // canonicalized as "" and let a receipt minted for another service verify here, and an absent
    // anchor would dereference to nothing instead of reaching the refusal it exists for.
    if (isEmpty(expected.target())) {
      return VerifyResult.refuse(
          "expected.Target is required — it must be YOUR target identifier, asserted independently"
              + " of the receipt (DIV Target Isolation)");
    }
    if (expected.approvers() == null) {
      return VerifyResult.refuse(
          "expected.Approvers is required — the Approver key MUST come from your own trust policy,"
              + " never from the receipt (DIV Invariant 3)");
    }

    // The requirement is part of the SIGNED bytes, so reading it back from the payload is not
    // circular: a forged value changes the string and fails the byte comparison below.
    if (fields.requirement() == null) {
      return VerifyResult.refuse("receipt payload is missing the signed approval requirement");
    }
    String quorumProblem = checkQuorumMinimum(fields.requirement());
    if (quorumProblem != null) {
      return VerifyResult.refuse(quorumProblem);
    }
    String classProblem = checkSignerClass(fields.requirement());
    if (classProblem != null) {
      return VerifyResult.refuse(classProblem);
    }
    // DIV §5-step-3c. Before Local Payload Reconstruction, so an unsupported payload shape does not
    // surface as a params mismatch.
    String evidenceProblem = checkEvidence(receipt.canonicalPayload());
    if (evidenceProblem != null) {
      return VerifyResult.refuse(evidenceProblem);
    }

    // Offline proofs carry challengedAt so the validity WINDOW can be bounded here, not merely at
    // mint. An unparseable expiresAt must be refused HERE rather than relying on the expiry check
    // further down — that check is disabled by AllowExpired, the documented forensic mode, which
    // would leave the cap unenforced on a proof whose window cannot be computed. DIV §5a.3 makes
    // the window the entire revocation story for an offline proof.
    if (offline) {
      if (isEmpty(fields.challengedAt())) {
        return VerifyResult.refuse("offline proof is missing challengedAt");
      }
      OffsetDateTime challenged;
      try {
        challenged = OffsetDateTime.parse(fields.challengedAt());
      } catch (DateTimeParseException e) {
        return VerifyResult.refuse("challengedAt is not a valid RFC3339 timestamp");
      }
      OffsetDateTime expiry;
      try {
        expiry = OffsetDateTime.parse(expiresAt);
      } catch (DateTimeParseException e) {
        return VerifyResult.refuse("expiresAt is not a valid RFC3339 timestamp");
      }
      Duration window = Duration.between(challenged, expiry);
      if (window.isNegative()) {
        return VerifyResult.refuse("offline proof expires before it was challenged");
      }
      if (window.compareTo(Duration.ofMinutes(Div.MAX_OFFLINE_WINDOW_MINUTES)) > 0) {
        return VerifyResult.refuse(String.format(
            "offline window is %.1f minutes, over the %d-minute maximum",
            window.toMillis() / 60000.0, Div.MAX_OFFLINE_WINDOW_MINUTES));
      }
      // The cap above bounds the window's WIDTH; this bounds its POSITION (DIV §5a.3 rule 3).
      // Without it a proof challenged for a date years out, with a compliant 60-minute window,
      // verifies today and keeps verifying until that date — the pre-signed bearer capability
      // §5a.1 rejects. NOT gated on AllowExpired: that override re-examines a proof that WAS valid
      // and has lapsed, and says nothing about one dated in the future.
      if (challenged.toInstant().isAfter(latestAcceptableOrigin(opts))) {
        return VerifyResult.refuse("offline proof is challenged in the future (DIV §5a.3)");
      }
      // A hardware-key policy CANNOT be satisfied offline (DIV §5a.3 step 4): WebAuthn needs a
      // secure context and an RP ID an offline signing surface will not match, so an offline
      // witness is always a bare key. Fail closed, and say why.
      if (fields.requirement().requireHardwareKey()) {
        return VerifyResult.refuse(
            "the signed policy requires a hardware-backed WebAuthn credential, which cannot be"
                + " produced offline — this action cannot be approved out of band (DIV §5a.3)");
      }
    }

    // A delegation substitutes WHO may approve and HOW MANY, and nothing else (DIV §5a.6). Every
    // agreement check is on the SIGNED bytes of both proofs, so neither can widen the other.
    List<String> delegatedTo = null;
    int delegatedQuorum = 0;
    if (opts.delegation() != null) {
      VerifiedDelegation d = opts.delegation();
      OffsetDateTime delegationExpiry;
      try {
        delegationExpiry = OffsetDateTime.parse(d.expiresAt());
      } catch (DateTimeParseException | NullPointerException e) {
        return VerifyResult.refuse("delegation expiresAt is not a valid RFC3339 timestamp");
      }
      if (!opts.allowExpired()) {
        Instant now = opts.asOf() != null ? opts.asOf() : Instant.now();
        int skew = opts.clockSkewSeconds() != null ? opts.clockSkewSeconds() : Div.DEFAULT_CLOCK_SKEW_SECONDS;
        if (now.isAfter(delegationExpiry.toInstant().plusSeconds(skew))) {
          return VerifyResult.refuse(
              "delegation has expired (set AllowExpired for audit re-verification)");
        }
      }
      if (!Objects.equals(nz(d.target()), nz(expected.target()))) {
        return VerifyResult.refuse("the delegation was issued for a different target");
      }
      if (!Objects.equals(nz(d.actionType()), nz(expected.actionType()))) {
        return VerifyResult.refuse("the delegation was issued for a different actionType");
      }
      String delegationParams;
      String executingParams;
      try {
        delegationParams = Canonical.stableStringify(d.params());
        executingParams = Canonical.stableStringify(expected.params());
      } catch (Canonical.NonPortableValueException e) {
        // A non-portable number, not a mismatch — say so, rather than sending the caller hunting
        // for a tampering that isn't there.
        return VerifyResult.refuse("params are not canonicalizable: " + e.getMessage());
      }
      if (!delegationParams.equals(executingParams)) {
        return VerifyResult.refuse("the delegation was issued for different params");
      }
      // The offline payload's signed quorum must equal the delegated one, so the operators signed
      // the policy their signatures are being counted toward rather than a different one.
      if (fields.requirement().requiredApprovals() != d.delegatedQuorum()) {
        return VerifyResult.refuse(String.format(
            "offline proof declares %d required approval(s) but the delegation delegates a quorum of %d",
            fields.requirement().requiredApprovals(), d.delegatedQuorum()));
      }
      delegatedTo = d.delegatedTo();
      delegatedQuorum = d.delegatedQuorum();
    }

    String recomputed;
    try {
      if (offline) {
        recomputed = Canonical.canonicalOfflineIntentPayload(
            expected.target(),
            expected.actionType(),
            receipt.actionDescription(),
            expected.params(),
            receipt.requester(),
            fields.requirement(),
            fields.nonce(),
            fields.challengedAt(),
            expiresAt);
      } else {
        recomputed = Canonical.canonicalIntentPayload(
            expected.target(),
            expected.actionType(),
            receipt.actionDescription(),
            expected.params(),
            receipt.requester(),
            fields.requirement(),
            fields.nonce(),
            expiresAt,
            agentIntent ? expected.agentContext() : null);
      }
    } catch (Canonical.NonPortableValueException e) {
      // Almost always expected.params carrying a non-portable number. Deliberately DISTINCT from
      // the mismatch below: "do not match" would send an operator chasing a tampering that isn't there.
      return VerifyResult.refuse("expected.Params is not canonicalizable: " + e.getMessage());
    }

    if (!recomputed.equals(receipt.canonicalPayload())) {
      return VerifyResult.refuse("target/params/actionType do not match what was approved");
    }

    // Expiration (DIV §5.8/§6.2). Fail-closed by default; opt out only for audit re-verification.
    if (!opts.allowExpired()) {
      OffsetDateTime expiry;
      try {
        expiry = OffsetDateTime.parse(expiresAt);
      } catch (DateTimeParseException e) {
        return VerifyResult.refuse("expiresAt is not a valid RFC3339 timestamp");
      }
      Instant now = opts.asOf() != null ? opts.asOf() : Instant.now();
      int skew = opts.clockSkewSeconds() != null ? opts.clockSkewSeconds() : Div.DEFAULT_CLOCK_SKEW_SECONDS;
      if (now.isAfter(expiry.toInstant().plusSeconds(skew))) {
        return VerifyResult.refuse("proof has expired (set AllowExpired for audit re-verification)");
      }
    }

    // A policy AUTO_APPROVED receipt carries NO human signature, so there is nothing to verify
    // cryptographically and a relying party must opt in. Opting in waives the SIGNATURE
    // requirement — it does not waive DIV §5 steps 8 and 9, which is why this sits AFTER the
    // canonical payload comparison and the expiry check.
    if ("AUTO_APPROVED".equals(receipt.sigAlg())) {
      // An offline approval with no human signature is a contradiction: the entire premise is that
      // humans signed out of band, so AllowAutoApproved must not rescue it.
      if (offline) {
        return VerifyResult.refuseAutoApproved(
            "an offline approval cannot be auto-approved — there is no human signature to verify");
      }
      if (!opts.allowAutoApproved()) {
        return VerifyResult.refuseAutoApproved("AUTO_APPROVED receipts are refused by default");
      }
      return VerifyResult.acceptAutoApproved();
    }

    List<ApprovalWitness> witnesses = witnessesOf(receipt);
    if (witnesses.isEmpty()) {
      return VerifyResult.refuse("missing signature or public key");
    }
    // The witness list is attacker-supplied and every entry costs ECDSA verifications, in the
    // relying party's own process, immediately before the action it gates. Bound it.
    if (witnesses.size() > Div.MAX_WITNESSES) {
      return VerifyResult.refuse(String.format(
          "receipt carries %d witnesses, above the %d this verifier will process",
          witnesses.size(), Div.MAX_WITNESSES));
    }

    if (fields.requirement().requesterCannotApprove() && expected.approvers().isKeySetMode())
      return VerifyResult.refuse("requesterCannotApprove requires a DID-mode trust anchor");
    // Count DISTINCT approvers whose signature verifies under a key we independently trust.
    // Distinct is load-bearing: without it, N copies of one approver's signature satisfy an N-of-M
    // quorum.
    Set<String> verified = new LinkedHashSet<>();
    List<String> failures = new ArrayList<>();
    for (ApprovalWitness w : witnesses) {
      ApproverTrustAnchor.Candidates cands =
          expected.approvers().candidatesRestricted(w.signerDid(), w.signerPublicKey(), delegatedTo);
      if (cands.error() != null) {
        failures.add(cands.error());
        continue;
      }
      String matched = null;
      String last = "signature does not verify against any trusted approver key";
      for (ApproverTrustAnchor.Candidate c : cands.list()) {
        String why = verifyWitness(w, c.key(), receipt, opts);
        if (why.isEmpty()) {
          matched = c.identity();
          break;
        }
        last = why;
      }
      if (matched == null) {
        failures.add(last);
        continue;
      }
      // A hardware-key policy is only partially checkable offline: a bare P-256 key carries no
      // attestation at all, so it can never satisfy the requirement, while a WebAuthn assertion is
      // accepted without proving the authenticator's model.
      if (fields.requirement().requireHardwareKey() && !"WEBAUTHN".equals(w.sigAlg())) {
        failures.add("signer " + w.signerDid()
            + " used a bare key, but the signed policy requires a hardware-backed WebAuthn credential");
        continue;
      }
      // Four-eyes, verified offline against the requester in the same signed payload.
      if (fields.requirement().requesterCannotApprove()
          && Objects.equals(w.signerDid(), receipt.requester().did())) {
        failures.add("four-eyes: requester " + w.signerDid() + " cannot approve their own action");
        continue;
      }
      verified.add(matched);
    }

    // Under a delegation the quorum is the DELEGATED one. Already checked to equal the offline
    // payload's signed requiredApprovals, so this is the same number by a different route — stated
    // explicitly so the substitution is visible where it takes effect.
    int required = fields.requirement().requiredApprovals();
    if (delegatedQuorum > 0) {
      required = delegatedQuorum;
    }
    if (verified.size() < required) {
      return VerifyResult.refuse(String.format(
          "quorum not met: %d of %d required approver signatures verified%s",
          verified.size(), required, foldFailures(failures)));
    }
    List<String> signers = new ArrayList<>(verified);
    Collections.sort(signers);
    return VerifyResult.accept(signers);
  }

  /**
   * Verifies a DELEGATION (DIV §5a.6 step 1) — a statement, signed in advance by the ordinary
   * quorum, naming local operators who may approve one pre-declared action while the gateway is
   * unreachable. Deliberately SEPARATE from {@link #verifyApprovalReceipt}, which refuses this
   * payload type outright: a delegation authorizes nothing, and the only way to keep that true
   * structurally is to make it impossible to hand one to the approval verifier and get an OK back.
   *
   * <p>{@code expected.approvers} MUST be the ORDINARY approver set, not the delegated operators:
   * the point of the check is that the people entitled to approve this action are the ones who
   * signed away that entitlement.
   */
  public static DelegationVerification verifyDelegation(
      ApprovalReceipt receipt, Expected expected, VerifyOptions opts) {
    if (isEmpty(receipt.canonicalPayload())) {
      return refuseDelegation("missing canonicalPayload");
    }
    CanonicalFields fields;
    try {
      fields = Records.JSON.readValue(receipt.canonicalPayload(), CanonicalFields.class);
    } catch (Exception e) {
      return refuseDelegation("canonicalPayload is not valid JSON");
    }
    if (fields.v() == null || fields.v() != Div.VERSION) {
      return refuseDelegation("unsupported DIV payload version");
    }
    if (!Div.DELEGATION_TYPE.equals(fields.type())) {
      return refuseDelegation("payload is not a div-delegation");
    }
    if (expected.approvers() == null) {
      return refuseDelegation(
          "expected.Approvers is required — the Approver key MUST come from your own trust policy,"
              + " never from the receipt (DIV Invariant 3)");
    }
    // DIV §4.4.6: a Delegation REQUIRES an identity-associating anchor and MUST be refused under a
    // key-set anchor — at seal verification too, not only when delegatedTo is enforced at use time.
    // The sealing quorum names PEOPLE; in public-keys mode it would count credentials instead.
    if (expected.approvers().isKeySetMode()) {
      return refuseDelegation(
          "a delegation requires a DID-mode trust anchor (ApproverTrustAnchor.ofDids/ofDidsMultiKey);"
              + " a key-set anchor cannot associate identities (DIV §4.4.6)");
    }
    if (fields.delegatedTo() == null || fields.delegatedTo().isEmpty()) {
      return refuseDelegation("delegation is missing a valid delegatedTo set");
    }
    if (fields.delegatedQuorum() == null || fields.delegatedQuorum() < 1) {
      return refuseDelegation("delegation is missing a valid delegatedQuorum");
    }
    // Deduplicate before the size check: a delegatedTo listing one operator three times would
    // otherwise appear to support a 3-of-3 quorum that one person could satisfy alone.
    Set<String> distinct = new LinkedHashSet<>();
    for (String d : fields.delegatedTo()) {
      if (d != null && !d.isEmpty()) {
        distinct.add(d);
      }
    }
    if (distinct.size() < fields.delegatedQuorum()) {
      return refuseDelegation(String.format(
          "delegation names %d distinct operator(s) but delegates a quorum of %d — it can never be satisfied",
          distinct.size(), fields.delegatedQuorum()));
    }
    if (isEmpty(fields.sealedAt())) {
      return refuseDelegation("delegation is missing sealedAt");
    }
    if (isEmpty(fields.expiresAt())) {
      return refuseDelegation("delegation is missing expiresAt");
    }
    OffsetDateTime sealed;
    try {
      sealed = OffsetDateTime.parse(fields.sealedAt());
    } catch (DateTimeParseException e) {
      return refuseDelegation("sealedAt is not a valid RFC3339 timestamp");
    }
    OffsetDateTime expiry;
    try {
      expiry = OffsetDateTime.parse(fields.expiresAt());
    } catch (DateTimeParseException e) {
      return refuseDelegation("expiresAt is not a valid RFC3339 timestamp");
    }
    Duration window = Duration.between(sealed, expiry);
    if (window.isNegative()) {
      return refuseDelegation("delegation expires before it was sealed");
    }
    if (window.compareTo(Duration.ofHours(Div.MAX_DELEGATION_WINDOW_HOURS)) > 0) {
      return refuseDelegation(String.format(
          "delegation window is %.1f hours, over the %d-hour maximum",
          window.toMillis() / 3600000.0, Div.MAX_DELEGATION_WINDOW_HOURS));
    }
    // Position, not just width (DIV §5a.6 step 1, mirroring §5a.3 rule 3). A forward-dated sealedAt
    // slides the 72-hour window arbitrarily far out, and §5a.8 names that cap as Delegation's ONLY
    // mitigation. Unconditional, like the offline mirror: AllowExpired does not reach it.
    if (sealed.toInstant().isAfter(latestAcceptableOrigin(opts))) {
      return refuseDelegation("delegation is sealed in the future (DIV §5a.6)");
    }
    if (receipt.requester() == null) {
      return refuseDelegation("delegation missing requester");
    }
    if (fields.requirement() == null) {
      return refuseDelegation("delegation payload is missing the signed approval requirement");
    }
    String quorumProblem = checkQuorumMinimum(fields.requirement());
    if (quorumProblem != null) {
      return refuseDelegation(quorumProblem);
    }
    String classProblem = checkSignerClass(fields.requirement());
    if (classProblem != null) {
      return refuseDelegation(classProblem);
    }
    if (isEmpty(expected.target())) {
      return refuseDelegation(
          "expected.Target is required — it must be YOUR target identifier, asserted independently"
              + " of the delegation (DIV Target Isolation)");
    }

    String recomputed;
    try {
      recomputed = Canonical.canonicalDelegationPayload(
          expected.target(),
          expected.actionType(),
          receipt.actionDescription(),
          expected.params(),
          receipt.requester(),
          fields.requirement(),
          fields.delegatedTo(),
          fields.delegatedQuorum(),
          fields.nonce(),
          fields.sealedAt(),
          fields.expiresAt());
    } catch (Canonical.NonPortableValueException e) {
      return refuseDelegation("expected.Params is not canonicalizable: " + e.getMessage());
    }
    if (!recomputed.equals(receipt.canonicalPayload())) {
      return refuseDelegation("target/params/actionType do not match what was delegated");
    }

    if (!opts.allowExpired()) {
      Instant now = opts.asOf() != null ? opts.asOf() : Instant.now();
      int skew = opts.clockSkewSeconds() != null ? opts.clockSkewSeconds() : Div.DEFAULT_CLOCK_SKEW_SECONDS;
      if (now.isAfter(expiry.toInstant().plusSeconds(skew))) {
        return refuseDelegation("delegation has expired (set AllowExpired for audit re-verification)");
      }
    }
    if ("AUTO_APPROVED".equals(receipt.sigAlg())) {
      return refuseDelegation(
          "a delegation cannot be auto-approved — delegating approval authority requires human signatures");
    }

    List<ApprovalWitness> witnesses = witnessesOf(receipt);
    if (witnesses.isEmpty()) {
      return refuseDelegation("delegation missing signature material");
    }
    // Same denial-of-service bound as the approval path.
    if (witnesses.size() > Div.MAX_WITNESSES) {
      return refuseDelegation(String.format(
          "delegation carries %d witnesses, above the %d this verifier will process",
          witnesses.size(), Div.MAX_WITNESSES));
    }
    Set<String> verified = new LinkedHashSet<>();
    List<String> failures = new ArrayList<>();
    for (ApprovalWitness w : witnesses) {
      ApproverTrustAnchor.Candidates cands =
          expected.approvers().candidatesRestricted(w.signerDid(), w.signerPublicKey(), null);
      if (cands.error() != null) {
        failures.add(cands.error());
        continue;
      }
      String matched = null;
      String last = "signature does not verify against any trusted approver key";
      for (ApproverTrustAnchor.Candidate c : cands.list()) {
        String why = verifyWitness(w, c.key(), receipt, opts);
        if (why.isEmpty()) {
          matched = c.identity();
          break;
        }
        last = why;
      }
      if (matched == null) {
        failures.add(last);
        continue;
      }
      if (fields.requirement().requireHardwareKey() && !"WEBAUTHN".equals(w.sigAlg())) {
        failures.add("signer " + w.signerDid()
            + " used a bare key, but the signed policy requires a hardware-backed WebAuthn credential");
        continue;
      }
      if (fields.requirement().requesterCannotApprove()
          && Objects.equals(w.signerDid(), receipt.requester().did())) {
        failures.add("four-eyes: requester " + w.signerDid() + " cannot delegate to themselves");
        continue;
      }
      verified.add(matched);
    }
    int required = fields.requirement().requiredApprovals();
    if (verified.size() < required) {
      return refuseDelegation(String.format(
          "delegation quorum not met: %d of %d required approver signatures verified%s",
          verified.size(), required, foldFailures(failures)));
    }

    List<String> signers = new ArrayList<>(verified);
    Collections.sort(signers);
    return new DelegationVerification(
        new VerifyResult(true, null, false, List.of()),
        new VerifiedDelegation(
            // The DEDUPLICATED set: what gets enforced against witness DIDs later; a duplicate
            // entry must not create the illusion of a larger eligible pool.
            List.copyOf(distinct),
            fields.delegatedQuorum(),
            expected.target(),
            expected.actionType(),
            expected.params(),
            fields.nonce(),
            signers,
            fields.expiresAt()));
  }

  /**
   * Validates requirement.signerClass out of the signed bytes. FAIL CLOSED both ways: an absent
   * class predates (or dropped) the field, and an unrecognized class must never verify as if it
   * were human-approved. "human" is the only class defined today (DIV §4.3.2). Returns null when
   * acceptable, else the refusal reason.
   */
  /**
   * Validate the reserved {@code evidence} field out of the signed bytes (DIV §4.3.4). REQUIRED to
   * be present and REQUIRED to be {@code null} in v1; a non-null value is an evidence-conditioned
   * authorization whose semantics this verifier has not been taught, and must never verify as if it
   * were unconditioned.
   *
   * <p>Uses the tree model rather than {@code CanonicalFields}: {@code Records.JSON} is configured
   * with {@code FAIL_ON_UNKNOWN_PROPERTIES=false} and maps both an absent key and an explicit null
   * onto the same {@code null} reference, so a record component cannot express the absent-vs-null
   * distinction this check is made of. {@code JsonNode.has} can.
   *
   * @return a refusal reason, or null when the field is present and null.
   */
  private static String checkEvidence(String canonicalPayload) {
    com.fasterxml.jackson.databind.JsonNode payload;
    try {
      payload = Records.JSON.readTree(canonicalPayload);
    } catch (Exception e) {
      return "the signed payload is not valid JSON";
    }
    if (!payload.has("evidence")) {
      return "the signed payload is missing evidence (DIV §4.3.4)";
    }
    if (!payload.get("evidence").isNull()) {
      return "the signed payload declares an evidence condition, which this verifier does not"
          + " support — refusing rather than treating it as unconditioned (DIV §4.3.4)";
    }
    return null;
  }

  private static String checkSignerClass(ApprovalRequirement requirement) {
    String signerClass = requirement.signerClass();
    if (signerClass == null || signerClass.isEmpty()) {
      return "the signed requirement is missing signerClass (DIV §4.3.2)";
    }
    if (!"human".equals(signerClass)) {
      return "the signed requirement declares signerClass \"" + signerClass
          + "\", which this verifier does not recognize — refusing rather than treating it as"
          + " human-approved (DIV §4.3.2)";
    }
    return null;
  }

  /** Shared refusal text for a signed quorum below DIV §4.3.2's minimum. */
  private static final String INVALID_QUORUM_REASON =
      "signed requirement.requiredApprovals must be an integer of at least 1 (DIV §4.3.2)";

  /**
   * Enforces DIV §4.3.2: requiredApprovals is an integer ≥ 1. Stated as its own refusal rather than
   * clamped, because §5 step 7 rejects unless the counted identities are AT LEAST this number — 0 is
   * satisfied by counting nothing, so an unenforced minimum would attest an envelope carrying no
   * valid witness signature. Returns null when acceptable, else the refusal reason.
   */
  private static String checkQuorumMinimum(ApprovalRequirement requirement) {
    return requirement.requiredApprovals() < 1 ? INVALID_QUORUM_REASON : null;
  }

  /**
   * The instant every time-based check shares — expiry (DIV §6.2) and the forward-dating rule of
   * §5a.3 rule 3 — already widened by the caller's skew tolerance.
   */
  private static Instant latestAcceptableOrigin(VerifyOptions opts) {
    Instant now = opts.asOf() != null ? opts.asOf() : Instant.now();
    int skew = opts.clockSkewSeconds() != null ? opts.clockSkewSeconds() : Div.DEFAULT_CLOCK_SKEW_SECONDS;
    return now.plusSeconds(skew);
  }

  /** Renders at most {@link Div#MAX_REPORTED_FAILURES} per-witness reasons, eliding the rest as "+N more". */
  private static String foldFailures(List<String> failures) {
    if (failures.isEmpty()) {
      return "";
    }
    List<String> shown = failures;
    int elided = 0;
    if (failures.size() > Div.MAX_REPORTED_FAILURES) {
      shown = failures.subList(0, Div.MAX_REPORTED_FAILURES);
      elided = failures.size() - Div.MAX_REPORTED_FAILURES;
    }
    String detail = " (" + String.join("; ", shown);
    if (elided > 0) {
      detail += "; +" + elided + " more";
    }
    return detail + ")";
  }

  /** Normalizes a receipt to a witness list: {@code signatures} if present, else the single-signature fields. */
  private static List<ApprovalWitness> witnessesOf(ApprovalReceipt receipt) {
    if (receipt.signatures() != null && !receipt.signatures().isEmpty()) {
      // Same guard the single-signature branch below applies, and for the same reason: the list is
      // attacker-supplied JSON, so "signatures":[null] or a witness with no signature must drop out
      // here rather than reach a base64 decoder as an NPE this method's callers do not catch.
      List<ApprovalWitness> usable = new ArrayList<>(receipt.signatures().size());
      for (ApprovalWitness w : receipt.signatures()) {
        if (w != null && w.signature() != null) {
          usable.add(w);
        }
      }
      return usable;
    }
    if (receipt.signerPublicKey() == null || receipt.signature() == null) {
      return List.of();
    }
    return List.of(new ApprovalWitness(
        receipt.signerDid() == null ? "" : receipt.signerDid(),
        receipt.signerPublicKey(),
        receipt.signature(),
        receipt.sigAlg(),
        receipt.authenticatorData(),
        receipt.clientDataJSON()));
  }

  /** Verifies one witness using an already-TRUSTED key. Returns "" on success. */
  private static String verifyWitness(
      ApprovalWitness w, String trustedKey, ApprovalReceipt receipt, VerifyOptions opts) {
    if ("WEBAUTHN".equals(w.sigAlg())) {
      return WebAuthnSupport.verifyWitness(w, trustedKey, receipt, opts);
    }
    if (!"ES256".equals(w.sigAlg())) return "unsupported witness signature algorithm";
    // ES256: the human's key signed the canonical payload bytes directly.
    byte[] pubKeyBytes;
    try {
      pubKeyBytes = Base64.getDecoder().decode(trustedKey);
    } catch (IllegalArgumentException e) {
      return "invalid trusted key base64";
    }
    java.security.interfaces.ECPublicKey pub;
    try {
      pub = Ecdsa.parseSpkiP256(pubKeyBytes);
    } catch (Ecdsa.Refusal e) {
      return e.getMessage();
    }
    byte[] sigBytes;
    try {
      sigBytes = Base64.getDecoder().decode(w.signature());
    } catch (IllegalArgumentException e) {
      return "invalid signature base64";
    }
    if (!Ecdsa.verifySignature(
        pub, receipt.canonicalPayload().getBytes(StandardCharsets.UTF_8), sigBytes)) {
      return "signature does not verify against the trusted signer key";
    }
    return "";
  }

  private static DelegationVerification refuseDelegation(String reason) {
    return new DelegationVerification(VerifyResult.refuse(reason), null);
  }

  private static boolean isEmpty(String s) {
    return s == null || s.isEmpty();
  }

  private static String nz(String s) {
    return s == null ? "" : s;
  }

  private Verify() {}
}
