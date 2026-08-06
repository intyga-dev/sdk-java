package com.intyga.verify;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Offline verification of DIV approval receipts: recompute the canonical payload from the caller's
 * OWN parameters, confirm it byte-matches what was signed, and verify the human's ES256 or WebAuthn
 * signature against a key the caller resolved — no Intyga secret, no network.
 */
public final class Verify {

  /** Just enough of the DIV Intent Payload to gate version/type and read nonce/expiry back. */
  private record CanonicalFields(
      @JsonProperty("v") Integer v,
      String type,
      String nonce,
      String expiresAt,
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
    if (!Objects.equals(nz(fields.nonce()), nz(expected.nonce()))) {
      return VerifyResult.refuse("receipt is for a different challenge");
    }

    // NOTE: the AUTO_APPROVED decision deliberately does NOT live here. Accepting it before the
    // canonical payload has been recomputed would attest a receipt on the strength of a matching
    // nonce alone — see the block after the expiry check below.

    if (receipt.requester() == null) {
      return VerifyResult.refuse("receipt missing requester");
    }
    if (isEmpty(fields.expiresAt())) {
      return VerifyResult.refuse("receipt missing expiresAt");
    }

    // The requirement is part of the SIGNED bytes, so reading it back from the payload is not
    // circular: a forged value changes the string and fails the byte comparison below.
    if (fields.requirement() == null) {
      return VerifyResult.refuse("receipt payload is missing the signed approval requirement");
    }
    String classProblem = checkSignerClass(fields.requirement());
    if (classProblem != null) {
      return VerifyResult.refuse(classProblem);
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
        expiry = OffsetDateTime.parse(fields.expiresAt());
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
            fields.expiresAt());
      } else {
        recomputed = Canonical.canonicalIntentPayload(
            expected.target(),
            expected.actionType(),
            receipt.actionDescription(),
            expected.params(),
            receipt.requester(),
            fields.requirement(),
            fields.nonce(),
            fields.expiresAt());
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
        expiry = OffsetDateTime.parse(fields.expiresAt());
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

    // Count DISTINCT approvers whose signature verifies under a key we independently trust.
    // Distinct is load-bearing: without it, N copies of one approver's signature satisfy an N-of-M
    // quorum.
    Set<String> verified = new LinkedHashSet<>();
    List<String> failures = new ArrayList<>();
    for (ApprovalWitness w : witnesses) {
      ApproverTrustAnchor.Candidates cands =
          expected.approvers().candidatesRestricted(w.signerDid(), delegatedTo);
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
    if (required < 1) {
      required = 1;
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
    if (receipt.requester() == null) {
      return refuseDelegation("delegation missing requester");
    }
    if (fields.requirement() == null) {
      return refuseDelegation("delegation payload is missing the signed approval requirement");
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
          expected.approvers().candidatesRestricted(w.signerDid(), null);
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
    int required = Math.max(fields.requirement().requiredApprovals(), 1);
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
      return receipt.signatures();
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
