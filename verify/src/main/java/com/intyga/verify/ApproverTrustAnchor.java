package com.intyga.verify;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

/**
 * The set of approver keys the relying party trusts, resolved from its OWN key-management policy.
 * Supply either {@code publicKeys} (a direct base64 SPKI/COSE allowlist) or {@code dids} plus a
 * resolver (your own directory lookup).
 *
 * <p>{@code resolveKeys} returns EVERY key bound to one DID and takes precedence over
 * {@code resolveKey}. An approver commonly holds a software key plus registered authenticators, and
 * any of them is legitimately theirs; every key returned counts as that ONE approver, so quorum
 * still counts people rather than credentials.
 */
public final class ApproverTrustAnchor {
  private final List<String> publicKeys;
  private final List<String> dids;
  private final Function<String, String> resolveKey;
  private final Function<String, List<String>> resolveKeys;

  private ApproverTrustAnchor(
      List<String> publicKeys,
      List<String> dids,
      Function<String, String> resolveKey,
      Function<String, List<String>> resolveKeys) {
    this.publicKeys = publicKeys;
    this.dids = dids;
    this.resolveKey = resolveKey;
    this.resolveKeys = resolveKeys;
  }

  /** Direct allowlist mode: the identity IS the key (see the quorum caveat in the README). */
  public static ApproverTrustAnchor ofPublicKeys(List<String> publicKeys) {
    return new ApproverTrustAnchor(List.copyOf(publicKeys), null, null, null);
  }

  /** DID/identity mode with a single-key resolver; return null or "" for an unknown DID. */
  public static ApproverTrustAnchor ofDids(List<String> dids, Function<String, String> resolveKey) {
    return new ApproverTrustAnchor(null, List.copyOf(dids), resolveKey, null);
  }

  /** DID/identity mode with a multi-key resolver — every returned key counts as that ONE approver. */
  public static ApproverTrustAnchor ofDidsMultiKey(
      List<String> dids, Function<String, List<String>> resolveKeys) {
    return new ApproverTrustAnchor(null, List.copyOf(dids), null, resolveKeys);
  }

  /** True in direct-allowlist mode, where the identity IS the key and no DID can be verified. */
  boolean isKeySetMode() {
    return publicKeys != null;
  }

  /** One (key, identity) candidate pair for a witness. */
  record Candidate(String key, String identity) {}

  /** Either a candidate list or a refusal reason — never both. */
  record Candidates(List<Candidate> list, String error) {}

  /**
   * The keys this witness may be accepted under, each tagged with the identity it represents so a
   * quorum counts distinct APPROVERS. In publicKeys mode the identity is the key itself: the
   * receipt's signerDid is unverified there, and counting it would let one approver claim to be
   * three. {@code restrictTo} optionally narrows to the identities a delegation names (DIV §5a.6
   * step 3) — applied ON TOP of the trust anchor, never instead of it.
   */
  Candidates candidatesRestricted(String signerDid, List<String> restrictTo) {
    if (publicKeys != null && !publicKeys.isEmpty()) {
      // A delegation names identities, and in publicKeys mode signerDid is an unverified string —
      // enforcing delegatedTo against it would be security theatre. Refuse rather than pretend.
      if (restrictTo != null) {
        return new Candidates(
            null,
            "a delegation names approver identities, so it requires a DID-mode trust anchor"
                + " (DIDs + ResolveKeys); in PublicKeys mode signerDid is unverified and delegatedTo"
                + " cannot be enforced");
      }
      List<Candidate> out = new ArrayList<>(publicKeys.size());
      for (String k : publicKeys) {
        out.add(new Candidate(k, k));
      }
      return new Candidates(out, null);
    }
    if (dids == null || dids.isEmpty() || (resolveKey == null && resolveKeys == null)) {
      return new Candidates(
          null,
          "expected.Approvers is required — the Approver key MUST come from your own trust policy,"
              + " never from the receipt (DIV Invariant 3)");
    }
    boolean found = signerDid != null && !signerDid.isEmpty() && dids.contains(signerDid);
    if (!found) {
      return new Candidates(null, "signer " + signerDid + " is not an authorized approver");
    }
    if (restrictTo != null && !restrictTo.contains(signerDid)) {
      return new Candidates(null, "signer " + signerDid + " is not named in the delegation");
    }
    List<String> keys;
    if (resolveKeys != null) {
      keys = resolveKeys.apply(signerDid);
    } else {
      String key = resolveKey.apply(signerDid);
      keys = key == null || key.isEmpty() ? List.of() : List.of(key);
    }
    List<Candidate> out = new ArrayList<>();
    if (keys != null) {
      for (String k : keys) {
        if (k != null && !k.isEmpty()) {
          // All keys for one DID share that DID as their identity — quorum still counts one approver.
          out.add(new Candidate(k, signerDid));
        }
      }
    }
    if (out.isEmpty()) {
      return new Candidates(null, "no trusted key could be resolved for " + signerDid);
    }
    return new Candidates(out, null);
  }
}
