package com.intyga.sdk.offline;

import com.intyga.verify.ApproverTrustAnchor;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The DID → keys mapping a DID-mode trust anchor is built from — the Java counterpart of the
 * reference's {@code { dids, resolveKey }}. Inspectable (unlike {@link ApproverTrustAnchor}, which
 * is opaque by design), and convertible with {@link #toTrustAnchor()}.
 *
 * <p>DID mode, not public-keys mode, and that is load-bearing: quorum must count distinct
 * APPROVERS. Flattening every key into one allowlist would let one approver holding a software key
 * and two passkeys satisfy a 3-of-N quorum alone.
 */
public final class ApproverDirectory {
  private final List<String> dids;
  private final Map<String, List<String>> byDid;

  /** Every DID in {@code byDid} is eligible. */
  ApproverDirectory(Map<String, List<String>> byDid) {
    this(new ArrayList<>(byDid.keySet()), byDid);
  }

  /**
   * {@code dids} are the eligible approvers; {@code byDid} may also resolve keys for identities
   * that are NOT eligible, so the verifier can recognise a key bound to one of them.
   */
  ApproverDirectory(List<String> dids, Map<String, List<String>> byDid) {
    Map<String, List<String>> copy = new LinkedHashMap<>();
    byDid.forEach((did, keys) -> copy.put(did, List.copyOf(keys)));
    this.dids = List.copyOf(dids);
    this.byDid = Collections.unmodifiableMap(copy);
  }

  /** The eligible approver DIDs, in bundle (or file) order. */
  public List<String> dids() {
    return dids;
  }

  /**
   * Every key bound to {@code did}, or null when the bundle knows no keys for it. Resolution is
   * wider than eligibility: a non-eligible DID can resolve, and {@link #dids()} alone says who counts.
   */
  public List<String> resolveKey(String did) {
    List<String> keys = byDid.get(did);
    return keys == null || keys.isEmpty() ? null : keys;
  }

  /**
   * The verifier's anchor: each DID's keys count as that ONE approver. A DID listing no keys
   * resolves to none, which only a self-certifying {@code did:intyga:key:} DID can survive.
   */
  public ApproverTrustAnchor toTrustAnchor() {
    return ApproverTrustAnchor.ofDidsMultiKey(
        dids,
        did -> {
          List<String> keys = byDid.get(did);
          return keys == null ? List.of() : keys;
        });
  }
}
