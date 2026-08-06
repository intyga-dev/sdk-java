package com.intyga.sdk;

/**
 * Public witness lookup response: has this document hash been signed, by whom, and when?
 *
 * <p>An unknown hash is an HTTP 200 with {@code verified=false} and status {@code "NOT_FOUND"} —
 * branch on {@link #verified()}, never on the HTTP status code.
 *
 * <p>Named for the lookup rather than "verify" deliberately. The sibling Go and Rust clients call
 * this type {@code VerifyResult}, but they reach their verifier through a package qualifier; in
 * Java both packages sit on one classpath, where that name collides with
 * {@code com.intyga.verify.VerifyResult} under a wildcard import — and, worse, would suggest that
 * {@link IntygaClient#verify(String)} checks a receipt's signature. It does not: it asks the
 * gateway what it recorded. Offline receipt verification is
 * {@code com.intyga.verify.Verify.verifyApprovalReceipt}.
 */
public record WitnessLookupResult(
    boolean verified,
    String status,
    String documentHash,
    String signerDid,
    String signedAt,
    String signatureHash) {}
