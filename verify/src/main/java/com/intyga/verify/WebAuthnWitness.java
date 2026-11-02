package com.intyga.verify;

/**
 * One WebAuthn assertion and the exact payload it claims to sign — a single stored witness row, as
 * {@code WebAuthnWitness} in {@code @intyga/verify}. Verify it with
 * {@link Verify#verifyWebAuthnWitness}.
 *
 * @param signedPayload the string whose UTF-8 bytes were the assertion challenge, as signed
 * @param publicKey the credential's P-256 public key, base64 or base64url: a COSE_Key (as recorded
 *     at registration) or DER SubjectPublicKeyInfo. Supply it from YOUR record of the credential,
 *     never from the thing being verified, or any key the presenter chose will do.
 * @param authenticatorData base64 or base64url, as the browser returned it
 * @param clientDataJSON base64 or base64url, as the browser returned it
 * @param signature the DER ECDSA assertion signature, base64 or base64url
 */
public record WebAuthnWitness(
    String signedPayload,
    String publicKey,
    String authenticatorData,
    String clientDataJSON,
    String signature) {}
