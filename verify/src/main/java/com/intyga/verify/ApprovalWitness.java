package com.intyga.verify;

/** One approver's signature over the canonical payload. WebAuthn fields are null for ES256 witnesses. */
public record ApprovalWitness(
    String signerDid,
    String signerPublicKey,
    String signature,
    String sigAlg,
    String authenticatorData,
    String clientDataJSON) {}
