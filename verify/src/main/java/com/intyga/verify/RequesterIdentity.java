package com.intyga.verify;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

/** Who requested the action. {@code attestation} is null for an unattested requester — and that null is signed too. */
public record RequesterIdentity(
    String did,
    RequesterAttestation attestation,
    // A present JSON null binds as "", never null: see NullIsMalformed.
    @JsonDeserialize(using = NullIsMalformed.Did.class) String credentialIssuerDid) {
  /** Source-compatible constructor for receipts without an issuer/controller identity. */
  public RequesterIdentity(String did, RequesterAttestation attestation) {
    this(did, attestation, null);
  }
}
