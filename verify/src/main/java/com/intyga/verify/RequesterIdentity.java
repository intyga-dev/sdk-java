package com.intyga.verify;

/** Who requested the action. {@code attestation} is null for an unattested requester — and that null is signed too. */
public record RequesterIdentity(String did, RequesterAttestation attestation) {}
