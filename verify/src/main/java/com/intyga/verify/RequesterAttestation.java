package com.intyga.verify;

/** Workload identity attestation of the requester. */
public record RequesterAttestation(String method, String issuer, String subject) {}
