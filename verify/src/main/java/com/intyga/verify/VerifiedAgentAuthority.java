package com.intyga.verify;

import java.util.List;

/** A quorum-sealed authority whose signed scope and validity window verified. */
public record VerifiedAgentAuthority(
    String agentDid,
    String target,
    List<String> actionPatterns,
    String nonce,
    List<String> signers,
    String sealedAt,
    String expiresAt,
    String parentReceiptHash) {}
