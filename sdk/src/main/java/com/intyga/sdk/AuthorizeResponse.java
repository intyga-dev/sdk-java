package com.intyga.sdk;

/** Returned by {@link IntygaClient#authorize}: the challenge to poll and its initial status. */
public record AuthorizeResponse(String nonce, ApprovalStatus status) {}
