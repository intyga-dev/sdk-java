package com.intyga.sdk;

/**
 * Returned by {@link IntygaClient#consume}. {@code reason} is null when the gateway gave none; it
 * is deliberately uninformative on requester mismatch ("unknown nonce") — the real reason is
 * audited server-side.
 */
public record ConsumeResult(boolean ok, String reason) {}
