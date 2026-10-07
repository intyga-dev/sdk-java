package com.intyga.sdk;

import java.util.List;

/**
 * Outcome of {@link IntygaClient#reconcileOfflineApprovals}: how many buffered offline approvals
 * the gateway acknowledged (and were cleared), how many were not, and why — one reason per failure,
 * prefixed with the nonce. A failed record stays buffered for the next attempt.
 */
public record ReconcileResult(int reported, int failed, List<String> reasons) {}
