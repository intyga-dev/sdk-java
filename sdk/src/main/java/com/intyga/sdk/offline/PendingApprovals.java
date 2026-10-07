package com.intyga.sdk.offline;

import java.util.List;

/**
 * What {@link OfflineApproval#readPendingApprovals} found in the reconciliation buffer.
 *
 * @param records the readable pending approvals, in file-name order
 * @param unreadable the file names that are not pending approvals anyone can read — still
 *     approvals nobody has reported, so they need a human
 */
public record PendingApprovals(List<PendingApproval> records, List<String> unreadable) {}
