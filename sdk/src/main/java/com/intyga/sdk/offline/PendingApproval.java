package com.intyga.sdk.offline;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * A buffered offline approval awaiting reconciliation ({@code <bundleDir>/.pending/<nonce>.json}).
 * It records that an approval HAPPENED; nothing in it authorizes anything.
 *
 * @param usedAt when it was used, {@code toISOString()} form
 * @param receipt the full receipt, as stored — so the gateway can re-verify the approval rather
 *     than take this relying party's word for it. Kept as raw JSON so a record written by another
 *     language's SDK is forwarded exactly as written; {@code ApprovalReceipt.parse(receipt)} reads it.
 * @param delegationNonce the delegation's nonce when one supplied the approver set, else null
 */
public record PendingApproval(
    String nonce,
    String target,
    String actionType,
    String display,
    String usedAt,
    JsonNode receipt,
    String delegationNonce) {}
