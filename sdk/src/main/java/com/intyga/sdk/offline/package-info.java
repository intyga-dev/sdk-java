/**
 * Offline approval (DIV §5a) — for when the gateway cannot be reached. Port of the TypeScript
 * reference ({@code packages/sdk/src/offline.ts}, {@code trust-bundle.ts}, {@code trust-anchor.ts});
 * the contract is {@code docs/OFFLINE-APPROVAL-SDK.md}.
 *
 * <ul>
 *   <li>{@link com.intyga.sdk.offline.TrustBundle} — verify, save and load the gateway-signed trust
 *       bundle; derive approver anchors and the requirement for an action.
 *   <li>{@link com.intyga.sdk.offline.OfflineApproval} — build a challenge, encode and decode the
 *       {@code DIV1:} / {@code SIG1:} envelopes, sign as an approver, and run the whole ceremony.
 *   <li>{@link com.intyga.sdk.offline.TrustAnchorFile} — the customer-authored, unsigned anchor
 *       file, online or offline.
 * </ul>
 *
 * <p>The client's per-call fallback is {@code RequireApprovalOptions.Builder.offline(...)}; it
 * reports {@code ApprovalStatus.OFFLINE_APPROVED}, never {@code APPROVED}, and pending records are
 * reported with {@code IntygaClient.reconcileOfflineApprovals}.
 */
package com.intyga.sdk.offline;
