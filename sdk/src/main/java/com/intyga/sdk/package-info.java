/**
 * Java client for Intyga. The primitive is uniform: request a challenge &#8594; a human approves with a
 * passkey or security key &#8594; poll until resolved. It works for AI agents, humans, and any backend
 * service; the only difference is which API key/token you hold.
 *
 * <p>Offline receipt verification is bundled: hand {@link com.intyga.sdk.ApprovalResult#receipt()}
 * to {@code com.intyga.verify.ApprovalReceipt.parse(...)} and
 * {@code com.intyga.verify.Verify.verifyApprovalReceipt(...)} to check what was signed against a key
 * YOU resolved — a receipt checked against the key embedded in itself proves only that it is
 * self-consistent.
 */
package com.intyga.sdk;
