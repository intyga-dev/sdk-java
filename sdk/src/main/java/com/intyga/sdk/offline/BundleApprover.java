package com.intyga.sdk.offline;

import java.util.List;

/**
 * One approver and every public key bound to them at export time.
 *
 * @param did the approver's stable identity
 * @param publicKeys base64 SPKI (raw P-256) and/or base64 COSE (WebAuthn credential) keys — all of
 *     them this ONE approver
 * @param offlinePublicKeys base64 SPKI offline signing keys (DIV §5a.4), or null when the bundle
 *     predates them. They count ONLY toward a {@code div-offline-intent} — never a delegation or an
 *     ordinary intent — which is why they are a separate list rather than merged into {@code
 *     publicKeys}. See {@link TrustBundle#approverAnchor}.
 */
public record BundleApprover(String did, List<String> publicKeys, List<String> offlinePublicKeys) {}
