package com.intyga.sdk.offline;

import java.util.Map;

/**
 * The action an offline approval is for, asserted by the relying party from its OWN state — the
 * {@code expected} argument of the reference's {@code useOfflineApproval}.
 *
 * @param target this relying party / execution environment (DIV Target Isolation)
 * @param actionType the exact action ID the bundle policy is keyed on
 * @param display the text the approvers see; signed, but never selects a rule
 * @param params the exact structured variables that will execute; signed
 */
public record OfflineAction(String target, String actionType, String display, Map<String, Object> params) {}
