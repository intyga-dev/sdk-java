package com.intyga.verify;

/**
 * The MINIMUM approval requirement the relying party's own policy demands for this action (DIV §5
 * step 3d).
 *
 * <p>The signed requirement is authored by whoever composed the bytes the approvers signed — the
 * issuer, or any one approver composing their own payload — so its signature protects it against
 * third parties but NOT against the signers the quorum constrains. Without a floor a verifier proves
 * only the signers' OWN stated quorum: an approver who is also the requester can sign
 * {@code {requiredApprovals: 1, requesterCannotApprove: false}} alone and it verifies.
 *
 * <p>Only strictly weaker signed values are refused; an equal or stricter one passes and the SIGNED
 * value is then enforced. {@code allowedAaguids} is not floored — express that as
 * {@code requireHardwareKey}.
 *
 * @param requiredApprovals integer ≥ 1; the signed requiredApprovals must be at least this
 * @param requesterCannotApprove when true, the signed requirement must also forbid the requester approving
 * @param requireHardwareKey when true, the signed requirement must also demand a hardware key
 * @param excludedSignerDids when non-null, the signed exclusion set must cover every DID listed
 * @param requireEnrolledDevice when true, the signed requirement must also demand an enrolled
 *     approver device (DIV §4.3.2)
 */
public record RequirementFloor(
    int requiredApprovals, boolean requesterCannotApprove, boolean requireHardwareKey,
    java.util.List<String> excludedSignerDids, boolean requireEnrolledDevice) {

  public RequirementFloor(int requiredApprovals, boolean requesterCannotApprove,
      boolean requireHardwareKey) {
    this(requiredApprovals, requesterCannotApprove, requireHardwareKey, null, false);
  }

  /** Source-compatible constructor for callers predating {@code requireEnrolledDevice}. */
  public RequirementFloor(int requiredApprovals, boolean requesterCannotApprove,
      boolean requireHardwareKey, java.util.List<String> excludedSignerDids) {
    this(requiredApprovals, requesterCannotApprove, requireHardwareKey, excludedSignerDids, false);
  }

  /** This floor, also demanding (or no longer demanding) an enrolled approver device. */
  public RequirementFloor withRequireEnrolledDevice(boolean value) {
    return new RequirementFloor(requiredApprovals, requesterCannotApprove, requireHardwareKey,
        excludedSignerDids, value);
  }

  /** The single malformed-floor text, as {@link #problem} and {@link #fromJson} report it. */
  static final String MALFORMED_REASON = "expected.requirement() is malformed: requiredApprovals must be an"
      + " integer of at least 1 and the flags booleans";

  /**
   * A floor from your policy's JSON form ({@code requiredApprovals}, the optional boolean flags
   * {@code requesterCannotApprove} / {@code requireHardwareKey} / {@code requireEnrolledDevice}, and
   * an optional {@code excludedSignerDids} array). The typed record cannot hold a wrongly typed
   * flag, so this is where the reference's malformed-floor refusal happens for JSON input: a
   * non-integer quorum, a flag that is present but not a boolean (an explicit {@code null}
   * included), or an exclusion set that is not an array of strings throws with that exact text,
   * rather than being coerced or read as "no floor". Values (a quorum below 1, a malformed DID) are
   * still judged by the verifier.
   *
   * @return null for a null or JSON-null node (no floor)
   * @throws IllegalArgumentException with the malformed-floor reason
   */
  public static RequirementFloor fromJson(com.fasterxml.jackson.databind.JsonNode floor) {
    if (floor == null || floor.isNull() || floor.isMissingNode()) return null;
    com.fasterxml.jackson.databind.JsonNode quorum = floor.get("requiredApprovals");
    // An integral JSON number (1 and 1.0 alike, as JavaScript reads them) within int range.
    if (!floor.isObject() || quorum == null || !quorum.isNumber() || !quorum.canConvertToInt()
        || quorum.doubleValue() != Math.rint(quorum.doubleValue())) {
      throw new IllegalArgumentException(MALFORMED_REASON);
    }
    boolean[] flags = new boolean[3];
    String[] names = {"requesterCannotApprove", "requireHardwareKey", "requireEnrolledDevice"};
    for (int i = 0; i < names.length; i++) {
      com.fasterxml.jackson.databind.JsonNode flag = floor.get(names[i]);
      if (flag != null && !flag.isBoolean()) throw new IllegalArgumentException(MALFORMED_REASON);
      flags[i] = flag != null && flag.booleanValue();
    }
    java.util.List<String> excluded = null;
    com.fasterxml.jackson.databind.JsonNode list = floor.get("excludedSignerDids");
    if (list != null) {
      if (!list.isArray()) throw new IllegalArgumentException(MALFORMED_REASON);
      excluded = new java.util.ArrayList<>();
      for (com.fasterxml.jackson.databind.JsonNode did : list) {
        if (!did.isTextual()) throw new IllegalArgumentException(MALFORMED_REASON);
        excluded.add(did.textValue());
      }
    }
    return new RequirementFloor(quorum.intValue(), flags[0], flags[1], excluded, flags[2]);
  }

  /** The reason stem every port uses for a signed requirement below the caller's floor. */
  public static final String WEAKER_REASON =
      "signed requirement is weaker than the relying party's policy";

  /** A quorum-only floor. */
  public static RequirementFloor ofQuorum(int requiredApprovals) {
    return new RequirementFloor(requiredApprovals, false, false, null, false);
  }

  /**
   * DIV §5 step 3d. Returns null when {@code floor} is null (no floor supplied — legacy behaviour) or
   * the signed requirement meets it; otherwise the refusal reason. A malformed floor fails CLOSED
   * rather than silently meaning "no floor".
   */
  static String problem(ApprovalRequirement signed, RequirementFloor floor) {
    if (floor == null) return null;
    // The reference's single malformed-floor text, then its check order: exclusions, quorum,
    // four-eyes, hardware, enrolled device.
    String malformed = MALFORMED_REASON;
    if (floor.requiredApprovals() < 1) return malformed;
    if (floor.excludedSignerDids() != null) {
      // A floor is a SET the signed exclusions must cover, so a repeated DID asks for nothing extra
      // and is accepted, as in the reference (validSignerExclusions) and every other port.
      for (String did : floor.excludedSignerDids()) {
        if (!validDid(did)) return malformed;
      }
      if (signed.excludedSignerDids() == null
          || !signed.excludedSignerDids().containsAll(floor.excludedSignerDids())) {
        return WEAKER_REASON + ": it omits a required signer exclusion";
      }
    }
    if (signed.requiredApprovals() < floor.requiredApprovals()) {
      return WEAKER_REASON + ": it requires " + signed.requiredApprovals() + " approval(s), the policy "
          + floor.requiredApprovals() + " (DIV §5 step 3d)";
    }
    if (floor.requesterCannotApprove() && !signed.requesterCannotApprove()) {
      return WEAKER_REASON + ": it does not forbid the requester approving (DIV §5 step 3d)";
    }
    if (floor.requireHardwareKey() && !signed.requireHardwareKey()) {
      return WEAKER_REASON + ": it does not require a hardware key (DIV §5 step 3d)";
    }
    if (floor.requireEnrolledDevice() && !signed.requiresEnrolledDevice()) {
      return WEAKER_REASON + ": it does not require an enrolled approver device (DIV §5 step 3d)";
    }
    return null;
  }

  private static boolean validDid(String did) {
    if (did == null || !did.startsWith("did:") || did.length() == 4
        || did.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 4096) return false;
    for (int i = 0; i < did.length(); i++) {
      char c = did.charAt(i);
      if (c <= 0x20 || c == 0x7f) return false;
      if (Character.isSurrogate(c)) {
        if (i + 1 >= did.length() || !Character.isSurrogatePair(c, did.charAt(i + 1))) return false;
        i++;
      }
    }
    return true;
  }
}
