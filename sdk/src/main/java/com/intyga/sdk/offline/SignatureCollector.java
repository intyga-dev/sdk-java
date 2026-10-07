package com.intyga.sdk.offline;

import java.util.List;

/**
 * How the operator gets a challenge to the approvers and their signatures back — a seam, not a
 * default: transporting the envelope is a human, site-specific act (a terminal prompt, a QR code on
 * a console, a phone read-out over a bridge line), and inventing one here would either not fit or
 * quietly assume connectivity. Returns the raw {@code SIG1:} strings; unreadable ones are discarded
 * and reported, never trusted. Blocking; an exception propagates out of {@link
 * OfflineApproval#useOfflineApproval}.
 */
@FunctionalInterface
public interface SignatureCollector {
  List<String> collect(OfflineChallenge challenge);
}
