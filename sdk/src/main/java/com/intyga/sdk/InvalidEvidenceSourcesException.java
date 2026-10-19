package com.intyga.sdk;

/**
 * An evidence-sources file was refused. The message names exactly one problem, prefixed {@code
 * invalid evidence-sources file:} — evidence-source trust is security configuration, so a malformed
 * file fails loudly at load time rather than surfacing later as a statement that silently earns no
 * trust.
 */
public final class InvalidEvidenceSourcesException extends IllegalArgumentException {
  InvalidEvidenceSourcesException(String detail) {
    super("invalid evidence-sources file: " + detail);
  }
}
