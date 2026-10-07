package com.intyga.sdk.offline;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;

/**
 * Default {@link RedemptionStore}: one file per redeemed nonce, {@code <dir>/<nonce>.used},
 * containing the redemption time and created with exclusive create ({@code O_CREAT|O_EXCL}).
 *
 * <p>Exclusive create is atomic on POSIX and on Windows — the OS refuses the open if the path
 * exists, so two processes (in any language) racing the same nonce cannot both succeed. A
 * read-then-write check would lose that race, which is the whole point of the store. A nonce that
 * is not a safe path segment is never redeemed.
 */
public final class FileRedemptionStore implements RedemptionStore {
  private final Path dir;

  /**
   * @throws UncheckedIOException when {@code dir} cannot be created or is not a real directory (a
   *     symlink, say) — refused rather than written through
   */
  public FileRedemptionStore(Path dir) {
    try {
      SecureFiles.ensurePrivateDir(dir);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
    this.dir = dir;
  }

  @Override
  public boolean redeem(String nonce) {
    if (!OfflineApproval.isPathSafeNonce(nonce)) {
      return false;
    }
    return SecureFiles.createPrivateMarker(dir.resolve(nonce + ".used"), JsTime.iso(JsTime.nowOr(null)));
  }
}
