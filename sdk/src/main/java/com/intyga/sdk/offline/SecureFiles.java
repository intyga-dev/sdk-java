package com.intyga.sdk.offline;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;
import java.util.UUID;

/**
 * Files that can prove an incident are private by default: directories 0700, files 0600 where the
 * platform has POSIX modes. Mirrors the reference's {@code secure-files.ts}, so a directory written
 * by one language's tool is just as private when another writes into it.
 */
final class SecureFiles {
  private static final boolean POSIX =
      FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
  private static final Set<PosixFilePermission> DIR_MODE = PosixFilePermissions.fromString("rwx------");
  private static final Set<PosixFilePermission> FILE_MODE = PosixFilePermissions.fromString("rw-------");

  private SecureFiles() {}

  private static FileAttribute<?>[] attrs(Set<PosixFilePermission> mode) {
    return POSIX
        ? new FileAttribute<?>[] {PosixFilePermissions.asFileAttribute(mode)}
        : new FileAttribute<?>[0];
  }

  /** Windows and some network filesystems have no POSIX modes; creation stays exclusive there. */
  private static void repairMode(Path target, Set<PosixFilePermission> mode) {
    if (!POSIX) {
      return;
    }
    try {
      Files.setPosixFilePermissions(target, mode);
    } catch (IOException | UnsupportedOperationException e) {
      // Same posture as the reference: best effort; the caller protects the volume.
    }
  }

  /** Create (or repair) a private directory, refusing one that is a symlink or not a directory. */
  static void ensurePrivateDir(Path dir) throws IOException {
    try {
      Files.createDirectories(dir, attrs(DIR_MODE));
    } catch (FileAlreadyExistsException e) {
      // createDirectories says this when the path exists as anything but a real directory — a
      // symlink to one included.
      throw new IOException("refusing unsafe directory: " + dir);
    }
    if (Files.isSymbolicLink(dir) || !Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)) {
      throw new IOException("refusing unsafe directory: " + dir);
    }
    repairMode(dir, DIR_MODE);
  }

  /** Atomically replace a sensitive file from a same-directory, exclusively created temporary. */
  static void writePrivateFile(Path file, String contents) throws IOException {
    Path dir = file.toAbsolutePath().getParent();
    ensurePrivateDir(dir);
    if (Files.exists(file, LinkOption.NOFOLLOW_LINKS)
        && (Files.isSymbolicLink(file) || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS))) {
      throw new IOException("refusing unsafe file: " + file);
    }
    Path temp =
        dir.resolve("." + file.getFileName() + "." + ProcessHandle.current().pid() + "."
            + UUID.randomUUID() + ".tmp");
    try {
      writeExclusive(temp, contents);
      repairMode(temp, FILE_MODE);
      try {
        Files.move(temp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
      } catch (AtomicMoveNotSupportedException e) {
        Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
      }
      repairMode(file, FILE_MODE);
    } finally {
      Files.deleteIfExists(temp);
    }
  }

  /**
   * Create a marker exactly once: {@code CREATE_NEW} is O_CREAT|O_EXCL, so two processes racing
   * the same path cannot both succeed, and with NOFOLLOW_LINKS an attacker-planted symlink is
   * refused rather than written through. Any failure reads as "not created".
   */
  static boolean createPrivateMarker(Path file, String contents) {
    try {
      ensurePrivateDir(file.toAbsolutePath().getParent());
      writeExclusive(file, contents);
      repairMode(file, FILE_MODE);
      return true;
    } catch (IOException | RuntimeException e) {
      return false;
    }
  }

  private static void writeExclusive(Path file, String contents) throws IOException {
    Set<OpenOption> options =
        Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
    try (SeekableByteChannel ch = Files.newByteChannel(file, options, attrs(FILE_MODE))) {
      ByteBuffer buf = ByteBuffer.wrap(contents.getBytes(StandardCharsets.UTF_8));
      while (buf.hasRemaining()) {
        ch.write(buf);
      }
    }
  }
}
