package com.intyga.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Generator-independent backstop pins, mirroring verify-go's verify_test.go. The vector suites are
 * the authoritative pin, but they and the vectors share a generator: if the TS reference ever
 * emitted a wrong vector, every port would agree with it. These literals were derived from the
 * DIV/DEWP specs by hand, so they fail independently.
 */
class CanonicalBackstopTest {

  @Test
  void sortsKeysByUtf16CodeUnit() {
    // The comparator, not merely "sorted": U+1F600 (surrogate pair, lead 0xD83D) sorts BEFORE
    // U+FFFD in UTF-16 code-unit order, and AFTER it in UTF-8 byte order. Go and Rust each needed
    // a hand-built comparator to get this right; Java's String.compareTo is already UTF-16.
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("�", 1);
    m.put("😀", 2);
    m.put("z", 3);
    assertEquals("{\"z\":3,\"😀\":2,\"�\":1}", Canonical.stableStringify(m));
  }

  @Test
  void doesNotEscapeHtmlSensitiveCharacters() {
    // The five characters that broke the Go port: <, >, & (HTML escaping) and U+2028/U+2029.
    // RFC 8785 escapes none of them; a port that does recomputes different bytes and reports a
    // valid approval as tampering.
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("t", "a<b>c&d e f");
    assertEquals("{\"t\":\"a<b>c&d e f\"}", Canonical.stableStringify(m));
  }

  @Test
  void escapesOnlyWhatJsonStringifyEscapes() {
    Map<String, Object> m = new LinkedHashMap<>();
    // Octal escapes, deliberately: a literal NUL byte in source is legal but silently manglable,
    // and a backslash-u escape is processed before tokenization (it is a compile error even
    // inside a comment, which is why this sentence spells it out instead).
    m.put("t", "he said \"hi\"\n\tdone\\ \0\037");
    assertEquals(
        "{\"t\":\"he said \\\"hi\\\"\\n\\tdone\\\\ \\u0000\\u001f\"}",
        Canonical.stableStringify(m));
  }

  @Test
  void refusesLoneSurrogatesButNotValidPairs() {
    // RFC 8785 builds on I-JSON, which forbids an unpaired surrogate (DIV §4.1). Escaping it as
    // the TS reference used to do made a receipt carrying one verify in some ports only; every
    // port now refuses it, in values and in member names alike.
    for (String bad : List.of("\uD800", "\uDC00", "\uD800a", "a\uDBFF")) {
      Map<String, Object> value = new LinkedHashMap<>();
      value.put("a", bad);
      assertThrows(Canonical.NonPortableValueException.class, () -> Canonical.stableStringify(value));
      Map<String, Object> key = new LinkedHashMap<>();
      key.put(bad, 1);
      assertThrows(Canonical.NonPortableValueException.class, () -> Canonical.stableStringify(key));
    }

    // A well-formed pair stays literal — escaping it would break every emoji in an approval.
    Map<String, Object> pair = new LinkedHashMap<>();
    pair.put("a", "😀");
    assertEquals("{\"a\":\"😀\"}", Canonical.stableStringify(pair));
  }

  @Test
  void formatsDoublesAsShortestRoundTrip() {
    // ECMAScript Number::toString semantics. 0.1 + 0.2 needs all 17 significant digits; 2.5 needs
    // two. A formatter that emits Java's default representation would disagree with every other port.
    assertEquals("0.30000000000000004", Canonical.stableStringify(0.1 + 0.2));
    assertEquals("2.5", Canonical.stableStringify(2.5));
    assertEquals("0.1", Canonical.stableStringify(0.1));
    assertEquals("0.0001", Canonical.stableStringify(0.0001));
    // Whole-valued doubles serialize as integers, exactly as JSON.stringify does.
    assertEquals("100", Canonical.stableStringify(100.0));
    assertEquals("-7", Canonical.stableStringify(-7.0));
    assertEquals("0", Canonical.stableStringify(0.0));
  }

  @Test
  void refusesNonPortableNumbers() {
    // Each of these serializes one way here and another way in some other port, so bytes signed
    // over one would fail verification elsewhere and read as tampering (DEWP §4.3.1).
    assertThrows(Canonical.NonPortableValueException.class, () -> Canonical.stableStringify(Double.NaN));
    assertThrows(
        Canonical.NonPortableValueException.class,
        () -> Canonical.stableStringify(Double.POSITIVE_INFINITY));
    assertThrows(Canonical.NonPortableValueException.class, () -> Canonical.stableStringify(-0.0));
    assertThrows(Canonical.NonPortableValueException.class, () -> Canonical.stableStringify(1e16));
    assertThrows(Canonical.NonPortableValueException.class, () -> Canonical.stableStringify(1e-5));
    // The boundary values themselves ARE portable and must not be refused.
    assertEquals("9999999999999998", Canonical.stableStringify(9999999999999998.0));
    assertEquals("0.0001", Canonical.stableStringify(1e-4));
  }

  @Test
  void emptyMerkleRootIsDomainSeparated() {
    // sha256(0x02), DEWP §5.1.1 — not sha256("") and not the zero hash.
    assertEquals(Ledger.emptyRoot(), Ledger.merkleRoot(new ArrayList<>()));
    assertEquals(64, Ledger.emptyRoot().length());
    // Leaf and node domains must never collide for the same bytes.
    String leaf = Ledger.hashLeaf("x");
    assertTrue(!leaf.equals(Ledger.hashPair(leaf, leaf)));
  }

  @Test
  void merkleRootDuplicatesLastOnOddLevels() {
    // The padding rule that makes bounds load-bearing: a 3-leaf tree equals the 4-leaf tree whose
    // last leaf repeats. VerifyMerkleProof's bounds are what stop that from forging membership.
    String a = Ledger.hashLeaf("a");
    String b = Ledger.hashLeaf("b");
    String c = Ledger.hashLeaf("c");
    assertEquals(Ledger.merkleRoot(List.of(a, b, c)), Ledger.merkleRoot(List.of(a, b, c, c)));
  }

  @Test
  void expectedPathLengthIsCeilLog2() {
    assertEquals(0, Ledger.expectedPathLength(1));
    assertEquals(1, Ledger.expectedPathLength(2));
    assertEquals(2, Ledger.expectedPathLength(3));
    assertEquals(2, Ledger.expectedPathLength(4));
    assertEquals(3, Ledger.expectedPathLength(5));
    assertEquals(4, Ledger.expectedPathLength(16));
  }
}
