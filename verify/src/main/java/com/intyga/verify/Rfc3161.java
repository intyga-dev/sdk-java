package com.intyga.verify;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.time.DateTimeException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Optional, offline RFC 3161 verification through a caller-selected OpenSSL 3 executable. */
public final class Rfc3161 {
  private static final int MAX = 1024 * 1024;
  private static final byte[] QUERY_PREFIX = HexFormat.of().parseHex("30360201013031300d060960864801650304020105000420");
  private static final Pattern CERT = Pattern.compile("-----BEGIN CERTIFICATE-----\\s*([A-Za-z0-9+/=\\r\\n]+?)\\s*-----END CERTIFICATE-----");
  private static final Pattern TIME = Pattern.compile("(\\d{14})(?:\\.(\\d*[1-9]))?Z");
  private static final byte[] SIGNED_DATA_OID = HexFormat.of().parseHex("2a864886f70d010702");
  private static final List<String> DIGEST_OIDS = List.of("608648016503040201", "608648016503040202", "608648016503040203");

  public record Trust(String caPem, String signerCertificateSha256, String revocation,
      String crlPem, String untrustedPem, Long verificationTime, String opensslPath) {
    public Trust(String caPem, String signerCertificateSha256, String revocation) {
      this(caPem, signerCertificateSha256, revocation, null, null, null, null);
    }
  }
  public record Verification(boolean ok, String reason, Long genTime) {
    static Verification fail() { return new Verification(false, "RFC 3161 evidence could not be verified", null); }
  }

  public static Verification verifyAnchor(Ledger.SignedAnchor anchor, Trust trust) {
    Path dir = null;
    try {
      if (anchor == null || trust == null || !"RFC3161".equals(anchor.kind())
          || !Ledger.isWellFormedAnchor(anchor.anchorInput())
          || !("ES256".equals(anchor.algorithm()) || "Ed25519".equals(anchor.algorithm()) || "RSA-PSS".equals(anchor.algorithm()))
          || anchor.issuer() == null || anchor.timestamp() == null) return Verification.fail();
      byte[] token = strictBase64(anchor.evidence()); wholeSequence(token);
      cmsDigestAlgorithm(token);
      byte[] digest = HexFormat.of().parseHex(Ledger.anchorDigestHex(anchor.anchorInput()));
      long now = trust.verificationTime() != null ? trust.verificationTime() : (System.currentTimeMillis() + 999) / 1000;
      String openssl = trust.opensslPath() == null ? "openssl" : trust.opensslPath();
      if (empty(trust.caPem()) || bytes(trust.caPem()) > MAX || empty(openssl) || openssl.indexOf('\0') >= 0
          || trust.signerCertificateSha256() == null || !trust.signerCertificateSha256().matches("[0-9a-f]{64}")
          || !("crl".equals(trust.revocation()) || "unchecked".equals(trust.revocation()))
          || "crl".equals(trust.revocation()) && empty(trust.crlPem()) || now < 0 || now > 253402300799L
          || trust.crlPem() != null && bytes(trust.crlPem()) > MAX
          || trust.untrustedPem() != null && bytes(trust.untrustedPem()) > MAX) return Verification.fail();
      // Commands run from the private directory below. Preserve caller-relative executable paths;
      // a bare command name intentionally remains subject to normal PATH lookup.
      if (openssl.indexOf('/') >= 0 || openssl.indexOf('\\') >= 0)
        openssl = Path.of(openssl).toAbsolutePath().normalize().toString();
      dir = Files.createTempDirectory("intyga-rfc3161-"); setPermissions(dir, "rwx------");
      Path empty = Files.createDirectory(dir.resolve("empty")); setPermissions(empty, "rwx------");
      write(dir.resolve("token.der"), token);
      byte[] query = new byte[QUERY_PREFIX.length + digest.length];
      System.arraycopy(QUERY_PREFIX, 0, query, 0, QUERY_PREFIX.length);
      System.arraycopy(digest, 0, query, QUERY_PREFIX.length, digest.length); write(dir.resolve("query.tsq"), query);
      write(dir.resolve("trust.pem"), (trust.caPem() + (trust.crlPem() == null ? "" : "\n" + trust.crlPem())).getBytes(StandardCharsets.UTF_8));
      write(dir.resolve("openssl.cnf"), new byte[0]);
      if (!empty(trust.untrustedPem())) write(dir.resolve("intermediates.pem"), trust.untrustedPem().getBytes(StandardCharsets.UTF_8));
      Map<String,String> env = Map.of("OPENSSL_CONF", dir.resolve("openssl.cnf").toString(),
          "SSL_CERT_FILE", dir.resolve("none.pem").toString(), "SSL_CERT_DIR", empty.toString());
      if (!run(dir, env, List.of(openssl,"cms","-verify","-binary","-inform","DER","-in","token.der",
          "-noverify","-signer","signer.pem","-out","info.der"))) return Verification.fail();
      byte[] signer = Files.readAllBytes(dir.resolve("signer.pem")), info = Files.readAllBytes(dir.resolve("info.der"));
      if (signer.length > MAX || info.length > MAX || !sha256(oneSigner(signer)).equals(trust.signerCertificateSha256())) return Verification.fail();
      ParsedTime issued = generalizedTime(info);
      if (issued.seconds < 0 || issued.seconds > now || issued.fractional && now <= issued.seconds) return Verification.fail();
      // `ts -verify` never loads OpenSSL's default trust locations; it trusts only what is passed. No
      // `-CAstore`: OpenSSL 3.0 loads a store URI eagerly and fails on an empty one (3.5 is lazy), which
      // made every valid token fail closed on Ubuntu 24.04's 3.0.13.
      List<String> base = new ArrayList<>(List.of(openssl,"ts","-verify","-token_in","-in","token.der","-queryfile","query.tsq",
          "-CAfile","trust.pem","-CApath","empty"));
      if (!empty(trust.untrustedPem())) base.addAll(List.of("-untrusted","intermediates.pem"));
      List<String> current = new ArrayList<>(base); current.addAll(List.of("-attime",Long.toString(now),"-auth_level","2","-x509_strict"));
      if ("crl".equals(trust.revocation())) current.add("-crl_check_all");
      List<String> historical = new ArrayList<>(base); historical.addAll(List.of("-attime",Long.toString(issued.seconds),"-auth_level","2","-x509_strict"));
      if (!run(dir, env, current) || !run(dir, env, historical)) return Verification.fail();
      return new Verification(true, null, issued.seconds);
    } catch (Exception e) { return Verification.fail(); }
    finally { if (dir != null) removeTree(dir); }
  }

  private static boolean run(Path dir, Map<String,String> variables, List<String> args) {
    Process process = null;
    try {
      ProcessBuilder builder = new ProcessBuilder(args).directory(dir.toFile())
          .redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD);
      builder.environment().putAll(variables); process = builder.start(); process.getOutputStream().close();
      if (!process.waitFor(5, TimeUnit.SECONDS)) { process.destroyForcibly(); process.waitFor(); return false; }
      return process.exitValue() == 0;
    } catch (Exception e) { if (process != null) { process.destroyForcibly(); try { process.waitFor(); } catch (InterruptedException x) { Thread.currentThread().interrupt(); } } return false; }
  }
  private static void write(Path path, byte[] data) throws IOException { Files.write(path, data); setPermissions(path, "rw-------"); }
  private static void setPermissions(Path path, String mode) { try { Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(mode)); } catch (UnsupportedOperationException | IOException ignored) {} }
  private static int bytes(String value) { return value.getBytes(StandardCharsets.UTF_8).length; }
  private static boolean empty(String value) { return value == null || value.isEmpty(); }
  private static String sha256(byte[] value) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value)); }

  private static byte[] strictBase64(String value) {
    if (value == null || value.length() > ((MAX + 2) / 3) * 4 || value.length() % 4 != 0 || !value.matches("[A-Za-z0-9+/]*={0,2}")) throw new IllegalArgumentException();
    byte[] decoded = Base64.getDecoder().decode(value);
    if (decoded.length > MAX || !Base64.getEncoder().encodeToString(decoded).equals(value)) throw new IllegalArgumentException();
    return decoded;
  }
  private static byte[] oneSigner(byte[] pem) {
    Matcher matcher = CERT.matcher(new String(pem, StandardCharsets.US_ASCII));
    if (!matcher.find()) throw new IllegalArgumentException(); String body = matcher.group(1).replaceAll("\\s", "");
    if (matcher.find()) throw new IllegalArgumentException(); byte[] der = strictBase64(body); wholeSequence(der); return der;
  }
  private record Tlv(int content, int end) {}
  private static Tlv tlv(byte[] data, int at, int expected) {
    if (at + 2 > data.length || (data[at] & 255) != expected) throw new IllegalArgumentException(); int first=data[at+1]&255, pos=at+2, len;
    if (first < 128) len=first; else { int count=first&127; if(count==0||count>4||pos+count>data.length||data[pos]==0) throw new IllegalArgumentException(); len=0; for(int i=0;i<count;i++) len=(len<<8)|(data[pos++]&255); if(len<128) throw new IllegalArgumentException(); }
    if (len > data.length-pos) throw new IllegalArgumentException(); return new Tlv(pos,pos+len);
  }
  private static int wholeSequence(byte[] data) { Tlv t=tlv(data,0,0x30); if(t.end!=data.length) throw new IllegalArgumentException(); return t.content; }
  private record Algorithm(String oid, int end) {}
  private static Algorithm algorithm(byte[] data, int pos) {
    Tlv sequence=tlv(data,pos,0x30), oid=tlv(data,sequence.content,0x06); int cursor=oid.end;
    if(cursor<sequence.end){ Tlv nil=tlv(data,cursor,0x05); if(nil.content!=nil.end) throw new IllegalArgumentException(); cursor=nil.end; }
    String value=HexFormat.of().formatHex(data,oid.content,oid.end);
    if(cursor!=sequence.end||!DIGEST_OIDS.contains(value)) throw new IllegalArgumentException();
    return new Algorithm(value,sequence.end);
  }
  /** OpenSSL auth_level does not reject SHA-1/MD5 used as the CMS SignerInfo digest. */
  private static void cmsDigestAlgorithm(byte[] data) {
    int pos=wholeSequence(data); Tlv contentType=tlv(data,pos,0x06);
    if(!MessageDigest.isEqual(SIGNED_DATA_OID,java.util.Arrays.copyOfRange(data,contentType.content,contentType.end))) throw new IllegalArgumentException();
    Tlv explicit=tlv(data,contentType.end,0xA0); if(explicit.end!=data.length) throw new IllegalArgumentException();
    Tlv signed=tlv(data,explicit.content,0x30); if(signed.end!=explicit.end) throw new IllegalArgumentException(); pos=signed.content;
    pos=tlv(data,pos,0x02).end; Tlv digests=tlv(data,pos,0x31); Algorithm digest=algorithm(data,digests.content);
    if(digest.end!=digests.end) throw new IllegalArgumentException(); pos=digests.end;
    pos=tlv(data,pos,0x30).end;
    while(pos<signed.end&&((data[pos]&255)==0xA0||(data[pos]&255)==0xA1)) pos=tlv(data,pos,data[pos]&255).end;
    Tlv signers=tlv(data,pos,0x31); if(signers.end!=signed.end) throw new IllegalArgumentException();
    Tlv signer=tlv(data,signers.content,0x30); if(signer.end!=signers.end) throw new IllegalArgumentException(); pos=signer.content;
    pos=tlv(data,pos,0x02).end; if(pos>=signer.end||((data[pos]&255)!=0x30&&(data[pos]&255)!=0x80)) throw new IllegalArgumentException();
    pos=tlv(data,pos,data[pos]&255).end; Algorithm signerDigest=algorithm(data,pos);
    if(!digest.oid.equals(signerDigest.oid)) throw new IllegalArgumentException();
  }
  // STRICT resolver with the proleptic year `uuuu`: the default SMART resolver rolled 20260230 back
  // to 28 February, where the other ports refuse it (2026-09-27 review L20).
  private static final DateTimeFormatter GEN_TIME =
      DateTimeFormatter.ofPattern("uuuuMMddHHmmss").withResolverStyle(java.time.format.ResolverStyle.STRICT);
  record ParsedTime(long seconds, boolean fractional) {}
  private static ParsedTime generalizedTime(byte[] info) {
    int pos=wholeSequence(info); Tlv version=tlv(info,pos,0x02); if(version.end-version.content!=1||info[version.content]!=1) throw new IllegalArgumentException();
    pos=version.end; pos=tlv(info,pos,0x06).end; pos=tlv(info,pos,0x30).end; pos=tlv(info,pos,0x02).end; Tlv time=tlv(info,pos,0x18);
    return parseGeneralizedTime(new String(info,time.content,time.end-time.content,StandardCharsets.US_ASCII));
  }
  /** A TSTInfo genTime (GeneralizedTime text) to Unix seconds; throws IllegalArgumentException. */
  static ParsedTime parseGeneralizedTime(String text) {
    Matcher match=TIME.matcher(text); if(!match.matches()) throw new IllegalArgumentException();
    try { LocalDateTime parsed=LocalDateTime.parse(match.group(1),GEN_TIME); return new ParsedTime(parsed.toEpochSecond(ZoneOffset.UTC),match.group(2)!=null); }
    catch(DateTimeException e){ throw new IllegalArgumentException(e); }
  }
  private static void removeTree(Path root) { try (var paths=Files.walk(root)) { paths.sorted((a,b)->b.compareTo(a)).forEach(p->{try{Files.deleteIfExists(p);}catch(IOException ignored){}}); } catch(IOException ignored){} }
  private Rfc3161() {}
}
