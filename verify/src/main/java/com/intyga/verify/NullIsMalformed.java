package com.intyga.verify;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import java.io.IOException;
import java.util.List;

/**
 * Present-but-null is malformed, not absent (DIV §4.3.2: "Malformed optional fields MUST be refused,
 * not dropped"). Jackson binds an explicit {@code null} and an absent key to the same Java
 * {@code null}, so a receipt the TypeScript and Python verifiers refuse would verify here. These
 * deserializers map a PRESENT null to a value that is not a DID — the empty string — and leave an
 * absent key as {@code null}; the identity-extension check and the builders then refuse it with the
 * reference's exact reasons. No record component changes type.
 */
final class NullIsMalformed {
  private NullIsMalformed() {}

  /** For {@code requester.credentialIssuerDid}. */
  static final class Did extends JsonDeserializer<String> {
    @Override
    public String deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
      return ctxt.readValue(p, String.class);
    }

    @Override
    public String getNullValue(DeserializationContext ctxt) {
      return "";
    }

    @Override
    public Object getAbsentValue(DeserializationContext ctxt) {
      return null;
    }
  }

  /**
   * For {@code requirement.requireEnrolledDevice} (DIV §4.3.2): absent stays {@code null}, the
   * literal {@code true} binds as {@code TRUE}, and ANY other present value — {@code false},
   * {@code null}, a string, a number — binds as {@code FALSE}, which the verifiers refuse as
   * malformed ("must be omitted or true"). Strict on purpose: Jackson's default boolean coercion
   * would read {@code "true"} or {@code 1} as true, which no other port accepts.
   */
  static final class EnrolledDevice extends JsonDeserializer<Boolean> {
    @Override
    public Boolean deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
      if (p.currentToken() == com.fasterxml.jackson.core.JsonToken.VALUE_TRUE) return Boolean.TRUE;
      p.skipChildren();
      return Boolean.FALSE;
    }

    @Override
    public Boolean getNullValue(DeserializationContext ctxt) {
      return Boolean.FALSE;
    }

    @Override
    public Object getAbsentValue(DeserializationContext ctxt) {
      return null;
    }
  }

  /** For {@code requirement.excludedSignerDids}. */
  static final class DidList extends JsonDeserializer<List<String>> {
    @Override
    public List<String> deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
      return ctxt.readValue(p, ctxt.getTypeFactory().constructCollectionType(List.class, String.class));
    }

    @Override
    public List<String> getNullValue(DeserializationContext ctxt) {
      return List.of("");
    }

    @Override
    public Object getAbsentValue(DeserializationContext ctxt) {
      return null;
    }
  }
}
