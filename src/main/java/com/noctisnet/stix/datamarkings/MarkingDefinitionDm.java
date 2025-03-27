package com.noctisnet.stix.datamarkings;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.noctisnet.stix.common.StixCommonProperties;
import com.noctisnet.stix.common.StixCustomProperties;
import com.noctisnet.stix.datamarkings.objects.Statement;
import com.noctisnet.stix.datamarkings.objects.StatementMarkingObject;
import com.noctisnet.stix.datamarkings.objects.Tlp;
import com.noctisnet.stix.datamarkings.objects.TlpMarkingObject;
import com.noctisnet.stix.redaction.Redactable;
import com.noctisnet.stix.validation.constraints.defaulttypevalue.DefaultTypeValue;
import com.noctisnet.stix.validation.constraints.markingdefinitiontype.MarkingDefinitionTypeLimit;
import com.noctisnet.stix.validation.groups.DefaultValuesProcessor;
import org.immutables.serial.Serial;
import org.immutables.value.Value;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

/**
 * <p>Builder Required Fields:</p>
 * <ol>
 *     <li>{@link MarkingDefinition#getDefinitionType()} - (A helper is in-place for this field that will pre-populate the value based on the specific Marking Object, which makes this field essentially optional).</li>
 *     <li>{@link MarkingDefinition#getDefinition()}  - the Marking Object.  Two objects are currently supported: {@link Tlp} and {@link Statement}.</li>
 * </ol>
 */
@Value.Immutable @Serial.Version(1L)
@JsonTypeName("marking-definition")
@DefaultTypeValue(value = "marking-definition", groups = {DefaultValuesProcessor.class})
@Value.Style(typeAbstract="*Dm", typeImmutable="*", validationMethod = Value.Style.ValidationMethod.NONE, additionalJsonAnnotations = {JsonTypeName.class}, depluralize = true)
@JsonSerialize(as = MarkingDefinition.class) @JsonDeserialize(builder = MarkingDefinition.Builder.class)
@JsonPropertyOrder({"type", "id", "created_by_ref", "created",
        "external_references", "object_marking_refs", "granular_markings", "definition_type",
        "definition"})
@MarkingDefinitionTypeLimit(markingObject = TlpMarkingObject.class, markingDefinitionType = "tlp", groups = {DefaultValuesProcessor.class})
@MarkingDefinitionTypeLimit(markingObject = StatementMarkingObject.class, markingDefinitionType = "statement", groups = {DefaultValuesProcessor.class})
@Redactable
public interface MarkingDefinitionDm extends StixCommonProperties, StixCustomProperties {

    @NotBlank
    @JsonProperty("definition_type")
    String getDefinitionType();

    @NotNull
    @JsonProperty("definition")
    @JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "definition_type", include = JsonTypeInfo.As.EXTERNAL_PROPERTY)
    StixMarkingObject getDefinition();

}
