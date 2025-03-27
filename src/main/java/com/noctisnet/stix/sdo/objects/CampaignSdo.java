package com.noctisnet.stix.sdo.objects;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.noctisnet.stix.common.StixInstant;
import com.noctisnet.stix.redaction.Redactable;
import com.noctisnet.stix.sdo.DomainObject;
import com.noctisnet.stix.validation.constraints.defaulttypevalue.DefaultTypeValue;
import com.noctisnet.stix.validation.groups.DefaultValuesProcessor;
import org.immutables.serial.Serial;
import org.immutables.value.Value;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.util.Optional;
import java.util.Set;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

/**
 * campaign
 * <p>
 * A Campaign is a grouping of adversary behavior that describes a set of malicious activities or attacks that occur over a period of time against a specific set of targets.
 * 
 */
@Value.Immutable @Serial.Version(1L)
@JsonTypeName("campaign")
@DefaultTypeValue(value = "campaign", groups = {DefaultValuesProcessor.class})
@Value.Style(typeAbstract="*Sdo", typeImmutable="*", validationMethod = Value.Style.ValidationMethod.NONE, additionalJsonAnnotations = {JsonTypeName.class}, depluralize = true)
@JsonSerialize(as = Campaign.class) @JsonDeserialize(builder = Campaign.Builder.class)
@JsonPropertyOrder({"type", "id", "created_by_ref", "created",
        "modified", "revoked", "labels", "external_references",
        "object_marking_refs", "granular_markings", "name", "description",
        "aliases", "first_seen", "last_seen", "objective"})
@Redactable
public interface CampaignSdo extends DomainObject {

    @NotBlank
    @JsonProperty("name")
    @JsonPropertyDescription("The name used to identify the Campaign.")
    @Redactable(useMask = true)
    String getName();

    @JsonProperty("description")
    @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("A description that provides more details and context about the Campaign, potentially including its purpose and its key characteristics.")
    @Redactable
    Optional<String> getDescription();

    @NotNull
    @JsonProperty("aliases")
    @JsonInclude(value = NON_EMPTY, content = NON_EMPTY)
    @JsonPropertyDescription("Alternative names used to identify this campaign.")
    @Redactable
    default Set<String> getAliases() {
        return null;
    }

    @JsonProperty("first_seen")
    @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("The time that this Campaign was first seen.")
    @Redactable
    Optional<StixInstant> getFirstSeen();

    //@TODO add support to ensure that Last Seen is AFTER the First Seen value
    @JsonProperty("last_seen") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("The time that this Campaign was last seen.")
    @Redactable
    Optional<StixInstant> getLastSeen();

    @JsonProperty("objective") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("This field defines the Campaign’s primary goal, objective, desired outcome, or intended effect.")
    @Redactable
    Optional<String> getObjective();

}
