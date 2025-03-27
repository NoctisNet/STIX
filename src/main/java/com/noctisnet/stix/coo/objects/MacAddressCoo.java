package com.noctisnet.stix.coo.objects;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.noctisnet.stix.coo.CyberObservableObject;
import com.noctisnet.stix.validation.constraints.defaulttypevalue.DefaultTypeValue;
import com.noctisnet.stix.validation.groups.DefaultValuesProcessor;
import org.immutables.serial.Serial;
import org.immutables.value.Value;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

/**
 * mac-addr
 * <p>
 * The MAC Address Object represents a single Media Access Control (MAC) address.
 *
 */
@Value.Immutable @Serial.Version(1L)
@DefaultTypeValue(value = "mac-addr", groups = {DefaultValuesProcessor.class})
@Value.Style(typeAbstract="*Coo", typeImmutable="*", validationMethod = Value.Style.ValidationMethod.NONE, additionalJsonAnnotations = {JsonTypeName.class}, depluralize = true)
@JsonTypeName("mac-addr")
@JsonSerialize(as = MacAddress.class) @JsonDeserialize(builder = MacAddress.Builder.class)
@JsonPropertyOrder({"type", "extensions", "value"})
@JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
public interface MacAddressCoo extends CyberObservableObject {

    /**
     * The MAC address value MUST be represented as a single colon-delimited, lowercase MAC-48 address,
     * which MUST include leading zeros for each octet.
     * (Required)
     *
     */
    @JsonProperty("value")
    @JsonPropertyDescription("Specifies one or more mac addresses expressed using CIDR notation.")
    @Pattern(regexp="^([0-9a-f]{2}[:]){5}([0-9a-f]{2})$")
    @NotNull
    String getValue();

}
