package com.noctisnet.stix.coo;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyDescription;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.noctisnet.stix.coo.extension.CyberObservableExtension;
import com.noctisnet.stix.coo.json.extension.CyberObservableExtensionsFieldDeserializer;
import com.noctisnet.stix.coo.json.extension.CyberObservableExtensionsFieldSerializer;
import com.noctisnet.stix.sdo.objects.ObservedDataSdo;
import com.noctisnet.stix.validation.GenericValidation;
import org.immutables.value.Value;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.util.Set;
import java.util.UUID;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

public interface CyberObservableObjectCommonProperties extends GenericValidation {

    @NotBlank
    @JsonProperty("type")
    @JsonPropertyDescription("Indicates that this object is an Observable Object. The value of this property MUST be a valid Observable Object type name, but to allow for custom objects this has been removed from the schema.")
    @Pattern(regexp = "^\\-?[a-z0-9]+(-[a-z0-9]+)*\\-?$")
    @Size(min = 3, max = 250)
    String getType();

    /**
     * Multiple extensions can be added, but only 1 instance of a specific extension can be added.
     */
    // @TODO Add validation to ensure that only 1 instance of each extension is applied as per the spec
    @JsonProperty("extensions")
    @JsonInclude(value = NON_EMPTY, content = NON_EMPTY)
    @JsonPropertyDescription("Specifies any extensions of the object, as a dictionary.")
    @JsonSerialize(using = CyberObservableExtensionsFieldSerializer.class)
    @JsonDeserialize(using = CyberObservableExtensionsFieldDeserializer.class)
    default Set<CyberObservableExtension> getExtensions() {
        return null;
    }

    /**
     * Used for generation of Map Keys by {@link ObservedDataSdo#getObjects()}
     * Manually set this value if you want to control key names.  Otherwise UUIDs will be used.
     */
    @JsonProperty(value = "observable_object_key", access = JsonProperty.Access.WRITE_ONLY)
    @Value.Default
    default String getObservableObjectKey(){
        return UUID.randomUUID().toString();
    }

}
