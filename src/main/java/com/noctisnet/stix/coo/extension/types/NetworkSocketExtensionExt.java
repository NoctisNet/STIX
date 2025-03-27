package com.noctisnet.stix.coo.extension.types;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.noctisnet.stix.coo.extension.CyberObservableExtension;
import com.noctisnet.stix.coo.objects.NetworkTrafficCoo;
import com.noctisnet.stix.validation.constraints.coo.allowedparents.AllowedParents;
import com.noctisnet.stix.validation.constraints.defaulttypevalue.DefaultTypeValue;
import com.noctisnet.stix.validation.constraints.vocab.Vocab;
import com.noctisnet.stix.validation.groups.DefaultValuesProcessor;
import com.noctisnet.stix.vocabulary.vocabularies.NetworkSocketAddressFamilies;
import com.noctisnet.stix.vocabulary.vocabularies.NetworkSocketProtocolFamilies;
import com.noctisnet.stix.vocabulary.vocabularies.NetworkSocketTypes;
import org.immutables.serial.Serial;
import org.immutables.value.Value;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.PositiveOrZero;
import java.util.Map;
import java.util.Optional;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

/**
 * socket-ext
 * <p>
 * The Network Socket extension specifies a default extension for capturing
 * network traffic properties associated with network sockets.
 *
 */
@Value.Immutable @Serial.Version(1L)
@DefaultTypeValue(value = "socket-ext", groups = {DefaultValuesProcessor.class})
@Value.Style(typeAbstract="*Ext", typeImmutable="*", validationMethod = Value.Style.ValidationMethod.NONE, additionalJsonAnnotations = {JsonTypeName.class}, passAnnotations = {AllowedParents.class}, depluralize = true)
@JsonSerialize(as = NetworkSocketExtension.class) @JsonDeserialize(builder = NetworkSocketExtension.Builder.class)
@JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
@JsonPropertyOrder({"address_family", "is_blocking", "is_listening", "protocol_family", "options", "socket_type",
        "socket_descriptor", "socket_handle" })
@JsonTypeName("socket-ext")
@AllowedParents({NetworkTrafficCoo.class})
public interface NetworkSocketExtensionExt extends CyberObservableExtension {

    @JsonProperty("address_family")
    @JsonPropertyDescription("Specifies the address family (AF_*) that the socket is configured for.")
    @NotNull
    @Vocab(NetworkSocketAddressFamilies.class)
    String getAddressFamily();

    @JsonProperty("is_blocking")
    @JsonPropertyDescription("Specifies whether the socket is in blocking mode.")
    @NotNull
    Optional<Boolean> getBlocking();

    @JsonProperty("is_listening")
    @JsonPropertyDescription("Specifies whether the socket is in listening mode.")
    @NotNull
    Optional<Boolean> getListening();

    @JsonProperty("protocol_family")
    @JsonPropertyDescription("Specifies the protocol family (PF_*) that the socket is configured for.")
    Optional<@Vocab(NetworkSocketProtocolFamilies.class) String> getProtocolFamily();

    //@TODO Should this enforce SO_* ?
    @JsonProperty("options")
    @JsonPropertyDescription("Specifies any options (SO_*) that may be used by the socket, as a dictionary.")
    Map<String,String> getOptions();

    @JsonProperty("socket_type")
    @JsonPropertyDescription("Specifies the type of the socket.")
    Optional<@Vocab(NetworkSocketTypes.class) String> getSocketType();

    @JsonProperty("socket_descriptor")
    @JsonPropertyDescription("Specifies the socket file descriptor value associated with the socket, as a non-negative integer.")
    Optional<@PositiveOrZero Long> getSocketDescriptor();

    @JsonProperty("socket_handle")
    @JsonPropertyDescription("Specifies the handle or inode value associated with the socket.")
    Optional<Long> getSocketHandle();

}
