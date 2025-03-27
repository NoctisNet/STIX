package com.noctisnet.stix.sdo;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.noctisnet.stix.common.StixCommonProperties;
import com.noctisnet.stix.common.StixCustomProperties;
import com.noctisnet.stix.common.StixLabels;
import com.noctisnet.stix.common.StixModified;
import com.noctisnet.stix.common.StixRevoked;
import com.noctisnet.stix.common.*;
import com.noctisnet.stix.sro.objects.RelationshipSro;

import javax.validation.constraints.NotNull;
import java.io.Serializable;
import java.util.Set;

/**
 * Base interface used by Immutable STIX Domain Objects
 */
public interface DomainObject extends Serializable,
                                      StixCommonProperties,
                                      StixCustomProperties,
                                      StixLabels,
                                      StixModified,
                                      StixRevoked {

    /**
     * This is used with the SROs.  The SRO interface enforces what relationships can be created.  The Relationships can then be stored in the Domain object if they choose.
     * Otherwise you would typically add these Relationship SROs that are specific to SDOs, can be grabbed during bundle creation.
     *
     * @return Set of Relationship SROs
     */
    @NotNull
    @JsonIgnore
    default Set<RelationshipSro> getRelationships() {
        return null;
    }

}
