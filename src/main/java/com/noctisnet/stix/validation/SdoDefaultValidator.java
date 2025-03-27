package com.noctisnet.stix.validation;

import com.noctisnet.stix.validation.sequences.SequenceDefault;
import com.noctisnet.stix.validation.sequences.SequenceValidationIdOnly;

import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;
import javax.validation.Validation;
import javax.validation.Validator;
import java.util.Set;

public interface SdoDefaultValidator {

    Validator VALIDATOR = Validation.buildDefaultValidatorFactory().getValidator();

    default void validate() throws ConstraintViolationException{
        Set<ConstraintViolation<SdoDefaultValidator>> violations = VALIDATOR.validate(this, SequenceDefault.class);
        if (!violations.isEmpty()) {
            throw new ConstraintViolationException(violations);
        }
    }

    default void validateOnlyId() throws ConstraintViolationException{
        Set<ConstraintViolation<SdoDefaultValidator>> violations = VALIDATOR.validate(this, SequenceValidationIdOnly.class);
        if (!violations.isEmpty()) {
            throw new ConstraintViolationException(violations);
        }
    }
}




