package security.whisper.javastix.validation.constraints.relationship;

import security.whisper.javastix.bundle.BundleableObject;
import security.whisper.javastix.sro.objects.RelationshipSro;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.util.Arrays;
import java.util.stream.Collectors;

public class StixRelationshipLimitValidator implements ConstraintValidator<RelationshipLimit, RelationshipSro> {

    private Class<? extends BundleableObject> source;
    private String relationshipType;
    private Class<? extends BundleableObject>[] target;
    private boolean classEquality;

    @Override
    public void initialize(RelationshipLimit relationshipLimit) {
        source = relationshipLimit.source();
        target = relationshipLimit.target();
        relationshipType = relationshipLimit.relationshipType();
        classEquality = relationshipLimit.classEquality();
    }

    @Override
    public boolean isValid(RelationshipSro object,
                           ConstraintValidatorContext cxt) {

        if (object.getRelationshipType().equals(relationshipType)){
            if (classEquality){
                if (!object.getSourceRef().getClass().equals(object.getTargetRef().getClass())){
                    cxt.disableDefaultConstraintViolation();
                    String violationMessage = "Class Equality mismatch: Source: " +
                            source.getCanonicalName() + " does not match Target: " + object.getTargetRef().getClass().getCanonicalName();
                    cxt.buildConstraintViolationWithTemplate(violationMessage).addConstraintViolation();
                    return false;
                }
            }
            //@TODO write detail docs about the logic and how to eval this for debugging
            // The use of isAssignableFrom is typically confusing from basic logic between the interfaces and the Immutable class
            if (source.isAssignableFrom(object.getSourceRef().getClass())){
                boolean hasInstance = Arrays.stream(target).anyMatch(t-> t.isAssignableFrom(object.getTargetRef().getClass()));
                if (classEquality && object.getTargetRef().getClass().equals(object.getSourceRef().getClass())){
                    return true;

                } else if (hasInstance){
                    return true;

                }else {
                    cxt.disableDefaultConstraintViolation();
                    String targetClasses = Arrays.stream(target).map(Class::getCanonicalName).collect(Collectors.toList()).toString();
                    String violationMessage = "Source/Target/RelationshipType Mismatch: Source: " +
                            source.getCanonicalName() + " with Relationship-Type '" + relationshipType +
                            "' is only supported for Target(s): " + targetClasses;
                    cxt.buildConstraintViolationWithTemplate(violationMessage).addConstraintViolation();
                    return false;
                }

            } else {
                return true;
            }

        } else {
            return true;
        }
    }
}
