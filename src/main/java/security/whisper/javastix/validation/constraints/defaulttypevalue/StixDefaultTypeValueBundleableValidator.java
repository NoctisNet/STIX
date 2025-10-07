package security.whisper.javastix.validation.constraints.defaulttypevalue;

import security.whisper.javastix.bundle.BundleableObject;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.lang.reflect.Field;
import java.util.UUID;

/**
 * This is used on any class that implements <strong>BundleableObject</strong>.
 */
public class StixDefaultTypeValueBundleableValidator implements ConstraintValidator<DefaultTypeValue, BundleableObject> {

    private String defaultTypeValue;

    @Override
    public void initialize(DefaultTypeValue relationshipTypeLimitConstraint) {
        defaultTypeValue = relationshipTypeLimitConstraint.value();
    }

    @Override
    public boolean isValid(BundleableObject bundleableObject,
                           ConstraintValidatorContext cxt) {

        String type = bundleableObject.getType();
        if (type == null || type.isEmpty()){
            try {
                Field typeField = bundleableObject.getClass().getDeclaredField("type");
                typeField.setAccessible(true);
                typeField.set(bundleableObject, defaultTypeValue);
            } catch (NoSuchFieldException e) {
                cxt.disableDefaultConstraintViolation();
                String violationMessage = "Cant find Field: 'type' for: " + bundleableObject.getClass();
                cxt.buildConstraintViolationWithTemplate(violationMessage).addConstraintViolation();
                e.printStackTrace();
                return false;

            } catch (IllegalAccessException e) {
                cxt.disableDefaultConstraintViolation();
                String violationMessage = "Illegal Access Exception for: 'type' for: " + bundleableObject.getClass();
                cxt.buildConstraintViolationWithTemplate(violationMessage).addConstraintViolation();
                e.printStackTrace();
                return false;
            }
        } else {
            if (bundleableObject.getType().equals(defaultTypeValue)){
                return true;
            } else{
                cxt.disableDefaultConstraintViolation();
                String violationMessage = "Field 'type' must have value of " + defaultTypeValue + "for class " + bundleableObject.getClass().getCanonicalName();
                cxt.buildConstraintViolationWithTemplate(violationMessage).addConstraintViolation();
                return false;
            }
        }

        // Validate the ID attribute
        String id = bundleableObject.getId();
        if (id == null || id.isEmpty()){
            try {
                Field idField = bundleableObject.getClass().getDeclaredField("id");
                idField.setAccessible(true);
                String idValue = String.join("--", defaultTypeValue, UUID.randomUUID().toString());
                idField.set(bundleableObject, idValue);

            } catch (IllegalAccessException e) {
                cxt.disableDefaultConstraintViolation();
                String violationMessage = "Illegal Access Exception for: 'id' for: " + bundleableObject.getClass();
                cxt.buildConstraintViolationWithTemplate(violationMessage).addConstraintViolation();
                e.printStackTrace();
                return false;

            } catch (NoSuchFieldException e) {
                cxt.disableDefaultConstraintViolation();
                String violationMessage = "Cant find Field: 'id' for: " + bundleableObject.getClass();
                cxt.buildConstraintViolationWithTemplate(violationMessage).addConstraintViolation();
                e.printStackTrace();
                return false;
            }
        } else {
            boolean idStartsWithType = id.startsWith(defaultTypeValue + "--");
            if (!idStartsWithType){
                cxt.disableDefaultConstraintViolation();
                String violationMessage = "Id does not start with the proper type value(Looking for '" + defaultTypeValue + "--' : provided 'id' value was: " + id;
                cxt.buildConstraintViolationWithTemplate(violationMessage).addConstraintViolation();
                return false;
            }
            //@TODO add optional logic to enforce a style of UUID
        }

        return true;
    }
}

