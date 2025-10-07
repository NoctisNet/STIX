package security.whisper.javastix.validation.constraints.defaulttypevalue;

import security.whisper.javastix.coo.extension.CyberObservableExtension;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.lang.reflect.Field;

/**
 * This is used on any class that implements <strong>CyberObservableObject</strong>.
 */
public class StixDefaultTypeValueCyberObservableExtensionValidator implements ConstraintValidator<DefaultTypeValue, CyberObservableExtension> {

    private String defaultTypeValue;

    @Override
    public void initialize(DefaultTypeValue relationshipTypeLimitConstraint) {
        defaultTypeValue = relationshipTypeLimitConstraint.value();
    }

    @Override
    public boolean isValid(CyberObservableExtension cyberObservableExtension,
                           ConstraintValidatorContext cxt) {

        String type = cyberObservableExtension.getType();
        if (type == null || type.isEmpty()){
            try {
                Field typeField = cyberObservableExtension.getClass().getDeclaredField("type");
                typeField.setAccessible(true);
                typeField.set(cyberObservableExtension, defaultTypeValue);
            } catch (NoSuchFieldException e) {
                cxt.disableDefaultConstraintViolation();
                String violationMessage = "Cant find Field: 'type' for: " + cyberObservableExtension.getClass();
                cxt.buildConstraintViolationWithTemplate(violationMessage).addConstraintViolation();
                e.printStackTrace();
                return false;

            } catch (IllegalAccessException e) {
                cxt.disableDefaultConstraintViolation();
                String violationMessage = "Illegal Access Exception for: 'type' for: " + cyberObservableExtension.getClass();
                cxt.buildConstraintViolationWithTemplate(violationMessage).addConstraintViolation();
                e.printStackTrace();
                return false;
            }
        } else {
            if (cyberObservableExtension.getType().equals(defaultTypeValue)){
                return true;
            } else{
                cxt.disableDefaultConstraintViolation();
                String violationMessage = "Field 'type' must have value of " + defaultTypeValue + "for class " + cyberObservableExtension.getClass().getCanonicalName();
                cxt.buildConstraintViolationWithTemplate(violationMessage).addConstraintViolation();
                return false;
            }
        }

        return true;
    }
}

