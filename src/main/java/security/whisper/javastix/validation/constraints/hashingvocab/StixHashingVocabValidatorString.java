package security.whisper.javastix.validation.constraints.hashingvocab;

import com.google.common.collect.Sets;
import security.whisper.javastix.vocabulary.StixVocabulary;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.lang.reflect.InvocationTargetException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class StixHashingVocabValidatorString implements ConstraintValidator<HashingVocab, String> {

    private Class<? extends StixVocabulary> vocabulary;

    @Override
    public void initialize(HashingVocab hashingVocabConstraint) {
        vocabulary = hashingVocabConstraint.value();
    }

    @Override
    public boolean isValid(String vocab,
                           ConstraintValidatorContext cxt) {
        if (vocab.startsWith("x_")) {
            return true;
        } else {
            try {
                Set<String> vocabTerms = vocabulary.getDeclaredConstructor().newInstance().getAllTerms();
                boolean evalContains = vocabTerms.contains(vocab);
                if (!evalContains) {
                    Sets.SetView<String> difference = Sets.difference(new HashSet<>(Collections.singletonList(vocab)), vocabTerms);

                    cxt.disableDefaultConstraintViolation();
                    String violationMessage = "Item: " + difference + " is not found in class " + vocabulary.getCanonicalName();
                    cxt.buildConstraintViolationWithTemplate(violationMessage).addConstraintViolation();
                    return false;
                } else {
                    return true;
                }

            } catch (InstantiationException e) {
                cxt.disableDefaultConstraintViolation();
                String violationMessage = "InstantiationException from " + vocabulary.getSimpleName();
                cxt.buildConstraintViolationWithTemplate(violationMessage).addConstraintViolation();
                return false;

            } catch (IllegalAccessException e) {
                cxt.disableDefaultConstraintViolation();
                String violationMessage = "IllegalAccessException from " + vocabulary.getSimpleName();
                cxt.buildConstraintViolationWithTemplate(violationMessage).addConstraintViolation();
                return false;
            }catch (NoSuchMethodException | InvocationTargetException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
