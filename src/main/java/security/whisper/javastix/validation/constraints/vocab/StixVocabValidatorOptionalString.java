package security.whisper.javastix.validation.constraints.vocab;

import com.google.common.collect.Sets;
import security.whisper.javastix.vocabulary.StixVocabulary;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

public class StixVocabValidatorOptionalString implements ConstraintValidator<Vocab, Optional<String>> {

    private Class<? extends StixVocabulary> vocabulary;

    @Override
    public void initialize(Vocab vocabConstraint) {
        vocabulary = vocabConstraint.value();
    }

    @Override
    public boolean isValid(Optional<String> vocab, ConstraintValidatorContext cxt) {
        if (vocab.isPresent()) {
            try {
                Set<String> vocabTerms = vocabulary.newInstance().getAllTerms();
                boolean evalContains = vocabTerms.contains(vocab.get());
                if (!evalContains) {
                    Sets.SetView<String> difference = Sets.difference(new HashSet<>(Arrays.asList(vocab.get())), vocabTerms);
                    cxt.disableDefaultConstraintViolation();
                    String violationMessage = "Item: " + difference.toString() + " is not found in class " + vocabulary.getCanonicalName();
                    cxt.buildConstraintViolationWithTemplate(violationMessage).addConstraintViolation();
                }

                return evalContains;

            } catch (InstantiationException e) {
                cxt.disableDefaultConstraintViolation();
                String violationMessage = "InstantiationException from " + vocabulary.getSimpleName();
                cxt.buildConstraintViolationWithTemplate(violationMessage).addConstraintViolation();
                e.printStackTrace();
                return false;

            } catch (IllegalAccessException e) {
                cxt.disableDefaultConstraintViolation();
                String violationMessage = "IllegalAccessException from " + vocabulary.getSimpleName();
                cxt.buildConstraintViolationWithTemplate(violationMessage).addConstraintViolation();
                e.printStackTrace();
                return false;
            }
        } else {
            return true;
        }
    }
}
