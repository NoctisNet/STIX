package security.whisper.javastix.validation.constraints.vocab;

import com.google.common.collect.Sets;
import security.whisper.javastix.vocabulary.StixVocabulary;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.util.HashSet;
import java.util.Set;

public class StixVocabValidatorCollection implements ConstraintValidator<Vocab, Set<String>> {

    private Class<? extends StixVocabulary> vocabulary;

    @Override
    public void initialize(Vocab vocabConstraint) {
        vocabulary = vocabConstraint.value();
    }

    @Override
    public boolean isValid(Set<String> vocab,
                           ConstraintValidatorContext cxt) {
        // Null or empty collections are considered valid
        if (vocab == null || vocab.isEmpty()) {
            return true;
        }

        try {
            Set<String> vocabTerms = vocabulary.newInstance().getAllTerms();
            boolean evalContains = vocabTerms.containsAll(vocab);
            if (!evalContains){
                cxt.disableDefaultConstraintViolation();
                Sets.SetView<String> difference = Sets.difference(new HashSet<>(vocab), vocabTerms);

                String violationMessage = "Items: " + difference.toString() + " are not found in class " + vocabulary.getCanonicalName();
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
    }
}
