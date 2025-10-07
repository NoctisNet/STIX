package security.whisper.javastix.json.converters.dehydrated;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.util.StdConverter;
import security.whisper.javastix.datamarkings.MarkingDefinitionDm;
import security.whisper.javastix.json.StixParsers;

import java.util.HashSet;
import java.util.Set;

/**
 * Generates a Dehydrated Marking Definition Set used for Deserialization
 */
public class MarkingDefinitionSetConverter extends StdConverter<Set<String>, Set<MarkingDefinitionDm>> {

    @Override
    public Set<MarkingDefinitionDm> convert(Set<String> values) {
        Set<MarkingDefinitionDm> markDefSet = new HashSet<>();
        values.forEach(v -> {
            String[] parsedValue = v.split("--");

            if (parsedValue.length == 2) {
                ObjectMapper mapper = StixParsers.getJsonMapper();
                ObjectNode node = mapper.createObjectNode();

                node.put("type", parsedValue[0]);
                node.put("id", v);
                node.put("hydrated", false);

                try {
                    MarkingDefinitionDm markingDef = mapper.treeToValue(node, MarkingDefinitionDm.class);
                    //@TODO add more logic
                    markDefSet.add(markingDef);

                } catch (JsonProcessingException e) {
                    e.printStackTrace();
                    throw new IllegalArgumentException("Cannot Parse Json: " + e.getMessage());
                }

            } else {
                throw new IllegalArgumentException("Id is not valid format, Cannot Parse Value: " + v);
            }
        });
        return markDefSet;
    }
}