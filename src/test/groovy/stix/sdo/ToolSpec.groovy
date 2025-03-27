package stix.sdo

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.noctisnet.stix.json.StixParsers
import com.noctisnet.stix.sdo.objects.Tool
import org.skyscreamer.jsonassert.JSONAssert
import org.skyscreamer.jsonassert.JSONCompareMode
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll
import faker.StixMockDataGenerator

class ToolSpec extends Specification {

    @Shared ObjectMapper mapper = new ObjectMapper()
    @Shared StixMockDataGenerator stixMockDataGenerator = new StixMockDataGenerator()

    @Unroll
    def "Generate Tool Data: Run: '#i'"() {
        when: "Generating Tool Data"
        Tool originalTool = stixMockDataGenerator.mockTool()
//            println "Original Object: ${originalTool.toString()}"

        then: "Convert Tool to Json"
            JsonNode originalJson = mapper.readTree(originalTool.toJsonString())
            String originalJsonString = mapper.writeValueAsString(originalJson)
//            println "Original Json: ${originalJsonString}"

        then: "Parse Json back into Tool Object"
            Tool parsedTool = (Tool)StixParsers.parseObject(originalJsonString)
            Tool parsedToolGeneric = StixParsers.parse(originalJsonString, Tool.class)
//            println "Parsed Object: ${parsedTool}"

        //@TODO needs to be setup to handle dehydrated object comparison
//        then: "Parsed object should match Original object"
//            assert originalAttackPattern == parsedAttackPattern

        then: "Convert Parsed Tool back to into Json"
            JsonNode newJson =  mapper.readTree(parsedTool.toJsonString())
            String newJsonString = mapper.writeValueAsString(newJson)
//            println "New Json: ${newJsonString}"

        then: "New Json should match Original Json"
            JSONAssert.assertEquals(originalJsonString, newJsonString, JSONCompareMode.NON_EXTENSIBLE)

        where:
            i << (1..100) // More tests are run because of the large variation of probabilities and number of combinations
    }
}
