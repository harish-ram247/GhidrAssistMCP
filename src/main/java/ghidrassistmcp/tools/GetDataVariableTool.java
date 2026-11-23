package ghidrassistmcp.tools;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/** Look up a label and the containing listing item without enumerating defined data. */
public final class GetDataVariableTool implements McpTool {
    private static final ObjectMapper JSON = new ObjectMapper();

    @Override public String getName() { return "get_data_variable"; }
    @Override public boolean isIdempotent() { return true; }
    @Override public boolean isCacheable() { return true; }
    @Override public String getDescription() {
        return "Look up the qualified primary label at a memory address and the type, start, length, " +
            "and qualified label of any defined data containing it. Also identifies instructions and undefined bytes.";
    }
    @Override public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", Map.of("address", Map.of("type", "string",
            "description", "Ghidra memory address, optionally qualified by address space")),
            List.of("address"), false, null, null);
    }
    @Override public Map<String, Object> getOutputSchema() {
        var string = Map.of("type", "string");
        var nullableString = Map.of("type", List.of("string", "null"));
        return Map.of("type", "object", "properties", Map.of(
            "address", string, "label", nullableString,
            "kind", Map.of("enum", List.of("data", "instruction", "undefined")),
            "data_address", string, "data_type", string, "data_label", nullableString,
            "length", Map.of("type", "integer")),
            "required", List.of("address", "label", "kind"), "additionalProperties", false);
    }

    @Override public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program) {
        if (program == null) return error("No program currently loaded");
        if (!(arguments.get("address") instanceof String input) || input.isBlank()) {
            return error("Missing required parameter: address");
        }
        Address address = program.getAddressFactory().getAddress(input.strip());
        if (address == null) return error("Invalid address: " + input);

        CodeUnit unit = program.getListing().getCodeUnitContaining(address);
        if (unit == null) return error("Address outside program memory: " + address);
        Symbol label = program.getSymbolTable().getPrimarySymbol(address);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("address", address.toString());
        result.put("label", label == null ? null : label.getName(true));
        if (unit instanceof Data data && data.isDefined()) {
            result.put("kind", "data");
            result.put("data_address", data.getMinAddress().toString());
            result.put("data_type", data.getDataType().getDisplayName());
            result.put("length", data.getLength());
            Symbol baseLabel = data.getPrimarySymbol();
            result.put("data_label", baseLabel == null ? null : baseLabel.getName(true));
        } else {
            result.put("kind", unit instanceof Instruction ? "instruction" : "undefined");
        }
        try {
            return McpSchema.CallToolResult.builder().structuredContent(result)
                .addTextContent(JSON.writeValueAsString(result)).build();
        } catch (JsonProcessingException e) {
            return error("Could not encode data variable: " + e.getMessage());
        }
    }

    private static McpSchema.CallToolResult error(String message) {
        return McpSchema.CallToolResult.builder().addTextContent(message).isError(true).build();
    }
}
