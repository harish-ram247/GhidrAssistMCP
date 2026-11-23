package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/** Read existing instructions independently of stored function boundaries. */
public final class GetDisassemblyRangeTool implements McpTool {
    private static final int MAX_BYTES = 65536;

    @Override public String getName() { return "get_disassembly_range"; }
    @Override public boolean isCacheable() { return true; }
    @Override public boolean isIdempotent() { return true; }
    @Override public String getDescription() {
        return "Read existing instructions whose start lies within a memory window. Works outside functions. " +
            "Undefined bytes and data are skipped. Reads the listing without changing it.";
    }
    @Override public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", Map.of(
            "address", Map.of("type", "string", "description", "Start address in program memory"),
            "length", Map.of("type", "integer", "minimum", 1, "maximum", MAX_BYTES,
                "description", "Number of bytes in the window")),
            List.of("address", "length"), false, null, null);
    }
    @Override public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program) {
        if (program == null) return error("No program currently loaded");
        if (!(arguments.get("address") instanceof String input) || input.isBlank()) return error("Missing address");
        Address start = program.getAddressFactory().getAddress(input.strip());
        if (start == null || !program.getMemory().contains(start)) return error("Invalid or unmapped address: " + input);
        if (!(arguments.get("length") instanceof Number number) || number.doubleValue() != number.intValue() ||
                number.intValue() < 1 || number.intValue() > MAX_BYTES) {
            return error("length must be an integer between 1 and " + MAX_BYTES);
        }
        try {
            Address end = start.addNoWrap(number.intValue() - 1L);
            var header = new StringBuilder("Instruction starts in ").append(start).append(" - ").append(end).append("\n\n");
            return GetCodeTool.readInstructions(program, new AddressSet(start, end), TaskMonitor.DUMMY, header);
        } catch (AddressOverflowException e) {
            return error("Requested range exceeds the address space");
        }
    }
    private static McpSchema.CallToolResult error(String message) {
        return McpSchema.CallToolResult.builder().addTextContent(message).isError(true).build();
    }
}
