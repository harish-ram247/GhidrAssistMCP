package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

public class SearchStringsTool implements McpTool {

    @Override
    public boolean isCacheable() { return true; }

    @Override
    public String getName() { return "search_strings"; }

    @Override
    public String getDescription() { return "Search for strings matching a pattern in the program"; }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "pattern", Map.of("type", "string", "description", "Search pattern to match against string content"),
                "case_sensitive", Map.of("type", "boolean", "description", "Case sensitive search (default false)"),
                "limit", Map.of("type", "integer", "description", "Maximum results (default 100)")
            ),
            List.of("pattern"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder().addTextContent("No program currently loaded").build();
        }

        String pattern = (String) arguments.get("pattern");
        if (pattern == null || pattern.isEmpty()) {
            return McpSchema.CallToolResult.builder().addTextContent("pattern is required").build();
        }

        boolean caseSensitive = Boolean.TRUE.equals(arguments.get("case_sensitive"));
        int limit = 100;
        if (arguments.get("limit") instanceof Number) limit = ((Number) arguments.get("limit")).intValue();

        String searchPattern = caseSensitive ? pattern : pattern.toLowerCase(java.util.Locale.ROOT);

        StringBuilder result = new StringBuilder();
        result.append("Strings matching \"").append(pattern).append("\":\n\n");

        StringListing strings = new StringListing();
        DataIterator dataIter = currentProgram.getListing().getDefinedData(true);
        int count = 0;

        while (count < limit && dataIter.hasNext()) {
            Data data = dataIter.next();
            String stringValue = strings.representation(data);
            if (stringValue != null) {
                String text = StringListing.text(stringValue);
                String compareText = caseSensitive ? text : text.toLowerCase(java.util.Locale.ROOT);
                if (compareText.contains(searchPattern)) {
                    String display = stringValue.length() > 80 ? stringValue.substring(0, 77) + "..." : stringValue;
                    result.append("@ ").append(data.getAddress()).append(": ").append(display).append("\n");
                    count++;
                }
            }
        }

        if (count == 0) {
            result.append("No strings found matching: ").append(pattern);
        } else {
            result.append("\nFound ").append(count).append(" matching strings");
        }

        strings.appendSkipped(result);
        return McpSchema.CallToolResult.builder().addTextContent(result.toString()).build();
    }
}
