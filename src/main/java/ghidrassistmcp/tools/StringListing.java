package ghidrassistmcp.tools;

import ghidra.program.model.listing.Data;

/** Read each defined string independently; a bad string length can make Ghidra reject its range. */
final class StringListing {
    private int skipped;

    String representation(Data data) {
        try {
            return data.hasStringValue() ? data.getDefaultValueRepresentation() : null;
        } catch (IllegalArgumentException e) {
            skipped++;
            return null;
        }
    }

    static String text(String representation) {
        int first = representation.indexOf('"');
        int last = representation.lastIndexOf('"');
        return first >= 0 && last > first ? representation.substring(first + 1, last) : representation;
    }

    void appendSkipped(StringBuilder result) {
        if (skipped > 0) {
            result.append("\nSkipped ").append(skipped).append(" unreadable string record(s). Results may be incomplete.");
        }
    }
}
