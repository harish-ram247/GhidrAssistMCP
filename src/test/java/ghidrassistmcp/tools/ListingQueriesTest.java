package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ghidra.GhidraApplicationLayout;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.DataStub;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import io.modelcontextprotocol.json.McpJsonDefaults;
import io.modelcontextprotocol.spec.McpSchema;

class ListingQueriesTest {
    private ProgramBuilder builder;
    private Program program;

    @BeforeAll static void initializeGhidra() throws Exception {
        if (!Application.isInitialized()) {
            var layout = new GhidraApplicationLayout(new File(System.getProperty("mcp.testGhidraInstallDir")));
            var config = new ApplicationConfiguration();
            config.setInitializeLogging(false);
            Application.initializeApplication(layout, config);
        }
    }

    @BeforeEach void createProgram() throws Exception {
        builder = new ProgramBuilder("listing-test", ProgramBuilder._X86);
        program = builder.getProgram();
        builder.createMemory("test", "1000", 64);
        builder.createLabel("1000", "y", "x");
        builder.applyDataType("1000", DWordDataType.dataType);
    }

    @AfterEach void releaseProgram() {
        if (builder != null) builder.dispose();
    }

    @Test void listsOnlyActualClassesIncludingEmptyNestedClasses() throws Exception {
        var tool = new ClassTool();
        assertTrue(text(tool.execute(Map.of("action", "list"), program)).contains("No classes found"));
        builder.createClassNamespace("Widget", "x", SourceType.USER_DEFINED);
        builder.createClassNamespace("Other", "x", SourceType.USER_DEFINED);
        var page = tool.execute(Map.of("action", "list", "pattern", "X::", "case_sensitive", false,
            "offset", 1, "limit", 1), program);
        assertTrue(text(page).contains("- x::Widget\n"));
        assertTrue(text(page).contains("Showing 1 of 2"));
    }

    @Test void listingAndAddressLookupPreserveQualifiedLabelsAndInteriorAddresses() {
        assertTrue(text(new ListDataTool().execute(Map.of(), program)).contains("(x::y)"));
        builder.createLabel("1002", "inside", "x");
        Map<?, ?> data = lookup("1002");
        assertEquals("data", data.get("kind"));
        assertEquals("x::inside", data.get("label"));
        assertEquals("x::y", data.get("data_label"));
        assertEquals("00001000", data.get("data_address"));
        assertEquals("dword", data.get("data_type"));
        assertEquals(4, data.get("length"));
        assertEquals("x::y", lookup("0x1000").get("label"));
    }

    @Test void addressLookupHandlesUndefinedBytesAndInstructions() throws Exception {
        builder.createLabel("1010", "pending", "x");
        assertEquals("x::pending", lookup("1010").get("label"));
        assertEquals("undefined", lookup("1010").get("kind"));
        assertNull(lookup("1011").get("label"));
        builder.setBytes("1020", "90 c3", true);
        assertEquals("instruction", lookup("1020").get("kind"));
        var tool = new GetDataVariableTool();
        assertTrue(tool.execute(Map.of("address", "not-an-address"), program).isError());
        assertTrue(tool.execute(Map.of("address", "12345678"), program).isError());
    }

    @Test void readsOnlyInstructionStartsInTheWindowWithoutDefiningCodeOrFunctions() throws Exception {
        builder.setBytes("1020", "6a 03 90 c3", true);
        var tool = new GetDisassemblyRangeTool();
        long revision = program.getModificationNumber();
        String result = text(tool.execute(Map.of("address", "1021", "length", 2), program));
        assertTrue(result.contains("00001022: NOP"), result);
        assertTrue(result.contains("Total instructions: 1"), result);
        assertFalse(result.contains("PUSH"));
        assertFalse(result.contains("RET"));
        assertEquals(revision, program.getModificationNumber());
        assertTrue(text(tool.execute(Map.of("address", "1000", "length", 4), program)).contains("Total instructions: 0"));
        assertTrue(tool.execute(Map.of("address", "12345678", "length", 4), program).isError());
        assertTrue(tool.execute(Map.of("address", "1000", "length", 65537), program).isError());
    }

    @Test void malformedStringCannotHideTheFollowingValidString() {
        var malformed = new DataStub() {
            @Override public boolean hasStringValue() { return true; }
            @Override public String getDefaultValueRepresentation() {
                throw new IllegalArgumentException("Start address must be less than or equal to end address");
            }
        };
        var readable = new DataStub() {
            @Override public boolean hasStringValue() { return true; }
            @Override public String getDefaultValueRepresentation() { return "L\"found\""; }
        };
        StringListing strings = new StringListing();
        assertNull(strings.representation(malformed));
        assertEquals("found", StringListing.text(strings.representation(readable)));
        StringBuilder result = new StringBuilder();
        strings.appendSkipped(result);
        assertTrue(result.toString().contains("Skipped 1"));
    }

    @Test void inlineAnalyzersRunInAProgramTransaction() throws Exception {
        var inTransaction = new AtomicBoolean();
        var analyzer = new AbstractAnalyzer("Transaction check", "Check the inline analyzer context", AnalyzerType.BYTE_ANALYZER) {
            @Override public boolean added(Program target, AddressSetView set, TaskMonitor monitor, MessageLog log) {
                inTransaction.set(target.getCurrentTransactionInfo() != null);
                return true;
            }
        };
        AnalysisUtils.getManager(program).scheduleOneTimeAnalysis(analyzer, program.getMemory());
        AnalysisUtils.runAnalysis(program, "changes", null, Map.of(), TaskMonitor.DUMMY);
        assertTrue(inTransaction.get(), "Inline analyzers must be able to write to the program");
    }

    @Test void onlySuccessfulWholeProgramAnalysisSetsTheAnalyzedFlag() throws Exception {
        // ProgramBuilder marks its synthetic program as analyzed by default.
        program.withTransaction("Prepare fresh analysis state", () ->
            program.getOptions(Program.PROGRAM_INFO).setBoolean(Program.ANALYZED_OPTION_NAME, false));
        var cancelled = new TaskMonitorAdapter(true);
        cancelled.cancel();
        assertThrows(CancelledException.class, () ->
            AnalysisUtils.runAnalysis(program, "full", null, Map.of(), cancelled));
        assertFalse(AnalysisUtils.isAnalyzed(program));

        var monitor = TaskMonitor.DUMMY;
        AnalysisUtils.runAnalysis(program, "changes", null, Map.of(), monitor);
        assertFalse(AnalysisUtils.isAnalyzed(program));
        AnalysisUtils.runAnalysis(program, "full", AnalysisUtils.parseRange(program, "1000", "1003"),
            Map.of(), monitor);
        assertFalse(AnalysisUtils.isAnalyzed(program));
        AnalysisUtils.runAnalysis(program, "full", null, Map.of(), monitor);
        assertTrue(AnalysisUtils.isAnalyzed(program));
    }

    @Test void validatesBaseBeforeChangingOrSavingProgram() throws Exception {
        ImportFileTool.applyBaseAddress(program, "0x4000");
        assertEquals(0x4000, program.getImageBase().getOffset());
        assertThrows(Exception.class, () -> ImportFileTool.applyBaseAddress(program, "broken"));
        assertEquals(0x4000, program.getImageBase().getOffset());
    }

    private Map<?, ?> lookup(String address) {
        var tool = new GetDataVariableTool();
        var result = tool.execute(Map.of("address", address), program);
        assertFalse(Boolean.TRUE.equals(result.isError()), text(result));
        var validation = McpJsonDefaults.getSchemaValidator().validate(tool.getOutputSchema(), result.structuredContent());
        assertTrue(validation.valid(), validation.errorMessage());
        return (Map<?, ?>) result.structuredContent();
    }

    private static String text(McpSchema.CallToolResult result) {
        return ((McpSchema.TextContent) result.content().getFirst()).text();
    }
}
