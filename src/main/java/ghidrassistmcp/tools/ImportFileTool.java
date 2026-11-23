/*
 * MCP tool for importing a binary file into the current Ghidra project.
 *
 * SECURITY NOTE: This tool grants the MCP client file-system read access to any path
 * the Ghidra process can reach.  It is therefore registered as DISABLED by default
 * and must be explicitly enabled by the user in the GhidrAssistMCP configuration UI.
 */
package ghidrassistmcp.tools;

import java.io.File;
import java.util.List;
import java.util.Map;

import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.framework.model.Project;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.GhidrAssistMCPManager;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.tasks.McpTaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that imports a binary file into the active Ghidra project.
 * Detects the executable format or explicitly loads raw bytes with a user-selected language.
 *
 * Disabled by default because it exposes host file-system read access.
 */
public class ImportFileTool implements McpTool {

    @Override
    public String getName() {
        return "import_file";
    }

    @Override
    public String getDescription() {
        return "Import a binary file into the current Ghidra project. " +
               "Supports raw binary imports with configurable language/processor, " +
               "and base address. " +
               "SECURITY: This tool can read files from the host file system - " +
               "it is disabled by default and must be explicitly enabled. " +
               "Example: {\"file_path\": \"C:/roms/bank00.bin\", \"language\": \"6502:LE:16:default\", " +
               "\"base_address\": \"0x8000\"}";
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean isIdempotent() {
        return false;
    }

    @Override
    public boolean isOpenWorld() {
        return true;
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.ofEntries(
                Map.entry("file_path", Map.of(
                    "type", "string",
                    "description", "Absolute path to the binary file on the host file system")),
                Map.entry("program_name", Map.of(
                    "type", "string",
                    "description", "Name for the imported program (defaults to file name)")),
                Map.entry("loader", Map.of("type", "string", "enum", List.of("auto", "raw"),
                    "default", "auto", "description", "Detect the file format even when a language is supplied. Choose raw to force a flat binary import with an explicit language.")),
                Map.entry("language", Map.of(
                    "type", "string",
                    "description", "Language ID: processor:endian:size:variant " +
                                   "(e.g. '6502:LE:16:default', 'x86:LE:32:default', 'ARM:LE:32:v8'). " +
                                   "If omitted, Ghidra will attempt auto-detection.")),
                Map.entry("compiler", Map.of(
                    "type", "string",
                    "description", "Compiler spec ID (e.g. 'default', 'gcc', 'windows'). Omit or use 'default' for the language's default compiler.")),
                Map.entry("base_address", Map.of(
                    "type", "string",
                    "description", "Hexadecimal image base (e.g. '0x8000' or 'c000:0000' on a segmented architecture).")),
                Map.entry("folder", Map.of(
                    "type", "string",
                    "description", "Destination folder in the Ghidra project (e.g. '/' or '/banks'). Default: '/'.")),
                Map.entry("open_after_import", Map.of(
                    "type", "boolean",
                    "description", "Open the imported program in CodeBrowser after import. Default: true.")),
                Map.entry("suppress_analysis_prompt", Map.of(
                    "type", "boolean",
                    "description", "If open_after_import is true, set 'Should Ask To Analyze' to false before opening. Default: true.",
                    "default", true))
            ),
            List.of("file_path"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return error("This tool requires backend context (project access).");
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram,
                                            GhidrAssistMCPBackend backend) {
        GhidrAssistMCPManager manager = GhidrAssistMCPManager.findInstance();
        Project project = manager == null ? null : manager.getProject();
        if (project == null || project.isClosed()) {
            return error("No Ghidra project is open.");
        }

        // Bind queued imports to the original project even if the GUI changes projects.
        if (backend != null && backend.isAsyncExecutionEnabled()) {
            return backend.submitToolTask(getName(), arguments, null, task ->
                importFile(arguments, manager, project, new McpTaskMonitor(task, 0, 100, "Importing")));
        }
        return importFile(arguments, manager, project, TaskMonitor.DUMMY);
    }

    private McpSchema.CallToolResult importFile(Map<String, Object> arguments, GhidrAssistMCPManager manager,
                                                Project project, TaskMonitor monitor) {
        if (project.isClosed() || manager.getProject() != project) {
            return error("The destination project changed before import: " + project.getName());
        }
        String filePath = (String) arguments.get("file_path");
        if (filePath == null || filePath.isBlank()) {
            return error("file_path is required.");
        }

        File file = new File(filePath);
        if (!file.exists()) {
            return error("File not found: " + filePath);
        }
        if (!file.isFile()) {
            return error("Path is not a file: " + filePath);
        }

        String languageStr = (String) arguments.get("language");
        String compilerStr = (String) arguments.get("compiler");
        boolean raw = "raw".equals(arguments.get("loader"));
        if (raw && (languageStr == null || languageStr.isBlank())) {
            return error("A raw import requires an explicit language.");
        }

        String baseAddrStr = (String) arguments.get("base_address");
        String programName = (String) arguments.get("program_name");
        if (programName != null) {
            programName = programName.trim();
            if (programName.isEmpty()) {
                programName = null;
            }
        }

        String folderPath = (String) arguments.get("folder");
        if (folderPath == null || folderPath.isBlank()) {
            folderPath = "/";
        }

        Object openAfterObj = arguments.get("open_after_import");
        boolean openAfterImport = (openAfterObj == null) || Boolean.TRUE.equals(openAfterObj);
        Object suppressPromptObj = arguments.get("suppress_analysis_prompt");
        boolean suppressAnalysisPrompt = (suppressPromptObj == null) || Boolean.TRUE.equals(suppressPromptObj);

        // --- Perform import ---
        MessageLog messageLog = new MessageLog();

        try {
            ProgramLoader.Builder loader = ProgramLoader.builder().source(file).project(project)
                .projectFolderPath(folderPath).log(messageLog).monitor(monitor);
            if (languageStr != null && !languageStr.isBlank()) {
                Language language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageStr));
                loader.language(language);
                if (compilerStr != null && !compilerStr.isBlank()) {
                    loader.compiler("default".equals(compilerStr) ? language.getDefaultCompilerSpec() :
                        language.getCompilerSpecByID(new CompilerSpecID(compilerStr)));
                }
            } else if (compilerStr != null && !compilerStr.isBlank() && !"default".equals(compilerStr)) {
                loader.compiler(compilerStr);
            }
            if (raw) loader.loaders(BinaryLoader.class);
            if (programName != null) loader.name(programName);

            try (LoadResults<Program> loaded = loader.load()) {
                if (loaded.size() == 0) return error("Import created no program." + formatLog(messageLog));
                Program program = getPrimaryProgram(loaded);
                applyBaseAddress(program, baseAddrStr);
                if (openAfterImport && suppressAnalysisPrompt) AnalysisUtils.setAskToAnalyze(program, false);
                monitor.checkCancelled();
                if (project.isClosed() || manager.getProject() != project) {
                    return error("The destination project changed before saving the import: " + project.getName());
                }
                loaded.save(monitor);
                StringBuilder result = buildResultMessage(program, folderPath, messageLog);
                if (openAfterImport) {
                    try {
                        manager.openProgramInCodeBrowser(project, program);
                    } catch (RuntimeException e) {
                        return error(result + "Saved to the project. Opening CodeBrowser failed: " + e.getMessage());
                    }
                    result.append("  Opened in CodeBrowser: yes\n  Should Ask To Analyze: ")
                          .append(AnalysisUtils.shouldAskToAnalyze(program)).append("\n");
                }
                return McpSchema.CallToolResult.builder().addTextContent(result.toString()).build();
            }
        } catch (DuplicateNameException e) {
            return error("A program with that name already exists in folder '" + folderPath +
                "'. Use a different program_name or folder.");
        } catch (Exception e) {
            Msg.error(this, "Import failed", e);
            return error("Import failed: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private static Program getPrimaryProgram(LoadResults<Program> loadResults) {
        Program[] program = new Program[1];
        loadResults.getPrimary().apply(p -> program[0] = p);
        return program[0];
    }

    static void applyBaseAddress(Program program, String requested) throws Exception {
        if (requested == null) return;
        var space = program.getAddressFactory().getDefaultAddressSpace();
        String value = requested.strip();
        Address base = space.getAddress(value);
        if (base == null) throw new IllegalArgumentException("Invalid image base: " + requested);
        int transaction = program.startTransaction("Set Image Base");
        boolean committed = false;
        try {
            program.setImageBase(base, true);
            committed = true;
        } finally {
            program.endTransaction(transaction, committed);
        }
    }

    private static StringBuilder buildResultMessage(Program program, String folderPath,
                                                     MessageLog messageLog) {
        StringBuilder sb = new StringBuilder();
        sb.append("Successfully imported: ").append(program.getName()).append("\n");
        sb.append("  Project Path: ").append(program.getDomainFile().getPathname()).append("\n");
        sb.append("  Language: ").append(program.getLanguageID()).append("\n");
        sb.append("  Format: ").append(program.getExecutableFormat()).append("\n");
        sb.append("  Image Base: ").append(program.getImageBase()).append("\n");
        sb.append("  Folder: ").append(folderPath).append("\n");
        sb.append(formatLog(messageLog));
        return sb;
    }

    private static String formatLog(MessageLog messageLog) {
        String log = messageLog.toString();
        if (!log.isEmpty()) {
            return "  Import Log: " + log + "\n";
        }
        return "";
    }

    private static McpSchema.CallToolResult error(String message) {
        return McpSchema.CallToolResult.builder().addTextContent(message).isError(true).build();
    }
}
