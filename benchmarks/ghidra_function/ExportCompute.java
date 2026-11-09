// Receives an output directory and optional include-program mode. The target name is fixed.
//@category ReleaseGuard
import com.google.gson.GsonBuilder;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.framework.Application;
import ghidra.program.database.mem.AddressSourceInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ExportCompute extends HeadlessScript {
    private static final String TARGET = "rg_compute";
    private static final long MAX_BODY_BYTES = 1024 * 1024;
    private static final long MAX_PROGRAM_BYTES = 16 * 1024 * 1024;

    private String address(Address value) {
        if (value == null) return null;
        return value.isMemoryAddress() ? "0x" + Long.toHexString(value.getOffset()) : value.toString();
    }

    private List<Map<String, Object>> ranges(AddressSetView addresses) {
        List<Map<String, Object>> result = new ArrayList<>();
        AddressRangeIterator iterator = addresses.getAddressRanges();
        while (iterator.hasNext()) {
            AddressRange range = iterator.next();
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("start", address(range.getMinAddress()));
            row.put("size", range.getLength());
            result.add(row);
        }
        return result;
    }

    private Map<String, Object> functionSummary(Function function) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("name", function.getName());
        row.put("entry", address(function.getEntryPoint()));
        row.put("prototype", function.getPrototypeString(true, true));
        row.put("external", function.isExternal());
        row.put("thunk", function.isThunk());
        if (function.isThunk()) {
            Function target = function.getThunkedFunction(true);
            if (target != null) {
                row.put("thunk_target_name", target.getName());
                row.put("thunk_target_entry", address(target.getEntryPoint()));
            }
        }
        return row;
    }

    private Map<String, Object> byteRange(Address start, long fileOffset, byte[] original, byte[] loaded) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("start", address(start));
        row.put("size", original.length);
        if (fileOffset >= 0) {
            row.put("file_offset", fileOffset);
            row.put("hex", HexFormat.of().formatHex(original));
        }
        row.put("loaded_hex", HexFormat.of().formatHex(loaded));
        return row;
    }

    private Map<String, Object> memoryBytes(AddressSetView addresses, boolean requireFile) throws Exception {
        List<Map<String, Object>> result = new ArrayList<>();
        long modified = 0;
        long backed = 0;
        AddressRangeIterator iterator = addresses.getAddressRanges();
        while (iterator.hasNext()) {
            AddressRange range = iterator.next();
            byte[] bytes = new byte[Math.toIntExact(range.getLength())];
            byte[] original = new byte[bytes.length];
            Address start = range.getMinAddress();
            if (currentProgram.getMemory().getBytes(start, bytes) != bytes.length)
                throw new IllegalStateException("Incomplete initialized memory read");
            int chunkStart = 0;
            long chunkOffset = -1;
            for (int index = 0; index < bytes.length; index++) {
                monitor.checkCancelled();
                AddressSourceInfo source = currentProgram.getMemory().getAddressSourceInfo(start.add(index));
                long offset = source == null ? -1 : source.getFileOffset();
                if (requireFile && offset < 0)
                    throw new IllegalStateException("Function byte has no original file provenance");
                if (offset >= 0) {
                    original[index] = source.getOriginalValue();
                    backed++;
                    if (original[index] != bytes[index]) modified++;
                }
                if (index == 0) chunkOffset = offset;
                boolean sameSource = chunkOffset < 0 ? offset < 0 : offset == chunkOffset + index - chunkStart;
                if (!sameSource) {
                    result.add(byteRange(start.add(chunkStart), chunkOffset,
                                         Arrays.copyOfRange(original, chunkStart, index),
                                         Arrays.copyOfRange(bytes, chunkStart, index)));
                    chunkStart = index;
                    chunkOffset = offset;
                }
            }
            result.add(byteRange(start.add(chunkStart), chunkOffset,
                                 Arrays.copyOfRange(original, chunkStart, original.length),
                                 Arrays.copyOfRange(bytes, chunkStart, bytes.length)));
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ranges", result);
        out.put("file_backed_bytes", backed);
        out.put("unbacked_bytes", addresses.getNumAddresses() - backed);
        out.put("loaded_byte_changes", modified);
        return out;
    }

    private void writeJson(Path file, Object value) throws Exception {
        Files.writeString(file, new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(value),
                          StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
    }

    private void exportProgram(Path output, DecompInterface decompiler) throws Exception {
        List<Function> functions = new ArrayList<>();
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            Function function = iterator.next();
            if (!function.isExternal()) functions.add(function);
        }
        if (functions.isEmpty() || functions.size() > 2048)
            throw new IllegalStateException("Program function inventory is outside the export budget");
        List<Map<String, Object>> inventory = new ArrayList<>();
        for (Function function : functions) inventory.add(functionSummary(function));
        List<Map<String, Object>> observations = new ArrayList<>();
        ByteArrayOutputStream programC = new ByteArrayOutputStream();
        int completed = 0;
        for (Function function : functions) {
            monitor.checkCancelled();
            Map<String, Object> row = functionSummary(function);
            row.put("body_ranges", ranges(function.getBody()));
            row.put("body_addresses", function.getBody().getNumAddresses());
            List<String> calls = new ArrayList<>();
            for (Function callee : function.getCalledFunctions(monitor)) calls.add(address(callee.getEntryPoint()));
            calls.sort(String::compareTo);
            row.put("called_entries", calls);
            programC.writeBytes(("\n/* GHIDRA FUNCTION " + address(function.getEntryPoint()) + " */\n")
                                .getBytes(StandardCharsets.UTF_8));
            byte[] code = new byte[0];
            String status = "failed";
            String message = "";
            try {
                DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
                message = result.getErrorMessage();
                if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    code = result.getDecompiledFunction().getC().getBytes(StandardCharsets.UTF_8);
                    if (code.length > 0) status = "completed";
                }
                if (result.isTimedOut()) status = "timeout";
                if (result.isCancelled()) status = "cancelled";
            } catch (Exception error) {
                monitor.checkCancelled();
                message = error.getClass().getName() + " " + error.getMessage();
            }
            if (!status.equals("completed") && (message == null || message.isBlank()))
                message = "Decompiler returned " + status + " without a C result";
            row.put("status", status);
            row.put("message", message);
            row.put("c_offset", programC.size());
            row.put("c_bytes", code.length);
            row.put("c_sha256", HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(code)));
            programC.writeBytes(code);
            if (status.equals("completed")) completed++;
            observations.add(row);
            if (programC.size() > MAX_PROGRAM_BYTES)
                throw new IllegalStateException("Program C export exceeds the export budget");
            println("RELEASEGUARD_PROGRAM_FUNCTION " + address(function.getEntryPoint()) + " " + status);
        }
        Map<String, Object> program = new LinkedHashMap<>();
        program.put("schema", "releaseguard.program-observation.v1");
        program.put("input_sha256", currentProgram.getExecutableSHA256());
        program.put("function_inventory", inventory);
        program.put("functions", observations);
        program.put("function_count", functions.size());
        program.put("completed_functions", completed);
        program.put("failed_functions", functions.size() - completed);
        Files.write(output.resolve("program.c"), programC.toByteArray(), StandardOpenOption.CREATE_NEW);
        writeJson(output.resolve("program.json"), program);

        List<Map<String, Object>> blocks = new ArrayList<>();
        long total = 0;
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            monitor.checkCancelled();
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("name", block.getName());
            row.put("start", address(block.getStart()));
            row.put("size", block.getSize());
            row.put("read", block.isRead());
            row.put("write", block.isWrite());
            row.put("execute", block.isExecute());
            row.put("loaded", block.isLoaded());
            row.put("initialized", block.isInitialized());
            row.put("external", block.isExternalBlock());
            if (block.isInitialized() && block.isLoaded()) {
                total += block.getSize();
                if (total > MAX_PROGRAM_BYTES)
                    throw new IllegalStateException("Initialized program memory exceeds the export budget");
                row.put("memory", memoryBytes(new AddressSet(block.getStart(), block.getEnd()), false));
            }
            blocks.add(row);
        }
        Map<String, Object> memory = new LinkedHashMap<>();
        memory.put("schema", "releaseguard.program-memory.v1");
        memory.put("input_sha256", currentProgram.getExecutableSHA256());
        memory.put("initialized_loaded_bytes", total);
        memory.put("blocks", blocks);
        writeJson(output.resolve("program-memory.json"), memory);
    }

    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1 || args.length > 2 || (args.length == 2 && !args[1].equals("include-program"))
                || analysisTimeoutOccurred())
            throw new IllegalStateException("Require output directory, optional include-program, and completed analysis");
        boolean includeProgram = args.length == 2;
        Path output = Path.of(args[0]);
        if (!Files.isDirectory(output)) throw new IllegalStateException("Output directory is missing");

        SymbolIterator symbols = currentProgram.getSymbolTable().getSymbols(TARGET);
        if (!symbols.hasNext()) throw new IllegalStateException("Public target symbol missing");
        Symbol symbol = symbols.next();
        Function function = getFunctionAt(symbol.getAddress());
        if (symbols.hasNext() || function == null || function.isExternal() || (function.isThunk() && !includeProgram)
                || !symbol.getParentNamespace().isGlobal() || !TARGET.equals(function.getName()))
            throw new IllegalStateException("Public target is ambiguous or is not a defined global function");
        long bodySize = function.getBody().getNumAddresses();
        if (bodySize == 0 || bodySize > MAX_BODY_BYTES)
            throw new IllegalStateException("Function size is outside the measurement budget");

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("schema", "releaseguard.function-observation.v1");
        out.put("tool", "Ghidra");
        out.put("version", Application.getApplicationVersion());
        out.put("java_runtime", System.getProperty("java.runtime.version"));
        out.put("java_vendor", System.getProperty("java.vendor"));
        out.put("input_sha256", currentProgram.getExecutableSHA256());
        out.put("format", currentProgram.getExecutableFormat());
        out.put("language", currentProgram.getLanguageID().toString());
        out.put("image_base", address(currentProgram.getImageBase()));
        out.put("analysis_timed_out", false);
        out.put("public_abi", "uint32_t rg_compute(uint32_t)");
        out.put("symbol_source", symbol.getSource().toString());
        out.put("target", functionSummary(function));
        out.put("body_addresses", bodySize);
        out.put("body_ranges", ranges(function.getBody()));
        Map<String, Object> targetBytes = memoryBytes(function.getBody(), true);
        out.put("original_byte_ranges", targetBytes.get("ranges"));
        out.put("loaded_function_byte_changes", targetBytes.get("loaded_byte_changes"));

        List<Map<String, Object>> instructions = new ArrayList<>();
        List<Map<String, Object>> callSites = new ArrayList<>();
        List<Map<String, Object>> computedTransfers = new ArrayList<>();
        List<Map<String, Object>> outgoingFlows = new ArrayList<>();
        List<Map<String, Object>> dataDependencies = new ArrayList<>();
        AddressSet decoded = new AddressSet();
        InstructionIterator iterator = currentProgram.getListing().getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = iterator.next();
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("address", address(instruction.getAddress()));
            row.put("size", instruction.getLength());
            row.put("hex", HexFormat.of().formatHex(instruction.getBytes()));
            row.put("text", instruction.toString());
            row.put("flow_type", instruction.getFlowType().toString());
            row.put("fallthrough", address(instruction.getFallThrough()));
            List<String> flows = new ArrayList<>();
            for (Address destination : instruction.getFlows()) {
                flows.add(address(destination));
                if (!function.getBody().contains(destination)) {
                    Map<String, Object> flow = new LinkedHashMap<>();
                    flow.put("from", address(instruction.getAddress()));
                    flow.put("to", address(destination));
                    flow.put("type", instruction.getFlowType().toString());
                    outgoingFlows.add(flow);
                }
            }
            Address fallthrough = instruction.getFallThrough();
            if (fallthrough != null && !function.getBody().contains(fallthrough)) {
                Map<String, Object> flow = new LinkedHashMap<>();
                flow.put("from", address(instruction.getAddress()));
                flow.put("to", address(fallthrough));
                flow.put("type", "FALL_THROUGH");
                outgoingFlows.add(flow);
            }
            row.put("flow_targets", flows);
            if (instruction.getFlowType().isCall()) callSites.add(row);
            if (instruction.getFlowType().isComputed()) computedTransfers.add(row);
            for (Reference reference : instruction.getReferencesFrom()) {
                Address destination = reference.getToAddress();
                if (!reference.getReferenceType().isData() || !destination.isMemoryAddress()
                        || function.getBody().contains(destination)) continue;
                Map<String, Object> dependency = new LinkedHashMap<>();
                dependency.put("from", address(instruction.getAddress()));
                dependency.put("to", address(destination));
                dependency.put("type", reference.getReferenceType().toString());
                dependency.put("operand", reference.getOperandIndex());
                Symbol dataSymbol = currentProgram.getSymbolTable().getPrimarySymbol(destination);
                if (dataSymbol != null) dependency.put("symbol", dataSymbol.getName());
                MemoryBlock block = currentProgram.getMemory().getBlock(destination);
                if (block != null) dependency.put("memory_block", block.getName());
                dataDependencies.add(dependency);
            }
            decoded.add(instruction.getMinAddress(), instruction.getMaxAddress());
            instructions.add(row);
        }
        if (instructions.isEmpty()) throw new IllegalStateException("Function has no decoded instructions");
        if (!function.getBody().contains(decoded))
            throw new IllegalStateException("Decoded instruction extends outside the function body");
        AddressSet undecoded = function.getBody().subtract(decoded);
        out.put("instructions", instructions);
        out.put("instruction_count", instructions.size());
        out.put("undecoded_ranges", ranges(undecoded));
        out.put("undecoded_bytes", undecoded.getNumAddresses());

        List<Map<String, Object>> blocks = new ArrayList<>();
        BasicBlockModel model = new BasicBlockModel(currentProgram);
        CodeBlockIterator blockIterator = model.getCodeBlocksContaining(function.getBody(), monitor);
        while (blockIterator.hasNext()) {
            CodeBlock block = blockIterator.next();
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("entry", address(block.getFirstStartAddress()));
            row.put("ranges", ranges(block.intersect(function.getBody())));
            List<Map<String, Object>> edges = new ArrayList<>();
            CodeBlockReferenceIterator references = block.getDestinations(monitor);
            while (references.hasNext()) {
                CodeBlockReference reference = references.next();
                Map<String, Object> edge = new LinkedHashMap<>();
                edge.put("destination_block", address(reference.getDestinationAddress()));
                edge.put("from_instruction", address(reference.getReferent()));
                edge.put("to_address", address(reference.getReference()));
                edge.put("flow_type", reference.getFlowType().toString());
                edge.put("inside_function", function.getBody().contains(reference.getReference()));
                edges.add(edge);
            }
            row.put("edges", edges);
            blocks.add(row);
        }
        if (blocks.isEmpty()) throw new IllegalStateException("Function has no basic blocks");
        out.put("cfg_model", model.getName());
        out.put("cfg_blocks", blocks);

        List<Function> callees = new ArrayList<>(function.getCalledFunctions(monitor));
        callees.sort(Comparator.comparing(Function::getEntryPoint));
        List<Map<String, Object>> calledFunctions = new ArrayList<>();
        for (Function callee : callees) calledFunctions.add(functionSummary(callee));
        Map<String, Object> dependencies = new LinkedHashMap<>();
        dependencies.put("called_functions", calledFunctions);
        dependencies.put("call_sites", callSites);
        dependencies.put("computed_transfers", computedTransfers);
        dependencies.put("outgoing_flows", outgoingFlows);
        dependencies.put("external_data_references", dataDependencies);
        out.put("dependencies", dependencies);

        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram))
                throw new IllegalStateException("Decompiler could not open the imported program "
                                                + decompiler.getLastMessage());
            DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
            boolean complete = result.decompileCompleted() && result.getDecompiledFunction() != null;
            if (!complete && !includeProgram)
                throw new IllegalStateException("Function decompilation incomplete " + result.getErrorMessage());
            String code = complete ? result.getDecompiledFunction().getC() : "";
            if (complete && code.isBlank()) throw new IllegalStateException("Empty decompiled function");
            out.put("decompile_completed", complete);
            out.put("decompiler_message", result.getErrorMessage());
            out.put("decompiled_c_bytes", code.getBytes(StandardCharsets.UTF_8).length);
            Files.writeString(output.resolve("decompiled.c"), code, StandardCharsets.UTF_8,
                              StandardOpenOption.CREATE_NEW);
            if (includeProgram) exportProgram(output, decompiler);
        } finally {
            decompiler.dispose();
        }
        writeJson(output.resolve("function.json"), out);
        println("RELEASEGUARD_FUNCTION_EXPORT_COMPLETE");
    }
}
