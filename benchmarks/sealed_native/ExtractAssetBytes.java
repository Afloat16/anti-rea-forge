// Receives only a new report path. Never receives the expected payload, hash or key.
//@category ReleaseGuard
import com.google.gson.Gson;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.framework.Application;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SymbolIterator;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ExtractAssetBytes extends HeadlessScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1 || analysisTimeoutOccurred())
            throw new IllegalStateException("Require output path and completed analysis");
        Map<String,Object> out = new LinkedHashMap<>();
        out.put("tool", "Ghidra");
        out.put("version", Application.getApplicationVersion());
        out.put("input_sha256", currentProgram.getExecutableSHA256());
        out.put("language", currentProgram.getLanguageID().toString());
        out.put("format", currentProgram.getExecutableFormat());
        List<Map<String,Object>> blocks = new ArrayList<>();
        long total = 0;
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (!block.isInitialized() || !block.isLoaded()) continue;
            monitor.checkCancelled();
            total += block.getSize();
            if (total > 2L * 1024 * 1024) throw new IllegalStateException("Fixture image exceeds budget");
            byte[] bytes = new byte[(int)block.getSize()];
            if (block.getBytes(block.getStart(), bytes) != bytes.length)
                throw new IllegalStateException("Incomplete loaded block");
            Map<String,Object> row = new LinkedHashMap<>();
            row.put("start", "0x" + Long.toHexString(block.getStart().getOffset()));
            row.put("size", bytes.length);
            row.put("hex", HexFormat.of().formatHex(bytes));
            blocks.add(row);
        }
        if (blocks.isEmpty()) throw new IllegalStateException("Empty analysis");
        out.put("loaded_bytes", total);
        out.put("loaded_range_count", blocks.size());
        out.put("blocks", blocks);
        SymbolIterator symbols = currentProgram.getSymbolTable().getSymbols("rg_asset_gate");
        if (!symbols.hasNext()) throw new IllegalStateException("Gate export missing");
        Function gate = getFunctionAt(symbols.next().getAddress());
        if (gate == null || gate.isExternal() || symbols.hasNext())
            throw new IllegalStateException("Missing/ambiguous gate");
        int count = 0;
        InstructionIterator instructions = currentProgram.getListing().getInstructions(gate.getBody(), true);
        while (instructions.hasNext()) { instructions.next(); count++; }
        if (count == 0) throw new IllegalStateException("Gate has no disassembly");
        int size = (int)gate.getBody().getNumAddresses();
        byte[] prefix = new byte[Math.min(size, 16)];
        if (size < 6 || currentProgram.getMemory().getBytes(gate.getEntryPoint(), prefix) != prefix.length)
            throw new IllegalStateException("Gate bytes missing");
        out.put("gate_name", gate.getName());
        out.put("gate_entry", "0x" + Long.toHexString(gate.getEntryPoint().getOffset()));
        out.put("gate_size", size);
        out.put("gate_instructions", count);
        out.put("gate_prefix_hex", HexFormat.of().formatHex(prefix));
        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException("Decompiler unavailable");
        try {
            DecompileResults result = decompiler.decompileFunction(gate, 45, monitor);
            if (!result.decompileCompleted() || result.getDecompiledFunction() == null)
                throw new IllegalStateException("Gate not decompiled");
            out.put("gate_decompiled_bytes", result.getDecompiledFunction().getC().getBytes(StandardCharsets.UTF_8).length);
        } finally { decompiler.dispose(); }
        Files.writeString(Path.of(args[0]), new Gson().toJson(out), StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
        println("RELEASEGUARD_ASSET_BYTES_COMPLETE");
    }
}
