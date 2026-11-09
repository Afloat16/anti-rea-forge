// Synthetic fixture only. Never given a token, its digest, the issuer's files,
// source code or a precomputed address. The single argument is a new report path.
//@category ReleaseGuard
import com.google.gson.Gson;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.*;

public class InspectTokenGate extends HeadlessScript {
    private static final Pattern TOKEN = Pattern.compile("rg1_[0-9a-f]{64}");

    private static Set<String> matches(String text) {
        Set<String> out = new TreeSet<>();
        Matcher m = TOKEN.matcher(text);
        while (m.find()) out.add(m.group());
        return out;
    }

    @Override public void run() throws Exception {
        if (getScriptArgs().length != 1 || analysisTimeoutOccurred())
            throw new IllegalStateException("Need output path and completed auto-analysis");
        Map<String,Object> out = new LinkedHashMap<>();
        out.put("ghidra_version", Application.getApplicationVersion());
        out.put("java_runtime", System.getProperty("java.runtime.version"));
        out.put("java_vendor", System.getProperty("java.vendor"));
        out.put("input_sha256", currentProgram.getExecutableSHA256());
        out.put("format", currentProgram.getExecutableFormat());
        out.put("language", currentProgram.getLanguageID().toString());
        out.put("analysis_timed_out", false);
        Memory mem = currentProgram.getMemory();
        Set<String> memoryTokens = new TreeSet<>(), decompiledTokens = new TreeSet<>();
        int blocks = 0;
        long total = 0;
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized() || !block.isLoaded()) continue;
            monitor.checkCancelled();
            total += block.getSize();
            if (total > 16L * 1024 * 1024) throw new IllegalStateException("Fixture too large");
            byte[] bytes = new byte[(int)block.getSize()];
            if (block.getBytes(block.getStart(), bytes) != bytes.length)
                throw new IllegalStateException("Incomplete loaded-block read");
            memoryTokens.addAll(matches(new String(bytes, StandardCharsets.ISO_8859_1)));
            blocks++;
        }
        if (blocks == 0 || total == 0) throw new IllegalStateException("Empty loaded image");
        out.put("initialized_loaded_blocks", blocks);
        out.put("initialized_loaded_bytes", total);
        out.put("memory_candidates", memoryTokens);
        List<Map<String,Object>> selected = new ArrayList<>();
        int functionCount = 0;
        boolean gate = false;
        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException("Cannot decompile");
        try {
            FunctionIterator fns = currentProgram.getFunctionManager().getFunctions(true);
            while (fns.hasNext()) {
                Function f = fns.next();
                if (f.isExternal()) continue;
                functionCount++;
                String name = f.getName();
                if (!name.startsWith("rg_") && !name.contains("verify_issued_token")
                        && !name.contains("verify_native_token")) continue;
                monitor.checkCancelled();
                DecompileResults result = decompiler.decompileFunction(f, 45, monitor);
                if (!result.decompileCompleted() || result.getDecompiledFunction() == null)
                    throw new IllegalStateException("Incomplete function: " + name);
                String code = result.getDecompiledFunction().getC();
                if (code.isBlank() || !code.contains("return"))
                    throw new IllegalStateException("Missing/empty decompiler body: " + name);
                byte[] raw = code.getBytes(StandardCharsets.UTF_8);
                Set<String> found = matches(code);
                decompiledTokens.addAll(found);
                Map<String,Object> row = new LinkedHashMap<>();
                row.put("name", name);
                row.put("entry", f.getEntryPoint().toString());
                row.put("body_addresses", f.getBody().getNumAddresses());
                row.put("decompiled_c_bytes", raw.length);
                row.put("decompiled_c_sha256", HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw)));
                row.put("mentions_comparison", code.contains("memcmp"));
                row.put("mentions_token_verifier", code.contains("verify_issued_token") || code.contains("verify_native_token"));
                row.put("matches", found.size());
                selected.add(row);
                if (name.equals("rg_admit")) gate = true;
            }
        } finally { decompiler.dispose(); }
        if (!gate) throw new IllegalStateException("Real admission gate not decompiled");
        out.put("nonexternal_functions", functionCount);
        out.put("decompiled_functions", selected);
        out.put("decompiler_candidates", decompiledTokens);
        // The verifier is deliberately public. Read its actual named storage
        // from Ghidra's image, with no expected bytes or address as input.
        List<Map<String,Object>> digests = new ArrayList<>();
        SymbolIterator syms = currentProgram.getSymbolTable().getAllSymbols(true);
        while (syms.hasNext()) {
            Symbol symbol = syms.next();
            if (!symbol.getName().contains("issued_token_digest")) continue;
            Address at = symbol.getAddress();
            MemoryBlock block = mem.getBlock(at);
            if (block == null || !block.isLoaded() || !block.isInitialized() || block.isExecute()) continue;
            byte[] bytes = new byte[32];
            if (mem.getBytes(at, bytes) != bytes.length) continue;
            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(at);
            int references = 0;
            while (refs.hasNext()) { refs.next(); references++; }
            Map<String,Object> record = new LinkedHashMap<>();
            record.put("symbol", symbol.getName(true));
            record.put("address", at.toString());
            record.put("references", references);
            record.put("bytes_hex", HexFormat.of().formatHex(bytes));
            digests.add(record);
        }
        out.put("public_digest_symbols", digests);
        monitor.checkCancelled();
        Files.writeString(Path.of(getScriptArgs()[0]), new Gson().toJson(out),
            StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
        println("RELEASEGUARD_GHIDRA_COMPLETE");
    }
}
