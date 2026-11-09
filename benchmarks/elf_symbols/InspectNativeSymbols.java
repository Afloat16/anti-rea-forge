// The private address aligns all cases. Discover the exported gate by its stable public name.
//@category ReleaseGuard
import com.google.gson.Gson;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.Symbol;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeSet;

public class InspectNativeSymbols extends HeadlessScript {
    private void observe(Map<String,Object> out, DecompInterface decompiler, String label, Address entry)
            throws Exception {
        Function function = getFunctionAt(entry);
        if (function == null || function.isExternal()) throw new IllegalStateException("Missing " + label);
        InstructionIterator disassembly = currentProgram.getListing().getInstructions(function.getBody(), true);
        int count = 0;
        while (disassembly.hasNext()) { disassembly.next(); count++; }
        if (count == 0) throw new IllegalStateException("No instructions");
        DecompileResults result = decompiler.decompileFunction(function, 45, monitor);
        if (!result.decompileCompleted() || result.getDecompiledFunction() == null ||
            !result.getDecompiledFunction().getC().contains("return"))
            throw new IllegalStateException("No decompiled implementation");
        TreeSet<String> names = new TreeSet<>();
        for (Symbol symbol : currentProgram.getSymbolTable().getSymbols(entry)) names.add(symbol.getName());
        out.put(label + "_name", function.getName());
        out.put(label + "_aliases", names);
        out.put(label + "_entry", "0x" + Long.toHexString(entry.getOffset()));
        out.put(label + "_instructions", count);
        out.put(label + "_decompiled_bytes", result.getDecompiledFunction().getC().getBytes(StandardCharsets.UTF_8).length);
    }

    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2 || analysisTimeoutOccurred())
            throw new IllegalStateException("Expected completed analysis, output path and private address");
        Map<String,Object> out = new LinkedHashMap<>();
        out.put("tool", "Ghidra");
        out.put("version", Application.getApplicationVersion());
        out.put("input_sha256", currentProgram.getExecutableSHA256());
        out.put("language", currentProgram.getLanguageID().toString());
        out.put("format", currentProgram.getExecutableFormat());
        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException("Decompiler unavailable");
        try {
            Address privateEntry = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(Long.decode(args[1]));
            SymbolIterator symbols = currentProgram.getSymbolTable().getSymbols("rg_public_entry");
            if (!symbols.hasNext()) throw new IllegalStateException("Exported gate missing");
            Address publicEntry = symbols.next().getAddress();
            if (symbols.hasNext()) throw new IllegalStateException("Ambiguous exported gate");
            observe(out, decompiler, "private", privateEntry);
            observe(out, decompiler, "public", publicEntry);
        } finally { decompiler.dispose(); }
        monitor.checkCancelled();
        Files.writeString(Path.of(args[0]), new Gson().toJson(out), StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
        println("RELEASEGUARD_NATIVE_SYMBOLS_COMPLETE");
    }
}
