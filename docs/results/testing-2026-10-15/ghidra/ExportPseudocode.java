// Source-owned test helper: export static decompiler observations only.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.PrintWriter;
import java.io.File;
import java.nio.charset.StandardCharsets;

public class ExportPseudocode extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("one output directory required");
        File output = new File(args[0]);
        if (!output.isDirectory()) throw new IllegalArgumentException("output directory missing");
        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException("openProgram failed");
        int total = 0, completed = 0;
        try (PrintWriter inventory = new PrintWriter(new File(output, "functions.tsv"), StandardCharsets.UTF_8);
             PrintWriter all = new PrintWriter(new File(output, "pseudocode.txt"), StandardCharsets.UTF_8)) {
            inventory.println("entry\tname\tbody_addresses\tstatus\terror");
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext() && !monitor.isCancelled()) {
                Function fn = functions.next();
                if (fn.isExternal()) continue;
                total++;
                DecompileResults result = decompiler.decompileFunction(fn, 30, monitor);
                boolean done = result.decompileCompleted() && result.getDecompiledFunction() != null;
                if (done) completed++;
                String error = result.getErrorMessage().replace('\t', ' ').replace('\n', ' ');
                inventory.println(fn.getEntryPoint() + "\t" + fn.getName() + "\t" + fn.getBody().getNumAddresses() + "\t" + (done ? "completed" : "unavailable") + "\t" + error);
                all.println("// ENTRY " + fn.getEntryPoint() + " NAME " + fn.getName());
                if (done) {
                    String c = result.getDecompiledFunction().getC();
                    all.println(c);
                    try (PrintWriter single = new PrintWriter(new File(output, fn.getEntryPoint().toString().replace(':','_') + ".c"), StandardCharsets.UTF_8)) { single.println(c); }
                } else all.println("// DECOMPILATION UNAVAILABLE: " + error);
                all.println();
            }
        } finally { decompiler.dispose(); }
        println("ExportPseudocode completed=" + completed + " total=" + total + " language=" + currentProgram.getLanguageID());
    }
}
