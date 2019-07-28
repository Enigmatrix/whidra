import ghidra.app.util.headless.HeadlessScript;
import ghidra.framework.Application;
import ghidra.util.GhidraJarBuilder;

import java.io.File;
import java.util.stream.Collectors;

public class BuildSingleGhidraJar extends HeadlessScript {

    @Override
    public void run() throws Exception {
        var builder =
                new GhidraJarBuilder(
                        Application.getApplicationRootDirectories()
                                .stream()
                .map(x -> x.getFile(true))
                .collect(Collectors.toList()));

        builder.setMainClass("ghidra.JarRun");
        builder.addAllModules();

        builder.addExcludedFileExtension(".htm");
        builder.addExcludedFileExtension(".html");
        builder.addExcludedFileExtension(".pdf");

        builder.buildJar(new File(getScriptArgs()[0]), null, monitor);
    }

}

