import ghidra.base.project.GhidraProject;

import ghidra.app.util.headless.HeadlessScript;

/*
 * Create a shared project
 *
 * analyzeHeadless <shared/non-shared project> -postScript GetProjectBinaries.java -noanalysis
 *
*/

public class GetProjectBinaries extends HeadlessScript {

    @Override
    public void run() throws Exception {
        // TODO make this work for subfolder also
        var folder = state.getProject().getProjectData().getRootFolder();
        println("LIST BEGIN");
        for (var file : folder.getFiles()) {
            println(file.getName());
        }
        println("LIST END");
    }
}
