package tool

import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.program.model.listing.Program
import ghidra.program.util.GhidraProgramUtilities
import ghidra.util.task.TaskMonitor

object AutoAnalysisTool {
    fun analyzeProgram(program: Program, monitor: TaskMonitor) {
        val mgr = AutoAnalysisManager.getAnalysisManager(program)

        val txId = program.startTransaction("Analysis")
        try {
            mgr.initializeOptions()
            mgr.reAnalyzeAll(null)
            mgr.startAnalysis(monitor)
            GhidraProgramUtilities.setAnalyzedFlag(program, true);
        } finally {
            program.endTransaction(txId, true)
        }

        program.save("Auto analysis", monitor)
    }
}