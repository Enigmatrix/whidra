package tool

import ghidra.app.util.importer.AutoImporter
import ghidra.app.util.importer.MessageLog
import ghidra.framework.model.ProjectData
import ghidra.framework.protocol.ghidra.GhidraURLConnection
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import util.RepositoryUtil
import java.io.File
import java.net.URL

object ImportBinaryTool {
    fun importBinary(repoName: String, binary: String, monitor: TaskMonitor): Program {
        val project = RepositoryUtil.projectData(repoName, false)
        return AutoImporter.importByUsingBestGuess(
            File(binary),
            project.rootFolder,
            this, MessageLog(), monitor
        )
    }
}