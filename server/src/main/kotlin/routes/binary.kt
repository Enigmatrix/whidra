package routes

import ghidra.WhidraClient
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.AutoImporter
import ghidra.app.util.importer.MessageLog
import ghidra.base.project.GhidraProject.openProject
import ghidra.openProject
import ghidra.program.util.GhidraProgramUtilities
import io.ktor.application.call
import io.ktor.http.content.PartData
import io.ktor.http.content.readAllParts
import io.ktor.http.content.streamProvider
import io.ktor.locations.*
import io.ktor.request.receiveMultipart
import io.ktor.response.respond
import io.ktor.routing.Route
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import models.Binary
import session.whidraSession
import utils.WhidraException
import utils.task
import java.io.File

@Location("/{project}/binary/{name}")
data class Binary(val project: String, val name: String) {

}

@Location("/{project}/binary/upload")
data class UploadBinary(val project: String, val name: String)

fun Route.binaries() {
    post<UploadBinary> {
        val session = call.whidraSession()
        val form = call.receiveMultipart()
        val binary = form.readAllParts().filterIsInstance<PartData.FileItem>()
            .firstOrNull() ?: throw WhidraException("Upload binary not found")

        task<Binary> {
            val file = File("/tmp/${it.name}")
            withContext(Dispatchers.IO){
                file.createNewFile()
            }

            // copy file stream into file
            binary.streamProvider().use { input ->
                file.outputStream().use { fileOut ->
                    input.copyTo(fileOut)
                }
            }


            val project = session.openProject(it.project, false)
            val program = withContext(Dispatchers.IO) {
                AutoImporter.importByUsingBestGuess(
                    file,
                    project.rootFolder,
                    this, MessageLog(), monitor()
                )
            }

            val mgr = AutoAnalysisManager.getAnalysisManager(program)
            val txId = program.startTransaction("Analysis")
            mgr.initializeOptions()
            mgr.reAnalyzeAll(null)
            mgr.startAnalysis(monitor())
            GhidraProgramUtilities.setAnalyzedFlag(program, true);
            program.endTransaction(txId, true)

            withContext(Dispatchers.IO) {
                program.save("Analysis", monitor())
                program.domainFile.addToVersionControl("Add file ${it.name}", false, monitor())
            }

            project.close()
            file.delete()

            return@task Binary(it.name)
        }
    }
}