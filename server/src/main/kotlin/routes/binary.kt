package routes

import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.AutoImporter
import ghidra.app.util.importer.MessageLog
import ghidra.program
import ghidra.projectData
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
import models.Function
import session.appSession
import utils.FormFieldMissing
import utils.task
import java.io.File

@Location("/{project}/binary/{name}")
data class Binary(val project: String, val name: String) {
    @Location("/functions")
    data class Functions(val binary: routes.Binary)

    @Location("/code")
    data class Code(val binary: routes.Binary, val addr: String)

    @Location("/listing")
    data class Listing(val binary: routes.Binary, val addr: String, val len: Int)
}

@Location("/{project}/binary/upload")
data class UploadBinary(val project: String, val name: String)

fun Route.binaries() {

    get<routes.Binary.Listing> {

    }

    get<routes.Binary.Code> {

    }

    get<routes.Binary.Functions> { func ->
        val (server) = call.appSession()

        val program = server.program(func.binary.project, func.binary.name)
        call.respond(program.functionManager.getFunctions(true).map {
            Function(it.name, it.signature.getPrototypeString(true), it.entryPoint.offset,  it.isInline, it.isThunk, it.isExternal)
        })
    }

    post<UploadBinary> {
        val (server) = call.appSession()
        val form = call.receiveMultipart()
        val binary = form.readAllParts().filterIsInstance<PartData.FileItem>()
            .firstOrNull() ?: throw FormFieldMissing("binary")

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


            val project = server.projectData(it.project, false)
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
            GhidraProgramUtilities.setAnalyzedFlag(program, true)
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