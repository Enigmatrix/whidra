package routes

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.AutoImporter
import ghidra.app.util.importer.MessageLog
import ghidra.framework.model.ProjectData
import ghidra.framework.protocol.ghidra.GhidraURLConnection
import ghidra.program.model.listing.Program
import ghidra.program.util.GhidraProgramUtilities
import io.ktor.application.ApplicationCall
import io.ktor.application.call
import io.ktor.http.CacheControl
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.streamProvider
import io.ktor.request.receive
import io.ktor.request.receiveMultipart
import io.ktor.request.receiveParameters
import io.ktor.response.cacheControl
import io.ktor.response.respond
import io.ktor.response.respondOutputStream
import io.ktor.response.respondTextWriter
import io.ktor.routing.Route
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.routing.route
import io.ktor.sessions.get
import io.ktor.sessions.sessions
import io.ktor.util.pipeline.PipelineContext
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import main.tasks
import model.Binary
import model.Event
import model.Repository
import util.RepositoryUtil
import util.field
import java.io.File
import java.net.URL

class RepositoryService : Service() {
    fun getAllRepositories(): List<Repository> {
        return RepositoryUtil.repositories().map { name ->
            Repository(name, RepositoryUtil.binaries(name).map { Binary(it) })
        }
    }

    fun newRepository(repoName: String) {
        RepositoryUtil.newRepository(repoName)
    }

    fun importBinary(repoName: String, binary: File) = task<Unit> {
        val project = openProject(repoName, false)
        val program = AutoImporter.importByUsingBestGuess(
            binary,
            project.rootFolder,
            this, MessageLog(), monitor())

        val mgr = AutoAnalysisManager.getAnalysisManager(program)
        val txId = program.startTransaction("Analysis")
        mgr.initializeOptions()
        mgr.reAnalyzeAll(null)
        mgr.startAnalysis(monitor())
        GhidraProgramUtilities.setAnalyzedFlag(program, true);
        program.endTransaction(txId, true)

        program.save("Analysis", monitor())
        program.domainFile.addToVersionControl("Add file ${binary.nameWithoutExtension}", false, monitor())

        project.close()
    }

    fun deleteBinaries(repoName: String){
        val project = openProject(repoName, false)
        project.rootFolder.files.forEach {
            it.delete()
        }
    }
}

suspend fun <T> PipelineContext<Unit, ApplicationCall>.outputTask(task: Task<T>) {
    val session = call.sessions.get<model.Session>()
    if(session != null){
        tasks.getOrPut(session.id, { Channel() }).send(task)
    }
    coroutineScope {
        withContext(Dispatchers.Default){
            call.respond(task.execute())
        }
    }
}

fun Route.routesFor(svc: RepositoryService) {
    route("/repository") {
        get {
            call.respond(svc.getAllRepositories())
        }

        post("import") {
            val form = call.receiveForm();
            val repoName = form.field("repository")
            val binary = form.file("binary")
            // create file
            val file = File("/tmp/${binary.originalFileName}")
            withContext(Dispatchers.IO){
                file.createNewFile()
            }
            // copy file stream into file
            binary.streamProvider().use { input ->
                file.outputStream().use { fileOut ->
                    input.copyTo(fileOut)
                }
            }

            outputTask(svc.importBinary(repoName, file))

            //delete afterwards
            file.delete()
        }

        post("delete") {
            val repoName = call.field("repository")
            svc.deleteBinaries(repoName)
            call.respond(HttpStatusCode.OK)
        }

        post("new") {
            val form = call.receiveForm();
            val repoName = form.field("name")
            svc.newRepository(repoName)
            call.respond(HttpStatusCode.OK)
        }
    }
}
