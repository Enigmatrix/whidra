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
import io.ktor.util.pipeline.PipelineContext
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import model.Binary
import model.Event
import model.Repository
import util.RepositoryUtil
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

    fun importBinary(repoName: String, binaryName: String) = task<Unit> {
        val project = openProject(repoName, false)
        val program = AutoImporter.importByUsingBestGuess(
            File(binaryName),
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
        program.domainFile.addToVersionControl("Add file $binaryName", false, monitor())

        project.close()
    }

    fun deleteBinaries(repoName: String){
        val project = openProject(repoName, false)
        project.rootFolder.files.forEach {
            it.delete()
        }
    }
}

suspend fun <T> PipelineContext<Unit, ApplicationCall>.taskSSE(task: Task<T>) {
    call.response.cacheControl(CacheControl.NoCache(null))
    coroutineScope {
        launch {
            // TODO this objectmapper may not be the same as the one used by the pipeline. Maybe we should sync them?
            val mapper = ObjectMapper()
            call.respondTextWriter(contentType = ContentType.Text.EventStream) {
                for (event in task.events) {
                    withContext(Dispatchers.IO) {
                        write("data:")
                        write(mapper.writeValueAsString(event))
                        write("\n\n")
                        flush()
                    }
                }
            }
        }
        withContext(Dispatchers.Default){
            task.execute()
        }
    }
}

fun Route.repository(svc: RepositoryService) {
    route("/repository") {
        get {
            call.respond(svc.getAllRepositories())
        }

        post("import") {
            val body = call.request.queryParameters
            val repoName = body["repository"] ?: throw Exception("repository field must not be empty")
            val binName = body["binary"] ?: throw Exception("binary field must not be empty")

            taskSSE(svc.importBinary(repoName, binName))
        }

        post("delete") {
            val body = call.request.queryParameters
            val repoName = body["repository"] ?: throw Exception("repository field must not be empty")
            svc.deleteBinaries(repoName)
            call.respond(HttpStatusCode.OK)
        }

        post("new") {
            val body = call.receive<Map<String, Any>>()
            val repoName = body["repository"] as String
            svc.newRepository(repoName)
            call.respond(HttpStatusCode.OK)
        }
    }
}