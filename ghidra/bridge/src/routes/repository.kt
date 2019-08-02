package routes

import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.AutoImporter
import ghidra.app.util.importer.MessageLog
import ghidra.framework.model.ProjectData
import ghidra.framework.protocol.ghidra.GhidraURLConnection
import ghidra.program.model.listing.Program
import ghidra.program.util.GhidraProgramUtilities
import io.ktor.application.call
import io.ktor.http.HttpStatusCode
import io.ktor.request.receive
import io.ktor.request.receiveMultipart
import io.ktor.request.receiveParameters
import io.ktor.response.respond
import io.ktor.routing.Route
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.routing.route
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

        return@task
    }

    suspend fun <T> cpu(block: suspend CoroutineScope.() -> T): T {
        return withContext(Dispatchers.Default, block)
    }

    fun deleteBinaries(repoName: String){
        val project = openProject(repoName, false)
        project.rootFolder.files.forEach {
            it.delete()
        }
    }


    fun openProject(repoName: String, readOnly: Boolean): ProjectData {
        val repo = GhidraURLConnection(URL("ghidra", "localhost", "/$repoName"))
        repo.isReadOnly = readOnly
        return repo.projectData ?: throw Exception("Project data not found")
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

            val task = svc.importBinary(repoName, binName)
            launch {
                for (event in task.events) {
                    when (event) {
                        is Event.Indeterminate -> println("Task Indeterminate")
                        is Event.Message -> println("Task Message: ${event.msg}")
                        is Event.Progress -> println("Task Progress: ${event.current}/${event.max} (${100.0*event.current/event.max})")
                        is Event.Completed<*> -> println("Task Completed: ${event.value}")
                    }
                }
            }
            withContext(Dispatchers.Default){
                task.execute()
            }
            call.respond(HttpStatusCode.OK)
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