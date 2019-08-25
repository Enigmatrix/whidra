package main

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import ghidra.GhidraJarApplicationLayout
import ghidra.framework.HeadlessGhidraApplicationConfiguration
import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.features.CallLogging
import io.ktor.features.ContentNegotiation
import io.ktor.features.StatusPages
import io.ktor.http.CacheControl
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.cio.websocket.*
import io.ktor.http.content.default
import io.ktor.http.content.files
import io.ktor.http.content.static
import io.ktor.http.content.staticRootFolder
import io.ktor.jackson.jackson
import io.ktor.request.path
import io.ktor.response.cacheControl
import io.ktor.response.respond
import io.ktor.response.respondTextWriter
import io.ktor.routing.get
import io.ktor.routing.route import io.ktor.routing.routing
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.sessions.*
import io.ktor.websocket.WebSockets
import io.ktor.websocket.webSocket
import it.lamba.ktor.features.SinglePageApplication
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import kotlinx.coroutines.channels.mapNotNull
import kotlinx.coroutines.flow.flowViaChannel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import model.Event
import model.WsIncomingMessage
import model.WsOutgoingMessage
import org.slf4j.event.Level
import routes.*
import util.RepositoryUtil.initServer
import java.io.File
import java.io.PrintWriter
import java.util.concurrent.ConcurrentHashMap
import ghidra.framework.Application as GhidraApplication

lateinit var serializer: ObjectMapper
var tasks = ConcurrentHashMap<String, Channel<Task<*>>>()

fun main() {
    init()
    embeddedServer(Netty, 8000, watchPaths = listOf("bridge", "/opt/ghidra/bridge", "ghidra", "src"),
        module = Application::module)
        .start(wait = true)
}

fun Application.module() {
    install(ContentNegotiation) {
        //Jackson allows you to handle JSON content easily
        jackson {
            serializer = this
        }
    }

    install(CallLogging) {
        level = Level.INFO
        filter { call -> call.request.path().startsWith("/api") }
    }

    install(StatusPages) {
        exception<NullPointerException> { cause -> call.respondTextWriter(status = HttpStatusCode.Conflict) {
            val writer = PrintWriter(this)
            cause.printStackTrace(writer)
        }}
        exception<Exception> { cause -> call.respond(HttpStatusCode.BadRequest,
            cause.message ?: cause.localizedMessage ?: cause.toString()) }
    }

    install(Sessions) {
        cookie<model.Session>("SESSION", directorySessionStorage(File("/var/sessions"), cached = true))
    }

    install(WebSockets) {

    }

    if(System.getenv("DEV") == null) {
        install(SinglePageApplication) {
            useFiles = true
            folderPath = "frontend"
            defaultPage = "index.html"
        }
    }


    val binSvc = BinaryService()
    val repoSvc = RepositoryService()
    val userSvc = UserService()

    routing {
        route("api") {

            routesFor(binSvc)
            routesFor(repoSvc)
            routesFor(userSvc)

            webSocket("event-stream") {

                try {
                    val session = call.sessions.get<model.Session>()
                    if(session == null) {
                        println("session is null?!")
                        close(CloseReason(CloseReason.Codes.NORMAL, "session not found"))
                        return@webSocket
                    }

                    launch {
                        for (frame in incoming.mapNotNull { it as? Frame.Text }) {
                            when(val msg = serializer.readValue<WsIncomingMessage>(frame.readBytes())){
                                is WsIncomingMessage.Cancel -> println("cancelling ${msg.taskId}")
                            }
                        }
                    }

                    val userTasks = tasks.getOrPut(session.id, { Channel() })
                    for(task in userTasks) {
                        for(event in task.events){
                            send(serializer.writeValueAsString(WsOutgoingMessage.Progress(task.id, event)))
                        }
                    }
                }
                catch (e: ClosedReceiveChannelException) {
                    println("websocket closed :)")
                }
                catch (e: Throwable) {
                    println("exception thrown:")
                    throw e
                }
            }

        }
        /*static {
            staticRootFolder = File("./frontend")

            files(".")
            default("index.html")
        }*/
    }
}

fun init() {
    if (!GhidraApplication.isInitialized())
        GhidraApplication.initializeApplication(
            GhidraJarApplicationLayout(),
            HeadlessGhidraApplicationConfiguration()
        )

    initServer()
}

/*
    /*val run3 = measureTimeMillis {
        val repo = GhidraURLConnection(URL("ghidra", host, "/" + server.repositoryNames[0]))
        repo.isReadOnly = false

        val file = repo.projectData.rootFolder.files[0] as GhidraFile

        var program = file.getDomainObject(2, true, false, TaskMonitor.DUMMY) as ProgramDB
        println(program.name)
        program = edit(file, "Rename") { prog ->
            val main = prog.listing.getFunctions(true)
            .first { it.name == "FUN_00101069" }
            main.setName("main", SourceType.USER_DEFINED)
        }
    }

    println("rename took: ${run3/1000.0}")
*/

}

//TODO change this to an extension method of domainfile?
fun edit(file: DomainFile, msg: String, block: (ProgramDB) -> Unit): ProgramDB  {
    //TODO check return code
    file.checkout(false, TaskMonitor.DUMMY)
    val program = file.getDomainObject(2, true, false, TaskMonitor.DUMMY) as ProgramDB
    val tx = program.startTransaction(msg)
    //TODO try catch
    block(program)
    //TODO wtf is this boolean?
    program.endTransaction(tx, true)
    file.save(TaskMonitor.DUMMY)
    file.checkin(CheckinWithComment(msg), true, TaskMonitor.DUMMY)
    return program
}

class CheckinWithComment(val cmt: String): CheckinHandler {
    override fun getComment() = cmt
    override fun createKeepFile() = false
    override fun keepCheckedOut() = false

}
*/
