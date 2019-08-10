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
import io.ktor.jackson.jackson
import io.ktor.request.path
import io.ktor.response.cacheControl
import io.ktor.response.respond
import io.ktor.response.respondTextWriter
import io.ktor.routing.get
import io.ktor.routing.route
import io.ktor.routing.routing
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.sessions.*
import io.ktor.websocket.WebSockets
import io.ktor.websocket.webSocket
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
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
import java.util.concurrent.ConcurrentHashMap
import ghidra.framework.Application as GhidraApplication

lateinit var serializer: ObjectMapper
var tasks = ConcurrentHashMap<String, Channel<Task<*>>>()

fun main() {
    init()
    embeddedServer(Netty, 8000,
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
        exception<Exception> { cause -> call.respond(HttpStatusCode.BadRequest, cause.localizedMessage) }
    }

    install(Sessions) {
        cookie<model.Session>("SESSION", directorySessionStorage(File("/var/sessions"), cached = true))
    }

    install(WebSockets)

    val binSvc = BinaryService()
    val repoSvc = RepositoryService()
    val userSvc = UserService()

    routing {
        route("api") {
            routesFor(binSvc)
            routesFor(repoSvc)
            routesFor(userSvc)
            get("/events"){
                val session = call.sessions.get<model.Session>() ?: throw Exception("Session not found")
                call.response.cacheControl(CacheControl.NoCache(null))

                val userTasks = tasks[session.id] ?: throw Exception("Event channel not found for session")
                call.respondTextWriter(contentType = ContentType.Text.EventStream) {
                    val wr = this
                    for (task in userTasks) {
                        launch {
                            for (event in task.events) {
                                withContext(Dispatchers.IO) {
                                    wr.write("data:")
                                    wr.write(serializer.writeValueAsString(event))
                                    wr.write("\n\n")
                                    wr.flush()
                                }
                            }
                        }
                    }
                }
            }
            webSocket("/ws") {
                send("yo wassup")
                val session = call.sessions.get<model.Session>()
                if(session == null) {
                    close(CloseReason(CloseReason.Codes.VIOLATED_POLICY, "session not found"))
                    return@webSocket
                }

                launch {
                    for (frame in incoming.mapNotNull { it as? Frame.Text }) {
                        when(val msg = serializer.readValue<WsIncomingMessage>(frame.readBytes())){
                            is WsIncomingMessage.Cancel -> println("cancelling ${msg.taskId}")
                        }
                    }
                }

                launch {
                    val userTasks = tasks[session.id] ?: throw Exception("Event channel not found for session")
                    for(task in userTasks) {
                        for(event in task.events){
                            send(serializer.writeValueAsString(WsOutgoingMessage.Progress(task.id, event)))
                        }
                    }
                }
            }
        }
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


