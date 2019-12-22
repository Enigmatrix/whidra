import com.fasterxml.jackson.databind.ObjectMapper
import io.ktor.application.Application
import io.ktor.application.install
import io.ktor.features.CallLogging
import io.ktor.features.ContentNegotiation
import io.ktor.jackson.jackson
import io.ktor.routing.route
import io.ktor.routing.routing
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import org.slf4j.event.Level
import ghidra.WhidraClient
import io.ktor.http.cio.websocket.CloseReason
import io.ktor.http.cio.websocket.send
import io.ktor.locations.Locations

import io.ktor.sessions.*
import io.ktor.util.InternalAPI
import io.ktor.util.KtorExperimentalAPI
import io.ktor.websocket.WebSockets
import io.ktor.websocket.webSocket
import javafx.application.Application.launch
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import kotlinx.coroutines.channels.mapNotNull
import models.WsOut
import routes.binaries
import routes.projects
import routes.users
import session.WhidraUser
import session.whidraSession
import java.io.File

lateinit var serializer: ObjectMapper

@InternalAPI
@KtorExperimentalAPI
fun main() {
    WhidraClient.init()
    embeddedServer(Netty, 8080, "0.0.0.0",
        module = Application::module)
        .start(wait = true)
}


@InternalAPI
@KtorExperimentalAPI
fun Application.module() {
    install(ContentNegotiation) {
        jackson { serializer = this }
    }

    install(CallLogging) {
        level = Level.INFO
    }

    install(Locations)

    install(WebSockets)

    install(Sessions) {
        cookie<WhidraUser>("SESS_USER_ID",
            directorySessionStorage(File("/var/sessions"), cached=true))
    }

    routing {
        route("/api") {
            users()
            projects()
            binaries()

            webSocket("event-stream") {

                try {
                    val (_, taskMgr) = call.whidraSession()

                    for(task in taskMgr.tasks) {
                        for(event in task.events){
                            send(serializer.writeValueAsString(WsOut.Progress(task.id, event)))
                        }
                    }
                }
                catch (e: ClosedReceiveChannelException) {
                    // TODO maybe destroy cached session here?
                }
                catch (e: Throwable) {
                    println("exception thrown:")
                    throw e
                }
            }
        }
    }
}
