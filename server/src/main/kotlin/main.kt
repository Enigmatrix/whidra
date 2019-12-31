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
import io.ktor.application.call
import io.ktor.features.StatusPages
import io.ktor.http.cio.websocket.Frame
import io.ktor.http.cio.websocket.send
import io.ktor.locations.Locations
import io.ktor.response.respond

import io.ktor.sessions.*
import io.ktor.websocket.WebSockets
import io.ktor.websocket.webSocket
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import models.WsOut
import routes.binaries
import routes.projects
import routes.users
import session.UserIdentifier
import session.appSession
import utils.AppException
import java.io.File

lateinit var serializer: ObjectMapper

fun main() {
    WhidraClient.init()
    embeddedServer(Netty, 8080, "0.0.0.0",
        module = Application::module)
        .start(wait = true)
}


fun Application.module() {
    install(ContentNegotiation) {
        jackson { serializer = this }
    }

    install(CallLogging) {
        level = Level.INFO
    }

    install(StatusPages) {
        exception<AppException> { ex ->
            call.respond(ex.code, ex.message.orEmpty())
        }
    }

    install(Locations)

    install(WebSockets)

    install(Sessions) {
        cookie<UserIdentifier>("SESS_USER_ID",
            directorySessionStorage(File("/var/sessions"), cached=true))
    }

    routing {
        route("/api") {
            users()
            projects()
            binaries()

            webSocket("event-stream") {
                try {
                    val (_, taskMgr) = call.appSession()

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
