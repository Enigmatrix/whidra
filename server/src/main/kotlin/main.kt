import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationConfig
import com.fasterxml.jackson.databind.SerializerProvider
import com.fasterxml.jackson.databind.cfg.SerializerFactoryConfig
import com.fasterxml.jackson.databind.ser.AnyGetterWriter
import com.fasterxml.jackson.databind.ser.BeanPropertyWriter
import com.fasterxml.jackson.databind.ser.BeanSerializerBuilder
import com.fasterxml.jackson.databind.ser.BeanSerializerFactory
import com.fasterxml.jackson.databind.ser.std.JsonValueSerializer
import com.fasterxml.jackson.databind.ser.std.StdSerializer
import ghidra.WhidraClient
import ghidra.app.decompiler.ClangNode
import ghidra.program.model.address.Address
import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.features.CallLogging
import io.ktor.features.ContentNegotiation
import io.ktor.features.StatusPages
import io.ktor.http.cio.websocket.send
import io.ktor.jackson.jackson
import io.ktor.locations.Locations
import io.ktor.response.respond
import io.ktor.routing.route
import io.ktor.routing.routing
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.sessions.Sessions
import io.ktor.sessions.cookie
import io.ktor.sessions.directorySessionStorage
import io.ktor.websocket.WebSockets
import io.ktor.websocket.webSocket
import it.lamba.ktor.features.SinglePageApplication
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import models.WsOut
import org.slf4j.event.Level
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
        jackson {
            serializer = this
        }
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

    install(SinglePageApplication){
        folderPath = "/srv/"
        useFiles = true
    }

    install(Sessions) {
        cookie<UserIdentifier>("SESS_USER_ID",
            directorySessionStorage(File("/var/sessions"), cached=true))
    }

    routing {
        route("/api") {
            users()
            projects()
            binaries()

            webSocket("event-stream/{id}") {
                try {
                    val (_, taskMgr) = call.appSession(call.parameters["id"])

                    for(task in taskMgr.tasks) {
                        for(event in task.events){
                            send(serializer.writeValueAsString(WsOut.TaskProgress(task.id, event)))
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
