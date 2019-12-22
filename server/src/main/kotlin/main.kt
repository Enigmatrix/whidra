import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.features.CallLogging
import io.ktor.features.ContentNegotiation
import io.ktor.jackson.jackson
import io.ktor.response.respond
import io.ktor.routing.get
import io.ktor.routing.route
import io.ktor.routing.routing
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import org.slf4j.event.Level
import ghidra.WhidraClient
import io.ktor.http.HttpStatusCode
import io.ktor.request.receiveMultipart
import io.ktor.request.receiveParameters

import io.ktor.response.header
import io.ktor.routing.post
import io.ktor.sessions.*
import io.ktor.util.InternalAPI
import io.ktor.util.KtorExperimentalAPI
import session.WhidraSession
import session.WhidraUser
import session.genSessionId
import session.whidraSession
import utils.WhidraException
import java.io.File

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
        jackson { }
    }

    install(CallLogging) {
        level = Level.INFO
    }

    install(Sessions) {
        cookie<WhidraUser>("SESS_USER_ID",
            directorySessionStorage(File("/var/sessions"), cached=true))
    }

    routing {
        route("api") {
            get("hello") {
                call.respond("hello")
            }

            get("users") {
                val sess = call.whidraSession()
                call.respond(sess.server.allUsers)
            }

            post("login") {
                if (call.sessions.get<WhidraUser>() != null) {
                    throw WhidraException("Pre-existing session found")
                }

                val user = call.request.queryParameters["user"]
                val pass = call.request.queryParameters["pass"]
                if (user == null || pass == null) {
                    throw WhidraException("Missing params")
                }

                val rsa = WhidraClient.login(user, pass)
                if (rsa == null) {
                    call.respond(HttpStatusCode.Unauthorized)
                }
                else {
                    call.sessions.set(WhidraUser(user, pass))
                    call.respond(HttpStatusCode.OK)
                }
            }
        }
    }
}