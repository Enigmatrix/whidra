package org.whidra

import com.papsign.ktor.openapigen.OpenAPIGen
import com.papsign.ktor.openapigen.annotations.*
import com.papsign.ktor.openapigen.route.path.normal.get
import com.papsign.ktor.openapigen.route.response.respond
import com.papsign.ktor.openapigen.route.*
import com.papsign.ktor.openapigen.openAPIGen
import io.ktor.application.*
import io.ktor.features.*
import io.ktor.jackson.*
import io.ktor.response.*
import io.ktor.routing.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*

fun main() {
    embeddedServer(Netty,
        port = 8080,
        watchPaths = listOf("server"),
        module = Application::main)
    .start(wait = true)
}

@Response("A String Response")
data class StringResponse(val str: String)

fun Application.main() {
    install(CallLogging)
    install(OpenAPIGen) {
        info {
            version = "1.0.0"
            title = "Whidra API"
            description = "API Server for the Whidra project. Note the AUTHENTICATION and SESSION cookies/headers"
            contact {
                name = "Enigmatrix"
                email = "enigmatrix2000@gmail.com"
            }
        }
    }
    install(ContentNegotiation) {
        jackson()
    }
    routing {
        route("doc") {
            get("openapi.json") {
                call.respond(application.openAPIGen.api.serialize())
            }
            get("ui") {
                call.respondRedirect("/swagger-ui/index.html?url=/doc/openapi.json", true)
            }
        }
    }
    apiRouting {

        route("path").get<Unit, StringResponse>(
            info(summary = "summary?", description = "desc")) {
            respond(StringResponse("what"))
        }

    }
}