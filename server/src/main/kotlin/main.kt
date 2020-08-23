package org.whidra

import io.ktor.application.*
import io.ktor.features.*
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

fun Application.main() {
    install(CallLogging)
    routing {
        get("/") {
            call.respond("lmao 2  23yes")
        }
    }
}