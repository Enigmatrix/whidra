package main

import ghidra.GhidraJarApplicationLayout
import ghidra.framework.HeadlessGhidraApplicationConfiguration
import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.features.CallLogging
import io.ktor.features.ContentNegotiation
import io.ktor.jackson.jackson
import io.ktor.request.path
import io.ktor.response.respond
import io.ktor.routing.get
import io.ktor.routing.route
import io.ktor.routing.routing
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import model.Binary
import model.Repository
import org.slf4j.event.Level
import routes.BinaryService
import routes.RepositoryService
import routes.routesFor
import util.RepositoryUtil.initServer
import ghidra.framework.Application as GhidraApplication


fun main() {
    init()
    embeddedServer(Netty, 8000,
        module = Application::module)
        .start(wait = true)
}

fun Application.module() {
    install(ContentNegotiation) {
        //Jackson allows you to handle JSON content easily
        jackson { }
    }

    install(CallLogging) {
        level = Level.INFO
        filter { call -> call.request.path().startsWith("/api") }
    }

    val binSvc = BinaryService()
    val repoSvc = RepositoryService()

    routing {
        route("api") {
            routesFor(binSvc)
            routesFor(repoSvc)
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


