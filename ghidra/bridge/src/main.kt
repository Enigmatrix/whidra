import ghidra.GhidraJarApplicationLayout
import ghidra.framework.Application as GhidraApplication
import ghidra.framework.HeadlessGhidraApplicationConfiguration
import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.features.ContentNegotiation
import io.ktor.http.ContentType
import io.ktor.jackson.jackson
import io.ktor.response.respond
import io.ktor.response.respondText
import io.ktor.routing.Route
import io.ktor.routing.get
import io.ktor.routing.route
import io.ktor.routing.routing
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import model.Binary
import model.Repository
import routes.BinaryService
import routes.RepositoryService
import routes.binary
import routes.repository
import util.RepositoryUtil.binaries
import util.RepositoryUtil.initServer


fun main() {
    val server = embeddedServer(Netty, 8080, module = Application::module)
    server.start(wait = true)
}

fun Application.module() {
    install(ContentNegotiation) {
        jackson { }
    }

    val binSvc = BinaryService()
    val repoSvc = RepositoryService()

    routing {
        route("api") {
            get {
                call.respond(Repository("gctf-2019", listOf(Binary("mimikatz"), Binary("nonullsawal"))))
            }

            binary(binSvc)
            repository(repoSvc)
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


