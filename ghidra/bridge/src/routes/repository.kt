package routes

import io.ktor.application.call
import io.ktor.request.receive
import io.ktor.request.receiveMultipart
import io.ktor.request.receiveParameters
import io.ktor.response.respond
import io.ktor.routing.Route
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.routing.route
import model.Repository

class RepositoryService : Service() {
    fun getAllRepositories(): List<Repository> {
        return listOf()
    }
}

fun Route.repository(svc: RepositoryService) {
    route("/repository") {
        get {
            call.respond(svc.getAllRepositories())
        }

        post("/new") {
            val body = call.receive<Map<String, Any>>()
            println(body)
        }
    }
}