package routes

import io.ktor.application.call
import io.ktor.http.HttpStatusCode
import io.ktor.request.receive
import io.ktor.request.receiveMultipart
import io.ktor.request.receiveParameters
import io.ktor.response.respond
import io.ktor.routing.Route
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.routing.route
import kotlinx.coroutines.channels.Channel
import model.Binary
import model.Repository
import util.RepositoryUtil

class RepositoryService : Service() {
    fun getAllRepositories(): List<Repository> {
        return RepositoryUtil.repositories().map { name ->
            Repository(name, RepositoryUtil.binaries(name).map { Binary(it) })
        }
    }

    fun newRepository(repoName: String) {
        RepositoryUtil.newRepository(repoName)
    }
}

sealed class Progress(val kind: String) {
    object Indeterminate : Progress("indeterminate")
    class Value(val current: Long, val max: Long) : Progress("value")
    class Message(val msg: String) : Progress("message")
}

/*class Task<T> {
    val progress = Channel<Progress>()
}*/

fun Route.repository(svc: RepositoryService) {
    route("/repository") {
        get {
            call.respond(svc.getAllRepositories())
        }

        get("wut") {
            call.respond(Progress.Indeterminate)
        }

        post("new") {
            val body = call.receive<Map<String, Any>>()
            val repoName = body["repository"] as String
            svc.newRepository(repoName)
            call.respond(HttpStatusCode.OK)
        }
    }
}