package routes

import io.ktor.application.call
import io.ktor.http.HttpStatusCode
import io.ktor.response.respond
import io.ktor.routing.Route
import io.ktor.routing.post
import io.ktor.routing.route
import io.ktor.sessions.clear
import io.ktor.sessions.get
import io.ktor.sessions.sessions
import io.ktor.sessions.set
import model.User
import util.field
import util.randomSecret

class UserService : Service() {
    fun login(user: String, pass: String): Boolean {
        return true
    }

    fun register(user: String, pass: String): Boolean {
        return true
    }
}

fun Route.routesFor(svc: UserService) {
    route("user") {
        post("login") {
            if(call.sessions.get<model.Session>() != null) {
                throw Exception("Preexisting session found")
            }
            val form = call.receiveForm()
            val user = form.field("user")
            val pass = form.field("pass")
            if(svc.login(user, pass)) {
                call.sessions.set(model.Session(randomSecret()))
                call.respond(HttpStatusCode.OK)
            }
            else {
                throw Exception("Invalid credentials")
            }
        }
        post("register"){

        }
        post("logoff") {
            if(call.sessions.get<model.Session>() == null) {
                throw Exception("No preexisting session")
            }
            call.sessions.clear<model.Session>()
        }
    }
}
