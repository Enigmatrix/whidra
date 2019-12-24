package routes

import ghidra.WhidraClient
import io.ktor.application.call
import io.ktor.http.HttpStatusCode
import io.ktor.locations.*
import io.ktor.response.respond
import io.ktor.routing.Route
import io.ktor.sessions.clear
import io.ktor.sessions.get
import io.ktor.sessions.sessions
import io.ktor.sessions.set
import session.WhidraUser
import utils.WhidraException
import javax.security.auth.login.FailedLoginException

@Location("/users")
class Users {
    @Location("/login")
    data class Login(val username: String, val password: String)

    @Location("/logout")
    class Logout()
}

fun Route.users() {
    post<Users.Login>() {
        if (call.sessions.get<WhidraUser>() != null) {
            throw WhidraException("Pre-existing session found")
        }

        val rsa = try {
            WhidraClient.login(it.username, it.password)
        } catch (e: FailedLoginException) {
            null
        }
        if (rsa == null) {
            call.respond(HttpStatusCode.Unauthorized)
        } else {
            call.sessions.set(WhidraUser(it.username, it.password))
            call.respond(HttpStatusCode.OK)
        }
    }

    post<Users.Logout>() {
        if (call.sessions.get<WhidraUser>() == null) {
            throw WhidraException("No pre-existing session found")
        }
        call.sessions.clear<WhidraUser>()
    }
}
