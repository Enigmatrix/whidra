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
import session.UserIdentifier
import utils.IncorrectLoginException
import utils.LoggedInException
import utils.UnauthorizedException
import javax.security.auth.login.FailedLoginException

@Location("/users")
class Users {
    @Location("/login")
    data class Login(val username: String, val password: String)

    @Location("/info")
    class Info

    @Location("/logout")
    class Logout
}

fun Route.users() {

    get<Users.Info> {
        val sess = call.sessions.get<UserIdentifier>()
            ?: throw UnauthorizedException()
        
        call.respond(models.User(sess.user))
    }

    post<Users.Login> {
        if (call.sessions.get<UserIdentifier>() != null) {
            throw LoggedInException()
        }

        try {
            WhidraClient.login(it.username, it.password)
        } catch (e: FailedLoginException) {
            throw IncorrectLoginException()
        }

        call.sessions.set(UserIdentifier(it.username, it.password))
        call.respond(HttpStatusCode.OK)
    }

    post<Users.Logout> {
        call.sessions.get<UserIdentifier>() ?: throw UnauthorizedException()
        call.sessions.clear<UserIdentifier>()
    }
}
