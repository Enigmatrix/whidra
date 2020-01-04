package session

import com.google.common.cache.CacheBuilder
import ghidra.WhidraClient
import ghidra.framework.client.RepositoryServerAdapter
import io.ktor.application.ApplicationCall
import io.ktor.http.HttpStatusCode
import io.ktor.response.header
import io.ktor.sessions.get
import io.ktor.sessions.sessions
import utils.TaskManager
import utils.UnauthorizedException
import utils.AppException
import java.util.*
import java.util.concurrent.TimeUnit
import javax.security.auth.login.LoginException

data class UserIdentifier(val user: String, val pass: String)

data class ApplicationSession(val server: RepositoryServerAdapter, val taskMgr: TaskManager)

const val SESS_NAME = "SESS_ID"
val cache = CacheBuilder.newBuilder()
    .expireAfterAccess(5, TimeUnit.MINUTES)
    .build<String, ApplicationSession>()

// TODO create custom exception types
fun startAppSession(user: String, pass: String): ApplicationSession {
    val rsa = WhidraClient.login(user, pass) ?: throw LoginException()
    return ApplicationSession(rsa, TaskManager())
}

// TODO frontend needs to make generate its own session id
fun ApplicationCall.appSession(id: String? = null): ApplicationSession {
    val sessid = id ?: request.headers[SESS_NAME]
        ?: throw AppException("No session header found!", HttpStatusCode.BadRequest)
    val user = sessions.get<UserIdentifier>() ?: throw UnauthorizedException()
    return cache.get(sessid) {
        startAppSession(user.user, user.pass)
    }
}

fun genRandomId(): String {
    return UUID.randomUUID().toString()
}