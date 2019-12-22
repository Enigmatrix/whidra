package session

import com.google.common.cache.CacheBuilder
import ghidra.WhidraClient
import ghidra.framework.client.RepositoryServerAdapter
import io.ktor.application.ApplicationCall
import io.ktor.request.header
import io.ktor.response.header
import io.ktor.response.respondRedirect
import io.ktor.sessions.get
import io.ktor.sessions.sessions
import utils.TaskManager
import java.lang.Exception
import java.util.*
import java.util.concurrent.TimeUnit
import javax.security.auth.login.LoginException

data class WhidraUser(val user: String, val pass: String)

data class WhidraSession(val server: RepositoryServerAdapter, val taskMgr: TaskManager)

const val SESS_NAME = "SESS_ID"
val cache = CacheBuilder.newBuilder()
    .expireAfterAccess(5, TimeUnit.MINUTES)
    .build<String, WhidraSession>()

// TODO create custom exception types
fun createWhidraSession(user: String, pass: String): WhidraSession {
    val rsa = WhidraClient.login(user, pass) ?: throw LoginException()
    return WhidraSession(rsa, TaskManager())
}

// TODO frontend needs to make generate its own session id
fun ApplicationCall.whidraSession(): WhidraSession {
    val sessid = request.headers[SESS_NAME] ?: throw Exception("No session header found!")
    val user = sessions.get<WhidraUser>() ?: throw Exception("Not logged in!")
    response.header(SESS_NAME, sessid)
    return cache.get(sessid) {
        createWhidraSession(user.user, user.pass)
    }
}

fun genRandomId(): String {
    return UUID.randomUUID().toString()
}