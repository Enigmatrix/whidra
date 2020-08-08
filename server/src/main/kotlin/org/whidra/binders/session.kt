package org.whidra.binders

import io.micronaut.context.annotation.Primary
import io.micronaut.context.annotation.Replaces
import io.micronaut.context.event.ApplicationEventPublisher
import io.micronaut.http.HttpAttributes
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.AuthenticationUserDetailsAdapter
import io.micronaut.session.*
import org.whidra.bridge.Binary
import org.whidra.bridge.Client
import org.whidra.bridge.Repository
import java.security.Principal
import javax.inject.Singleton

/*@Singleton
@Primary
@Replaces(InMemorySessionStore::class)
class WhidraSessionStore(sessIdGen: SessionIdGenerator, sessConf: SessionConfiguration, evPub: ApplicationEventPublisher):
    InMemorySessionStore(sessIdGen, sessConf, evPub), SessionStore<InMemorySession> {
    override fun newSession(): InMemorySession {
        val sess =  super.newSession()
        val user = TODO("get from authentication providers")
        val pass = TODO()
        sess.put("client", SessionClient(Client(user, pass)))
        return sess
    }
}*/

fun Session.client(): SessionClient {
    val principal = get(HttpAttributes.PRINCIPAL.toString(), AuthenticationUserDetailsAdapter::class.java).get()
    val username = principal.attributes["username"] as String
    val password = principal.attributes["password"] as String
    put("client", SessionClient(Client(username, password)))
    return get("client", SessionClient::class.java).get()
}

fun Session.repository(name: String): SessionRepository {
    val cli = client()
    val res = cli.repositories.find { it.repository.name == name }
    if (res != null) return res
    val repo = SessionRepository(cli.client.repository(name))
    cli.repositories.plus(repo)
    return repo
}

fun Session.binary(bin: BinaryParam): SessionBinary {
    val repo = repository(bin.repository)
    val bin = repo.binaries.find { it.binary.program.name == bin.binary }
    if (bin != null) return bin

    TODO("find binary here, either with edit perms or no")
}

class SessionClient(val client: Client) {
    val repositories: List<SessionRepository> = listOf()
}

class SessionRepository(val repository: Repository) {
    val binaries: List<SessionBinary> = listOf()
}

class SessionBinary(val binary: Binary)
