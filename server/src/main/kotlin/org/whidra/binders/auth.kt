package org.whidra.binders

import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.*
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.reactivestreams.Publisher
import org.whidra.bridge.Client
import java.util.*
import java.util.concurrent.Flow
import javax.inject.Singleton
import javax.security.auth.login.FailedLoginException


@Singleton
class WhidraLoginProvider : AuthenticationProvider {
    override fun authenticate(
        httpRequest: HttpRequest<*>?,
        authenticationRequest: AuthenticationRequest<*, *>?
    ): Publisher<AuthenticationResponse> {
        return Flowable.create({
            val user = authenticationRequest!!.identity as String
            val pass = authenticationRequest.secret as String
            try {
                Client(user, pass).close()
                it.onNext(WhidraUserDetails(user, pass))
                it.onComplete()
            }
            catch (e: FailedLoginException) {
                it.onError(AuthenticationException(AuthenticationFailed()))
            }
        }, BackpressureStrategy.ERROR)
    }
}

class WhidraUserDetails(user: String, val pass: String, roles: Collection<String> = listOf(), attrs: Map<String, Any> = mapOf("password" to pass)) : UserDetails(user, roles, attrs)