package org.whidra.binders

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import io.micronaut.context.annotation.Value
import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.*
import io.micronaut.security.token.jwt.encryption.rsa.RSAEncryptionConfiguration
import io.micronaut.security.token.jwt.encryption.secret.SecretEncryptionConfiguration
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.python.bouncycastle.jcajce.provider.asymmetric.rsa.KeyPairGeneratorSpi
import org.python.bouncycastle.jce.provider.BouncyCastleProvider
import org.python.bouncycastle.jce.provider.PEMUtil
import org.python.bouncycastle.openssl.PEMKeyPair
import org.python.bouncycastle.openssl.PEMParser
import org.python.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.reactivestreams.Publisher
import org.whidra.bridge.Client
import java.io.File
import java.nio.file.Files
import java.nio.file.Paths
import java.security.KeyPair
import java.security.Security
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*
import java.util.concurrent.Flow
import javax.inject.Named
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