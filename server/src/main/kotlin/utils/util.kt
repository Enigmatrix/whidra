package utils

import io.ktor.routing.Route
import io.ktor.routing.get

/*data class Login(val username: String, val password: String) {
    fun Route.login() {
        get<Login> {

        }
    }
}*/

class WhidraException(msg: String) : Exception(msg) {

}
