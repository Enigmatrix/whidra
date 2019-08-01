package routes

import io.ktor.application.call
import io.ktor.request.queryString
import io.ktor.routing.Route
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.routing.route

class BinaryService : Service() {

}

fun Route.binary(svc: BinaryService) {
    route("binary") {
        post("new"){

        }

        get("functions") {
            val project = call.request.queryParameters["project"]
            val binary = call.request.queryParameters["binary"]

        }

        get("code") {

        }

        get("asm") {

        }
    }
}
