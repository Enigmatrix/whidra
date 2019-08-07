package util

import io.ktor.application.ApplicationCall

fun ApplicationCall.field(name: String): String {
    return request.queryParameters[name] ?: throw ParamException(name, ParamType.QUERY)
}
