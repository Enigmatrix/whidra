package util

import io.ktor.application.ApplicationCall

fun ApplicationCall.field(name: String): String {
    return request.queryParameters[name] ?: throw ParamException(name, ParamType.QUERY)
}

fun ApplicationCall.maybeField(name: String): String? {
    return request.queryParameters[name];
}

private val STRING_CHARACTERS = ('0'..'z').toList().toTypedArray()
fun randomSecret() = (1..16).map { STRING_CHARACTERS.random() }.joinToString("")
