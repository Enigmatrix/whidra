package org.whidra

import io.micronaut.runtime.Micronaut.*
import io.swagger.v3.oas.annotations.*
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType
import io.swagger.v3.oas.annotations.info.*
import io.swagger.v3.oas.annotations.security.SecurityRequirement
import io.swagger.v3.oas.annotations.security.SecurityScheme
import io.swagger.v3.oas.annotations.security.SecuritySchemes
import org.whidra.bridge.*

@OpenAPIDefinition(
    info = Info(
        title = "Whidra Server",
        version = "1.0-SNAPSHOT",
        description = "API Server for the Whidra project"
    )
)
// @SecurityScheme(type = SecuritySchemeType.APIKEY, `in` = SecuritySchemeIn.COOKIE, name = "sessionCookie", paramName = "SESSION")
object Api

fun main(args: Array<String>) {
    Ghidra.init()
    build()
        .args(*args)
        .packages("org.whidra")
        .start()
}