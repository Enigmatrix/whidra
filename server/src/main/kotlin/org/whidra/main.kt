package org.whidra

import io.micronaut.runtime.Micronaut.*
import io.swagger.v3.oas.annotations.*
import io.swagger.v3.oas.annotations.info.*


@OpenAPIDefinition(
    info = Info(
        title = "Whidra Server",
        version = "1.0-SNAPSHOT",
        description = "API Server for the Whidra project"
    )
)
object Api

fun main(args: Array<String>) {
    build()
        .args(*args)
        .packages("org.whidra")
        .start()
}