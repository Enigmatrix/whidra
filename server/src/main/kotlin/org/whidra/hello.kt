package org.whidra

import io.micronaut.http.annotation.*

@Controller("/")
class HelloController {
    @Get("/")
    fun hello(): String {
        return "hellooooo"
    }
}