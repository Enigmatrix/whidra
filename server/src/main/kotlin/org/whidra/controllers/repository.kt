package org.whidra.controllers

import io.micronaut.http.annotation.*

@Controller("/api/repository")
class RepositoryController {
    @Get("/all")
    suspend fun getAll(): List<String> {
        return listOf("Whidra", "Cobalt", "Windows")
    }

    @Post("/create")
    fun create() {

    }
}