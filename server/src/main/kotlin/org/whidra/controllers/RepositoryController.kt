package org.whidra.controllers

import io.micronaut.http.annotation.*
import io.swagger.v3.oas.annotations.tags.Tag
import org.whidra.model.*

@Controller("/api/repository")
@Tag(name = "Repository")
class RepositoryController {

    /**
     * Gets all the available Repositories to this user.
     */
    @Get("/all")
    suspend fun getAll(): List<Repository> {
        return listOf(
            Repository("Cobalt", listOf(Binary("msvcrt.dll"), Binary("kernel32.dll"))),
            Repository("winapi", listOf(Binary("winuser.dll"))))
    }

    /**
     * Creates a Repository with [name]
     */
    @Post("/create")
    suspend fun create(@Body name: String): Unit {

    }

    /**
     * Delete a Repository with the [name]
     */
    @Delete
    suspend fun delete(@QueryValue name: String): Unit {

    }
}