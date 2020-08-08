package org.whidra.controllers

import io.micronaut.http.annotation.*
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.session.Session
import io.micronaut.session.annotation.SessionValue
import io.swagger.v3.oas.annotations.tags.Tag
import org.whidra.binders.client
import org.whidra.model.*
import javax.inject.Inject

@Controller("/api/repository")
@Tag(name = "Repository")
class RepositoryController {

    /**
     * Gets all the available Repositories to this user.
     */
    @Get("/all")
    @Secured(SecurityRule.IS_ANONYMOUS)
    suspend fun getAll(session: Session): List<Repository> {
        val client = session.client().client
        return client.repositoryNames().map {
            val repo = client.repository(it)
            Repository(repo.name, repo.binaryNames().map { bin -> Binary(bin) })
        }
    }

    /**
     * Creates a Repository with [name]
     */
    @Post("/create")
    suspend fun create(session: Session, @Body name: String): Unit {
        val client = session.client().client
    }

    /**
     * Delete a Repository with the [name]
     */
    @Delete
    suspend fun delete(@QueryValue name: String): Unit {

    }
}