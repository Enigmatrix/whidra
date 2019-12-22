package routes

import ghidra.framework.client.RepositoryAdapter
import io.ktor.application.call
import io.ktor.http.HttpStatusCode
import io.ktor.locations.*
import io.ktor.response.respond
import io.ktor.routing.Route
import models.Binary
import session.whidraSession

@Location("/projects")
class Project {
    @Location("/create")
    class Create(val name: String)

    @Location("/delete")
    class Delete(val name: String)

    @Location("/all")
    class All
}

// TODO get rid of these stupid wartings proejct-wide
fun Route.projects() {
    post<Project.Create> {
        val server = call.whidraSession().server

        val project = server.createRepository(it.name)
        call.respond(projectFrom(project))
    }

    delete<Project.Delete> {
        val server = call.whidraSession().server

        server.deleteRepository(it.name)
        call.respond(HttpStatusCode.OK)
    }

    get<Project.All> {
        val server = call.whidraSession().server

        call.respond(server.repositoryNames.map {
            projectFrom(server.getRepository(it))
        })
    }
}

fun projectFrom(repo: RepositoryAdapter): models.Project {
    repo.connect()
    val proj = models.Project(repo.name,
        binaries = repo.getItemList("/").map { Binary(it.name) })
    repo.disconnect()
    return proj
}


