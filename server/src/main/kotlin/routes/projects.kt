package routes

import ghidra.framework.client.RepositoryAdapter
import io.ktor.application.call
import io.ktor.http.HttpStatusCode
import io.ktor.locations.*
import io.ktor.response.respond
import io.ktor.routing.Route
import models.Binary
import session.whidraSession

@Location("/projects/{name}")
data class Project(val name: String) {
    @Location("/create")
    data class Create(val project: Project)

    @Location("/delete")
    data class Delete(val project: Project)
}

@Location("/projects/all")
class AllProjects

// TODO get rid of these stupid wartings proejct-wide
fun Route.projects() {
    post<Project.Create> {
        val (server) = call.whidraSession()

        val project = server.createRepository(it.project.name)
        call.respond(projectFrom(project))
    }

    delete<Project.Delete> {
        val (server) = call.whidraSession()

        server.deleteRepository(it.project.name)
        call.respond(HttpStatusCode.OK)
    }

    get<AllProjects> {
        val (server) = call.whidraSession()

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


