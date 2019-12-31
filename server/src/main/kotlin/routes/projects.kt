package routes

import ghidra.framework.client.RepositoryAdapter
import io.ktor.application.call
import io.ktor.http.HttpStatusCode
import io.ktor.locations.*
import io.ktor.response.respond
import io.ktor.routing.Route
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import models.Binary
import session.appSession

@Location("/projects/{name}")
data class Project(val name: String) {
    @Location("/create")
    data class Create(val project: Project)

    @Location("/delete")
    data class Delete(val project: Project)
}

@Location("/projects/all")
class AllProjects

fun Route.projects() {
    post<Project.Create> {
        val (server) = call.appSession()

        val project = withContext(Dispatchers.IO) {
            server.createRepository(it.project.name)
        }
        call.respond(projectFrom(project))
    }

    delete<Project.Delete> {
        val (server) = call.appSession()

        withContext(Dispatchers.IO) {
            server.deleteRepository(it.project.name)
        }
        call.respond(HttpStatusCode.OK)
    }

    get<AllProjects> {
        val (server) = call.appSession()

        call.respond(server.repositoryNames.map {
            projectFrom(server.getRepository(it))
        })
    }
}

fun projectFrom(repo: RepositoryAdapter): models.Project {
    repo.connect()
    val project = models.Project(repo.name,
        binaries = repo.getItemList("/").map { Binary(it.name) })
    repo.disconnect()
    return project
}


