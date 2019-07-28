import ghidra.GhidraJarApplicationLayout
import ghidra.app.util.importer.AutoImporter
import ghidra.framework.Application
import ghidra.framework.HeadlessGhidraApplicationConfiguration
import ghidra.framework.client.ClientUtil
import ghidra.framework.client.PasswordClientAuthenticator
import ghidra.framework.client.RepositoryServerAdapter
import ghidra.framework.model.ProjectData
import ghidra.framework.protocol.ghidra.GhidraURLConnection
import ghidra.util.task.TaskMonitor
import java.io.File
import java.lang.Exception
import java.net.URL

val host = "localhost"
val port = 13100
val username = "ghidra"

lateinit var server: RepositoryServerAdapter

fun main() {
    init()
    val server = connect()
    server.repositoryNames
}

fun init() {
    if (!Application.isInitialized())
        Application.initializeApplication(
            GhidraJarApplicationLayout(),
            HeadlessGhidraApplicationConfiguration())
}

fun connect(): RepositoryServerAdapter {
    ClientUtil.setClientAuthenticator(PasswordClientAuthenticator(username, "changeme"))
    //TODO reset password
    return ClientUtil.getRepositoryServer(host, port, true)
}

fun repositories(): Array<String> {
    return server.repositoryNames
}

fun users(): Array<String> {
    return server.allUsers
}

fun binaries(repo: String): Iterable<String> {
    val repo = server.getRepository(repo)
    repo.connect()
    val binaries = repo.getItemList("/").map { it.name }
    repo.disconnect()
    return binaries
}

fun newRepository(repoName: String) {
    server.createRepository(repoName)
}

fun importBinary(repoName: String, binary: String) {
    val project = openProject(repoName, true)
    AutoImporter.importByUsingBestGuess(
        File("/uploads/$binary"),
        project.rootFolder,
        project, null, TaskMonitor.DUMMY)
    
}

fun openProject(repoName: String, readOnly: Boolean): ProjectData {
    val repo = GhidraURLConnection(URL("ghidra", host, "/$repoName"))
    repo.isReadOnly = readOnly
    return repo.projectData ?: throw Exception("Project data not found")
}
