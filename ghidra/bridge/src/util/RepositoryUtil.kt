package util

import ghidra.framework.client.ClientUtil
import ghidra.framework.client.PasswordClientAuthenticator
import ghidra.framework.client.RepositoryAdapter
import ghidra.framework.client.RepositoryServerAdapter
import ghidra.framework.model.ProjectData
import ghidra.framework.protocol.ghidra.GhidraURLConnection
import ghidra.server.Repository
import java.net.URL

object RepositoryUtil {
    private lateinit var server: RepositoryServerAdapter
    private const val host = "localhost"
    private const val port = 13100
    private const val password = "changeme"

    fun initServer() {
        // no need to put username since it just defaults to computer username
        ClientUtil.setClientAuthenticator(PasswordClientAuthenticator("", password))
        //TODO reset password
        server = ClientUtil.getRepositoryServer(host, port, true)
    }

    fun projectData(repoName: String, readOnly: Boolean): ProjectData {
        val repo = GhidraURLConnection(URL("ghidra", host, "/$repoName"))
        repo.isReadOnly = readOnly
        return repo.projectData ?: throw Exception("Project data not found")
    }

    fun repository(repoName: String): RepositoryAdapter {
        return server.getRepository(repoName)
    }

    fun newRepository(repoName: String) {
        server.createRepository(repoName)
    }

    fun binaries(repoName: String): Iterable<String> {
        val repo = server.getRepository(repoName)
        repo.connect()
        val binaries = repo.getItemList("/").map { it.name }
        repo.disconnect()
        return binaries
    }

    fun users(): Array<String> {
        return server.allUsers
    }

    fun repositories(): Array<String> {
        return server.repositoryNames
    }
}