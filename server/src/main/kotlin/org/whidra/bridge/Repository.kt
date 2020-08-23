package org.whidra.bridge

import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.bin.ByteProviderInputStream
import ghidra.app.util.bin.ByteProviderWrapper
import ghidra.app.util.importer.AutoImporter
import ghidra.app.util.importer.MessageLog
import ghidra.framework.client.*
import ghidra.framework.protocol.ghidra.*
import ghidra.program.model.listing.Program
import ghidra.program.util.GhidraProgramUtilities
import ghidra.util.*
import ghidra.util.task.TaskMonitor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.*
import java.net.*

class Repository(private val client: Client, val name: String): Closeable {

    private val ghidraConnection = GhidraURLConnection(URL("ghidra", Ghidra.host, "/$name"),
            WhidraProtocolHandler(client.repositoryServer)).apply { isReadOnly = false }

    private val projectData = ghidraConnection.projectData

    fun delete() {
        client.deleteRepository(name)
    }

    override fun close() {
        ghidraConnection.projectData.close()
    }

    fun binaryNames(): List<String> {
        return projectData.rootFolder.files.map { it.name }
    }

    suspend fun importBinary(file: File) {
        val monitor = TaskMonitor.DUMMY

        val program = withContext(Dispatchers.IO) {
            AutoImporter.importByUsingBestGuess(
                file,
                projectData.rootFolder,
                this, MessageLog(), monitor
            )
        }

        val mgr = AutoAnalysisManager.getAnalysisManager(program)
        val txId = program.startTransaction("Analysis")

        mgr.initializeOptions()
        mgr.reAnalyzeAll(null)
        mgr.startAnalysis(monitor)

        GhidraProgramUtilities.setAnalyzedFlag(program, true)
        program.endTransaction(txId, true)

        withContext(Dispatchers.IO) {
            program.save("Analysis", monitor)
            program.domainFile.addToVersionControl("Add file ${file.name}", false, monitor)
        }

    }

    fun binary(name: String, monitor: TaskMonitor = TaskMonitor.DUMMY): Binary {
        val file = projectData.rootFolder.getFile(name)
        return Binary(file.getDomainObject(this, true, true, monitor) as Program)
    }

    class WhidraProtocolHandler(private val server: RepositoryServerAdapter) : GhidraProtocolHandler() {
        override fun isExtensionSupported(extProtocolName: String?): Boolean {
            return extProtocolName == null
        }

        override fun getConnector(ghidraUrl: URL): GhidraProtocolConnector {
            val protocol = ghidraUrl.protocol
            if (protocol != null) {
                return WhidraProtocolConnector(server, ghidraUrl)
            } else {
                throw MalformedURLException("Unsupported URL form for ghidra protocol: " + ghidraUrl.toExternalForm())
            }
        }
    }

    class WhidraProtocolConnector(private val server: RepositoryServerAdapter, url: URL) : GhidraProtocolConnector(url) {
        private var readOnly: Boolean = false

        @Throws(NotConnectedException::class)
        override fun isReadOnly(): Boolean {
            if (this.responseCode == -1) {
                throw NotConnectedException("not connected")
            }
            return this.readOnly
        }

        @Throws(IOException::class)
        override fun connect(readOnlyAccess: Boolean): Int {

            if (this.responseCode != -1) {
                throw IllegalStateException("already connected")
            }
            this.readOnly = readOnlyAccess
            this.responseCode = 404

            this.repositoryServerAdapter = server
            if (this.repositoryName == null) {
                this.responseCode = 200
                return this.responseCode
            }

            this.repositoryAdapter = this.repositoryServerAdapter.getRepository(this.repositoryName)
            this.repositoryAdapter.connect()
            if (this.repositoryAdapter.isConnected) {
                this.responseCode = 200
                if (!this.repositoryAdapter.user.hasWritePermission() && !this.readOnly) {
                    this.readOnly = true
                    Msg.warn(this, "User does not have write permission for repository: " + this.repositoryName)
                }

                this.resolveItemPath()
            } else {
                this.responseCode = 401
            }

            return this.responseCode
        }

        override fun getRepositoryRootGhidraURL(): URL? {
            return if (this.repositoryName != null) GhidraURL.makeURL(
                    this.url.host,
                    this.url.port,
                    this.repositoryName
            ) else null
        }

    }

}
