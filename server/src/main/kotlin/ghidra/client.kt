package ghidra

import ghidra.framework.HeadlessGhidraApplicationConfiguration
import ghidra.framework.Application
import ghidra.framework.client.ClientUtil
import ghidra.framework.client.NotConnectedException
import ghidra.framework.client.PasswordClientAuthenticator
import ghidra.framework.client.RepositoryServerAdapter
import ghidra.framework.data.CheckinHandler
import ghidra.framework.model.ProjectData
import ghidra.util.HashUtilities
import ghidra.util.Msg
import javax.net.ssl.SSLHandshakeException
import java.rmi.RemoteException
import java.rmi.UnmarshalException
import java.io.IOException
import java.rmi.NotBoundException
import ghidra.framework.remote.GhidraServerHandle
import javax.rmi.ssl.SslRMIClientSocketFactory
import java.rmi.registry.LocateRegistry
import java.rmi.registry.Registry
import ghidra.framework.model.ServerInfo
import ghidra.framework.protocol.ghidra.*
import ghidra.framework.remote.GhidraPrincipal
import javax.net.ssl.SSLSocket
import ghidra.framework.remote.RMIServerPortFactory
import ghidra.framework.remote.RepositoryServerHandle
import ghidra.net.ApplicationKeyManagerFactory
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import java.net.MalformedURLException
import java.net.URL
import java.util.HashSet
import javax.security.auth.Subject
import javax.security.auth.callback.NameCallback
import javax.security.auth.callback.PasswordCallback


object WhidraClient {

    lateinit var server: RepositoryServerAdapter
    public const val host = "localhost"
    public const val port = 13100
    public const val user = "ghidra"
    public const val defaultPassword = "changeme"

    fun init() {
        if (!Application.isInitialized())
            Application.initializeApplication(
                GhidraJarApplicationLayout(),
                HeadlessGhidraApplicationConfiguration()
            )

        var pass = System.getenv("GHIDRA_PASS") ?: this.defaultPassword

        try {
            val server = this.connect(this.user, this.defaultPassword)
            server.setPassword(HashUtilities.getSaltedHash(HashUtilities.SHA256_ALGORITHM, pass.toCharArray()))
            server.disconnect()
        } catch (e: Exception) {
            Msg.warn(this, "Attempt to change password", e)
        }
        this.server = this.connect(this.user, pass)
    }

    fun connect(user: String, pass: String): RepositoryServerAdapter {
        ClientUtil.setClientAuthenticator(PasswordClientAuthenticator(user, pass))
        return ClientUtil.getRepositoryServer(this.host, this.port, true)
    }

    fun login(user: String, pass: String): RepositoryServerAdapter? {
        val serverInfo = ServerInfo(this.host, this.port)
        val serverHandle = this.getGhidraServerHandle(serverInfo)

        val pwCb = PasswordCallback("Password:", false)
        pwCb.password = pass.toCharArray()
        val nCb = NameCallback("User ID:")
        nCb.name = user

        val hdl = serverHandle?.getRepositoryServer(this.getUserSubject(user), arrayOf(nCb, pwCb)) ?: return null
        val rsa = WhidraRepositoryServerAdapter(hdl, serverInfo.toString())
        rsa.connect()
        return rsa
    }


    class WhidraRepositoryServerAdapter(serverHandle: RepositoryServerHandle?, serverInfoString: String?) :
        RepositoryServerAdapter(serverHandle, serverInfoString)

    private fun getUserSubject(username: String): Subject {
        val pset = HashSet<GhidraPrincipal>()
        val emptySet = HashSet<Any>()
        pset.add(GhidraPrincipal(username))
        return Subject(false, pset, emptySet, emptySet)
    }

    /**
     * Obtain a remote instance of the Ghidra Server Handle object
     * @param server server information
     * @return Ghidra Server Handle object
     * @throws IOException
     */
    @Throws(IOException::class)
    fun getGhidraServerHandle(server: ServerInfo): GhidraServerHandle? {
        try {
            // Test SSL Handshake to ensure that user is able to decrypt keystore.
            // This is intended to work around an RMI issue where a continuous
            // retry condition can occur when a user cancels the password entry
            // for their keystore which should cancel any connection attempt
            this.testServerSSLConnection(server)

            var reg: Registry
            try {
                // attempt to connect with older Ghidra Server registry without using SSL/TLS
                reg = LocateRegistry.getRegistry(server.serverName, server.portNumber)
                this.checkServerBindNames(reg)
            } catch (e: IOException) {
                reg = LocateRegistry.getRegistry(server.serverName, server.portNumber, SslRMIClientSocketFactory())
                this.checkServerBindNames(reg)
            }

            val gsh = reg.lookup(GhidraServerHandle.BIND_NAME) as GhidraServerHandle
            gsh.checkCompatibility(GhidraServerHandle.INTERFACE_VERSION)
            return gsh
        } catch (e: NotBoundException) {
            throw IOException(e.message)
        } catch (e: SSLHandshakeException) {
            if (this.isSSLHandshakeCancelled(e)) {
                return null
            }
            throw e
        } catch (e: RemoteException) {
            val cause = e.cause
            if (cause is UnmarshalException || cause is ClassNotFoundException) {
                throw RemoteException("Incompatible Ghidra Server interface version")
            }
            if (cause is SSLHandshakeException && this.isSSLHandshakeCancelled(cause)) {
                return null
            }
            throw e
        }
    }


    @Throws(IOException::class)
    private fun isSSLHandshakeCancelled(e: SSLHandshakeException): Boolean {
        val badcertidx = e.message?.indexOf("bad_certificate")
        if (badcertidx != null && badcertidx > 0) {
            if (ApplicationKeyManagerFactory.getPreferredKeyStore() == null) {
                throw IOException("User PKI Certificate not installed", e)
            }
            // assume user cancelled connect attempt when prompted for cert password
            // or other cert error occured
            return true
        }
        // TODO: Translate SSL exceptions to more meaningful errors
        //		else if (e.getMessage().indexOf("certificte_unknown") > 0) {
        //			// cert issued by unrecognized authority
        //		}
        return false
    }

    @Throws(IOException::class)
    private fun testServerSSLConnection(server: ServerInfo) {

        val portFactory = RMIServerPortFactory(server.portNumber)
        val factory = SslRMIClientSocketFactory()
        val serverName = server.serverName
        val sslRmiPort = portFactory.rmisslPort

        (factory.createSocket(serverName, sslRmiPort) as SSLSocket).use { socket ->
            // Complete SSL handshake to trigger client keystore access if required
            // which will give user ability to cancel without involving RMI which
            // will avoid RMI reconnect attempts
            socket.startHandshake()
        }
    }

    @Throws(RemoteException::class)
    private fun checkServerBindNames(reg: Registry) {

        var requiredVersion = GhidraServerHandle.MIN_GHIDRA_VERSION
        if (!Application.getApplicationVersion().startsWith(requiredVersion)) {
            requiredVersion = requiredVersion + " - " + Application.getApplicationVersion()
        }

        val regList = reg.list()
        var exc: RemoteException? = null
        var badVerCount = 0

        for (name in regList) {
            if (name == GhidraServerHandle.BIND_NAME) {
                return  // found it
            } else if (name.startsWith(GhidraServerHandle.BIND_NAME_PREFIX)) {
                var version = name.substring(GhidraServerHandle.BIND_NAME_PREFIX.length)
                if (version.length == 0) {
                    version = "4.3.x (or older)"
                }
                exc = RemoteException(
                    "Incompatible Ghidra Server interface, detected interface version " + version +
                            ",\nthis client requires server version " + requiredVersion
                )
                ++badVerCount
            }
        }
        if (exc != null) {
            if (badVerCount == 1) {
                throw exc
            }
            throw RemoteException(
                ("Incompatible Ghidra Server interface, detected " +
                        badVerCount + " incompatible server versions" +
                        ",\nthis client requires server version " + requiredVersion)
            )
        }
        throw RemoteException("Ghidra Server not found.")
    }
}


fun RepositoryServerAdapter.editProgram(
    repository: String,
    binary: String,
    msg: String,
    monitor: TaskMonitor,
    block: (Program) -> Unit
): Program {
    val project = this.projectData(repository, false)
    val file = project.rootFolder.getFile(binary)

    file.checkout(false, monitor)
    val program = file.getDomainObject(this, true, true, monitor) as Program
    val tx = program.startTransaction(msg)
    //TODO try catch
    block(program)
    //TODO wtf is this boolean?
    program.endTransaction(tx, true)
    file.save(monitor)
    file.checkin(CheckinWithComment(msg), true, monitor)
    return program
}

class CheckinWithComment(val cmt: String) : CheckinHandler {
    override fun getComment() = this.cmt
    override fun createKeepFile() = false
    override fun keepCheckedOut() = false
}

fun RepositoryServerAdapter.projectData(repoName: String, readOnly: Boolean): ProjectData {
    val repo = GhidraURLConnection(URL("ghidra", WhidraClient.host, "/$repoName"), WhidraProtocolHandler(this))
    repo.isReadOnly = readOnly
    return repo.projectData ?: throw Exception("Project data not found")
}

fun RepositoryServerAdapter.program(repository: String, binary: String): Program {
    val project = this.projectData(repository, true)
    val file = project.rootFolder.getFile(binary)
    val program = file.getDomainObject(this, true, true, TaskMonitor.DUMMY) as Program
    return program
}


class WhidraProtocolHandler(val rsa: RepositoryServerAdapter) : GhidraProtocolHandler() {
    override fun isExtensionSupported(extProtocolName: String?): Boolean {
        return extProtocolName == null
    }

    override fun getConnector(ghidraUrl: URL): GhidraProtocolConnector {
        val protocol = ghidraUrl.protocol
        if (protocol != null) {
            return WhidraProtocolConnector(rsa, ghidraUrl)
        } else {
            throw MalformedURLException("Unsupported URL form for ghidra protocol: " + ghidraUrl.toExternalForm())
        }
    }
}

class WhidraProtocolConnector(val rsa: RepositoryServerAdapter, url: URL) : GhidraProtocolConnector(url) {
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

        this.repositoryServerAdapter = rsa
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
