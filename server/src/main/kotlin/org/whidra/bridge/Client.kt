package org.whidra.bridge

import ghidra.framework.*
import ghidra.framework.client.*
import ghidra.framework.model.*
import ghidra.framework.remote.*
import ghidra.net.ApplicationKeyManagerFactory
import ghidra.util.*
import java.io.*
import java.rmi.*
import java.rmi.registry.*
import javax.net.ssl.*
import javax.rmi.ssl.SslRMIClientSocketFactory
import javax.security.auth.*
import javax.security.auth.callback.*

class Client(private val user: String, private val pass: String): Closeable {

    var repositoryServer: WhidraRepositoryServerAdapter

    init {
        val serverInfo = ServerInfo(Ghidra.host, Ghidra.port)
        val serverHandle = getGhidraServerHandle(serverInfo)

        val hdl = serverHandle?.getRepositoryServer(this.getUserSubject(user), arrayOf(
            NameCallback("User ID:").apply { name = user },
            PasswordCallback("Password:", false).apply { password = pass.toCharArray() }
        ))
        repositoryServer = WhidraRepositoryServerAdapter(hdl, serverInfo.toString()).apply { connect() }
    }

    fun repositoryNames(): Array<String> {
        return repositoryServer.repositoryNames
    }

    fun repository(name: String): Repository {
        return Repository(this, name)
    }

    fun deleteRepository(name: String) {
        repositoryServer.deleteRepository(name)
    }

    fun createRepository(name: String): Repository {
        repositoryServer.createRepository(name)
        return Repository(this, name)
    }

    fun users(): Array<String> {
        return repositoryServer.allUsers
    }

    fun setPassword(pass: String) {
        repositoryServer.setPassword(HashUtilities.getSaltedHash(HashUtilities.SHA256_ALGORITHM, pass.toCharArray()))
    }

    override fun close() {
        repositoryServer.disconnect()
    }


    // TODO find a way to NOT use these copy pasted stuff
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
                if (version.isEmpty()) {
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