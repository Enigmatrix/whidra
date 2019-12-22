package ghidra

import ghidra.framework.HeadlessGhidraApplicationConfiguration
import ghidra.framework.Application
import ghidra.framework.client.ClientUtil
import ghidra.framework.client.PasswordClientAuthenticator
import ghidra.framework.client.RepositoryServerAdapter
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
import ghidra.framework.remote.GhidraPrincipal
import javax.net.ssl.SSLSocket
import ghidra.framework.remote.RMIServerPortFactory
import ghidra.framework.remote.RepositoryServerHandle
import ghidra.net.ApplicationKeyManagerFactory
import java.util.HashSet
import javax.security.auth.Subject
import javax.security.auth.callback.ChoiceCallback
import javax.security.auth.callback.NameCallback
import javax.security.auth.callback.PasswordCallback


object WhidraClient {

    public lateinit var server: RepositoryServerAdapter
    private const val host = "localhost"
    private const val port = 13100
    private const val user = "ghidra"
    private const val defaultPassword = "changeme"

    fun init() {
        if (!Application.isInitialized())
            Application.initializeApplication(
                GhidraJarApplicationLayout(),
                HeadlessGhidraApplicationConfiguration()
            )

        var pass = System.getenv("GHIDRA_PASS") ?: defaultPassword

        try {
            val server = connect(user, defaultPassword)
            server.setPassword(HashUtilities.getSaltedHash(HashUtilities.SHA256_ALGORITHM, pass.toCharArray()))
            server.disconnect()
        } catch (e: Exception) {
            Msg.warn(this, "Attempt to change password", e)
        }
        server = connect(user, pass)
    }

    fun connect(user: String, pass: String): RepositoryServerAdapter {
        ClientUtil.setClientAuthenticator(PasswordClientAuthenticator(user, pass))
        return ClientUtil.getRepositoryServer(host, port, true)
    }

    fun login(user: String, pass: String): RepositoryServerAdapter? {
        val serverInfo = ServerInfo(host, port)
        val serverHandle = getGhidraServerHandle(serverInfo)

        val pwCb = PasswordCallback("Password:", false)
        pwCb.password = pass.toCharArray()
        val nCb = NameCallback("User ID:")
        nCb.name = user

        val hdl = serverHandle?.getRepositoryServer(getUserSubject(user), arrayOf(nCb, pwCb)) ?: return null
        val rsa = WhidraRepositoryServerAdapter(hdl, serverInfo.toString())
        rsa.connect()
        return rsa
    }

    class WhidraRepositoryServerAdapter(serverHandle: RepositoryServerHandle?, serverInfoString: String?) :
        RepositoryServerAdapter(serverHandle, serverInfoString) {

    }

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
            testServerSSLConnection(server)

            var reg: Registry
            try {
                // attempt to connect with older Ghidra Server registry without using SSL/TLS
                reg = LocateRegistry.getRegistry(server.serverName, server.portNumber)
                checkServerBindNames(reg)
            } catch (e: IOException) {
                reg = LocateRegistry.getRegistry(server.serverName, server.portNumber, SslRMIClientSocketFactory())
                checkServerBindNames(reg)
            }

            val gsh = reg.lookup(GhidraServerHandle.BIND_NAME) as GhidraServerHandle
            gsh.checkCompatibility(GhidraServerHandle.INTERFACE_VERSION)
            return gsh
        } catch (e: NotBoundException) {
            throw IOException(e.message)
        } catch (e: SSLHandshakeException) {
            if (isSSLHandshakeCancelled(e)) {
                return null
            }
            throw e
        } catch (e: RemoteException) {
            val cause = e.cause
            if (cause is UnmarshalException || cause is ClassNotFoundException) {
                throw RemoteException("Incompatible Ghidra Server interface version")
            }
            if (cause is SSLHandshakeException && isSSLHandshakeCancelled(cause)) {
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