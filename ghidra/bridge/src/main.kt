import bridge.Repository
import com.google.protobuf.Empty
import ghidra.GhidraJarApplicationLayout
import ghidra.app.util.importer.AutoImporter
import ghidra.app.util.importer.MessageLog;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.PseudoDisassembler
import ghidra.app.util.PseudoFlowProcessor
import ghidra.app.util.PseudoInstruction
import ghidra.framework.Application
import ghidra.framework.HeadlessGhidraApplicationConfiguration
import ghidra.framework.client.ClientUtil
import ghidra.framework.client.PasswordClientAuthenticator
import ghidra.framework.client.RepositoryServerAdapter
import ghidra.framework.model.ProjectData
import ghidra.framework.protocol.ghidra.GhidraURLConnection
import ghidra.program.model.listing.Program
import ghidra.program.util.GhidraProgramUtilities
import ghidra.util.task.TaskMonitor
import io.grpc.stub.StreamObserver
import ghidra.program.model.listing.Function
import java.io.File
import java.lang.Exception
import java.net.URL
import ghidra.util.Msg
import ghidra.util.exception.CancelledException
import ghidra.util.exception.VersionException
import java.io.IOException
import ghidra.framework.data.CheckinHandler
import kotlin.system.measureTimeMillis


val host = "localhost"
val port = 13100
val username = "daniellimws"

lateinit var server: RepositoryServerAdapter

fun main() {
    init()
    server = connect()
    val program = importBinary("testRepo", "bins/heapschool")
    analyzeProgram(program)
    disassemble(program, 0x400e05)
    // commitProgram("testRepo", program, "Add ${program.name} to version control")
}

fun init() {
    if (!Application.isInitialized())
        Application.initializeApplication(
            GhidraJarApplicationLayout(),
            HeadlessGhidraApplicationConfiguration()
        )
}

fun connect(): RepositoryServerAdapter {
    ClientUtil.setClientAuthenticator(PasswordClientAuthenticator(username, "password"))
    //TODO reset password
    return ClientUtil.getRepositoryServer(host, port, true)
}

class BridgeService : bridge.BridgeServiceGrpc.BridgeServiceImplBase() {
    override fun getRepositories(request: Empty?, response: StreamObserver<Repository>?) {
        server.repositoryNames.forEach {
            response?.onNext(Repository.newBuilder().setName(it).build())
        }
        response?.onCompleted()
    }
}

fun repositories(): Array<String> {
    return server.repositoryNames
}

fun users(): Array<String> {
    return server.allUsers
}

fun binaries(repoName: String): Iterable<String> {
    val repo = server.getRepository(repoName)
    repo.connect()
    val binaries = repo.getItemList("/").map { it.name }
    repo.disconnect()
    return binaries
}

fun newRepository(repoName: String) {
    server.createRepository(repoName)
}

fun importBinary(repoName: String, binary: String): Program {
    val project = openProject(repoName, false)
    return AutoImporter.importByUsingBestGuess(
        File(binary),
        project.rootFolder,
        project, MessageLog(), TaskMonitor.DUMMY
    )
}

fun analyzeProgram(program: Program) {
    val mgr = AutoAnalysisManager.getAnalysisManager(program)

    val txId = program.startTransaction("Analysis")
    try {
        mgr.initializeOptions()
        mgr.reAnalyzeAll(null)
        mgr.startAnalysis(TaskMonitor.DUMMY)
        GhidraProgramUtilities.setAnalyzedFlag(program, true);
    } finally {
        program.endTransaction(txId, true)
    }

    program.save("Auto-analysis", TaskMonitor.DUMMY)
}

fun commitProgram(repoName: String, program: Program, comment: String) {
    val repo = server.getRepository(repoName)
    repo.connect()

    val df = program.domainFile
    when {
        df.canAddToRepository() -> try {
            df.addToVersionControl(comment, false, TaskMonitor.DUMMY)
            Msg.info(null, "REPORT: Added file to repository: " + df.pathname)
        } catch (e: IOException) {
            Msg.error(null, df.pathname + ": File check-in failed - " + e.message)
            throw e
        } catch (e: CancelledException) {
            // this can never happen because there is no user interaction in headless!
        }

        df.canCheckin() -> try {
            df.checkin(object : CheckinHandler {
                @Throws(CancelledException::class)
                override fun keepCheckedOut(): Boolean {
                    return true
                }

                @Throws(CancelledException::class)
                override fun getComment(): String {
                    return comment
                }

                @Throws(CancelledException::class)
                override fun createKeepFile(): Boolean {
                    return false
                }
            }, true, TaskMonitor.DUMMY)
            Msg.info(null, "REPORT: Committed file changes to repository: " + df.pathname)
        } catch (e: IOException) {
            Msg.error(null, df.pathname + ": File check-in failed - " + e.message)
            throw e
        } catch (e: VersionException) {
            Msg.error(
                null,
                df.pathname + ": File check-in failed - version error occurred"
            )
        } catch (e: CancelledException) {
            // this can never happen because there is no user interaction in headless!
        }
        else -> Msg.error(null, df.pathname + ": Unable to commit file")
    }

    repo.disconnect()
}

fun openProject(repoName: String, readOnly: Boolean): ProjectData {
    val repo = GhidraURLConnection(URL("ghidra", host, "/$repoName"))
    repo.isReadOnly = readOnly
    return repo.projectData ?: throw Exception("Project data not found")
}

fun disassemble(program: Program, functionAddress: Int) {
    val f = getFunction(program, functionAddress);
    if (f == null) {
        System.err.println(String.format("Function not found at 0x%x", functionAddress));
        return;
    }

    val pDis = PseudoDisassembler(program);
    pDis.followSubFlows(f.entryPoint, 4000, object : PseudoFlowProcessor {
        override fun followFlows(instr: PseudoInstruction?): Boolean {
            return true;
        }

        override fun process(instr: PseudoInstruction?): Boolean {
            if (instr == null) {
                return false;
            }
            val fType = instr.flowType;
            if (fType.isTerminal) {
                if (instr.mnemonicString.compareTo("ret", true) == 0) {
                    return false;
                }
            }

            println(String.format("%s: %s", instr.address, instr));
            return true;
        }
    });
}

fun getFunction(program: Program, address: Int): Function? {
    val listing = program.listing
    val iterator = listing.getFunctions(true);
    while (iterator.hasNext()) {
        val f = iterator.next();
        if (f.isExternal) {
            continue;
        }

        val entry = f.entryPoint;
        if (entry != null && entry.offset == address.toLong()) {
            return f;
        }
    }
    return null;
}