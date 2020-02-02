package routes

import ghidra.*
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.AutoImporter
import ghidra.app.util.importer.MessageLog
import ghidra.program.flatapi.FlatProgramAPI
import ghidra.program.model.lang.Register
import ghidra.program.model.listing.*
import ghidra.program.model.scalar.Scalar
import ghidra.program.util.GhidraProgramUtilities
import ghidra.util.task.TaskMonitor
import io.ktor.application.ApplicationCall
import io.ktor.application.call
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.PartData
import io.ktor.http.content.readAllParts
import io.ktor.http.content.streamProvider
import io.ktor.locations.Location
import io.ktor.locations.get
import io.ktor.locations.post
import io.ktor.request.receiveMultipart
import io.ktor.response.respond
import io.ktor.response.respondOutputStream
import io.ktor.routing.Route
import io.ktor.util.pipeline.PipelineContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import models.*
import models.Binary
import models.Function
import session.appSession
import utils.AppException
import utils.FormFieldMissing
import utils.task
import java.io.File

@Location("/{project}/binary/{name}")
open class Binary(val project: String, val name: String) {
    @Location("/functions")
    class Functions(private val binary: routes.Binary) : routes.Binary(binary)

    @Location("/code")
    class Code(private val binary: routes.Binary, val addr: String? = null, val fnName: String? = null) : routes.Binary(binary)

    @Location("/listing")
    class Listing(private val binary: routes.Binary, val addr: String, val len: Int) : routes.Binary(binary)

    @Location("/type")
    class Type(private val binary: routes.Binary, val type: String): routes.Binary(binary)

    protected constructor(other: routes.Binary) : this(other.project, other.name)
}

@Location("/{project}/binary/upload")
data class UploadBinary(val project: String, val name: String)

suspend fun <T : routes.Binary> PipelineContext<Unit, ApplicationCall>.program(bin: T, msg: String, block: Program.() -> Unit) {
    val (server) = call.appSession()
    task<Unit> {
        server.editProgram(bin.project, bin.name, msg, monitor(), block)
    }
}

val formatter = CodeUnitFormat(
        CodeUnitFormatOptions.ShowBlockName.NEVER,
        CodeUnitFormatOptions.ShowNamespace.NEVER)

fun Route.binaries() {

    get<routes.Binary.Type> {
        val (server) = call.appSession()
        val program = server.program(it.project, it.name)

        val type = program.dataTypeManager.getDataType(it.type)

    }

    get<routes.Binary.Listing> {
        val (server) = call.appSession()
        val program = server.program(it.project, it.name)
        val api = FlatProgramAPI(program)
        val iter = program.listing.getCodeUnits(api.toAddr(it.addr), true)

        val fields = iter.take(it.len).map { cu ->

            val comments = Comments(cu.getComment(0), cu.getComment(1), cu.getComment(2), cu.getComment(3), cu.getComment(4))
            val addr = cu.address.toString(false)

            when (cu) {
                is Data -> {
                    ListingField.Data(cu.dataType.displayName, formatter.getDataValueRepresentationString(cu), addr, comments)
                }
                is Instruction -> {
                    val operands = (0 until cu.numOperands).map { i ->
                        val operand = formatter.getOperandRepresentationList(cu, i)
                        operand.map { opPart ->
                            when (opPart) {
                                is Char -> OpPart(opPart, OpPartType.Char)
                                is Register -> OpPart(opPart.name.toLowerCase(), OpPartType.Register)
                                is LabelString -> OpPart(opPart.toString(), OpPartType.Label)
                                is VariableOffset -> OpPart(opPart.variable.name, OpPartType.Variable)
                                is Scalar -> OpPart(opPart.toString(), OpPartType.Scalar)
                                else -> {
                                    println("unknown $opPart of <${opPart.javaClass}>")
                                    OpPart(opPart, OpPartType.Unknown)
                                }
                            }
                        }
                    }

                    ListingField.Instruction(cu.mnemonicString, operands, addr, comments)
                }
                else -> throw Exception("neither instruction nor data!")
            }
        }

        call.respond(fields)
    }

    get<routes.Binary.Code> {
        val (server) = call.appSession()
        val program = server.program(it.project, it.name)
        val api = FlatProgramAPI(program)

        val decompiler = DecompilerXML()
        decompiler.openProgram(program)

        val function = program.functionFrom(it.fnName, it.addr)

        val stream = decompiler.decompileFunctionXML(function, -1, TaskMonitor.DUMMY)
                ?: throw AppException("Decompile output empty", HttpStatusCode.BadRequest)

        call.respondOutputStream(ContentType.parse("text/xml"),
                producer = {
                    stream.transferTo(this)
                    decompiler.dispose()
                })

    }

    get<routes.Binary.Functions> { func ->
        val (server) = call.appSession()

        val program = server.program(func.project, func.name)
        call.respond(program.functionManager.getFunctions(true).map {
            Function(it.name, it.signature.getPrototypeString(true),
                    it.entryPoint.toString(false), it.isInline, it.isThunk, it.isExternal)
        })
    }

    post<UploadBinary> {
        val (server) = call.appSession()
        val form = call.receiveMultipart()
        val binary = form.readAllParts().filterIsInstance<PartData.FileItem>()
                .firstOrNull() ?: throw FormFieldMissing("binary")

        task<Binary> {
            val file = File("/tmp/${it.name}")
            withContext(Dispatchers.IO) {
                file.createNewFile()
            }

            // copy file stream into file
            binary.streamProvider().use { input ->
                file.outputStream().use { fileOut ->
                    input.copyTo(fileOut)
                }
            }


            val project = server.projectData(it.project, false)
            val program = withContext(Dispatchers.IO) {
                AutoImporter.importByUsingBestGuess(
                        file,
                        project.rootFolder,
                        this, MessageLog(), monitor()
                )
            }

            val mgr = AutoAnalysisManager.getAnalysisManager(program)
            val txId = program.startTransaction("Analysis")
            mgr.initializeOptions()
            mgr.reAnalyzeAll(null)
            mgr.startAnalysis(monitor())
            GhidraProgramUtilities.setAnalyzedFlag(program, true)
            program.endTransaction(txId, true)

            withContext(Dispatchers.IO) {
                program.save("Analysis", monitor())
                program.domainFile.addToVersionControl("Add file ${it.name}", false, monitor())
            }

            project.close()
            file.delete()

            return@task Binary(it.name)
        }
    }
}
