package routes

import ghidra.app.decompiler.ClangNode
import ghidra.app.decompiler.DecompInterface
import ghidra.app.decompiler.DecompileProcess
import ghidra.app.decompiler.LimitedByteBuffer
import ghidra.app.util.PseudoDisassembler
import ghidra.app.util.PseudoFlowProcessor
import ghidra.app.util.PseudoInstruction
import ghidra.program.flatapi.FlatProgramAPI
import ghidra.program.model.address.Address
import ghidra.program.model.lang.Register
import ghidra.program.model.listing.*
import ghidra.program.model.pcode.Varnode
import ghidra.program.model.scalar.Scalar
import ghidra.util.task.TaskMonitor
import io.ktor.application.call
import io.ktor.features.NotFoundException
import io.ktor.request.queryString
import io.ktor.response.respond
import io.ktor.routing.Route
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.routing.route
import io.ktor.util.hex
import model.Data
import model.Instruction
import model.OpPart
import model.OpPartType
import util.field
import util.maybeField
import java.io.InputStream


class BinaryService : Service() {

    fun getFunctions(repository: String, binary: String): List<model.Function> {
        val program = openProgram(repository, binary)
        return program.listing.getFunctions(true).map {
            model.Function(it.name, it.entryPoint.offset, it.signature.prototypeString) }
    }

    fun getCode(repository: String, binary: String, addr: Long?, fnname: String?): String {
        val program = openProgram(repository, binary)

        val decompiler = DecompilerXML()
        decompiler.openProgram(program)

        val function = functionFrom(program, fnname, addr)

        val stream = decompiler.decompileFunctionXML(function, -1, TaskMonitor.DUMMY)?.readAllBytes()
            ?: throw Exception("Decompile output empty")
        return String(stream)
    }

    fun getAsm(repository: String, binary: String, addr: Long, length: Long): List<Instruction> {
        val program = openProgram(repository, binary)
        val formatter = CodeUnitFormat(
            CodeUnitFormatOptions.ShowBlockName.NEVER,
            CodeUnitFormatOptions.ShowNamespace.NEVER)

        val api = FlatProgramAPI(program)
        val gAddr = api.toAddr(addr)

        val iter = program.listing.getCodeUnits(gAddr, true)

        return iter
            .take(length.toInt())
            .map { x ->

                if(x is ghidra.program.model.listing.Data) {
                    println(formatter.getDataValueRepresentationString(x))
                }

                val operands = (0 until x.numOperands).map { i ->
                    val operand = formatter.getOperandRepresentationList(x, i)
                    operand.map { opPart ->
                         when(opPart) {
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

                //formatter.getReferenceRepresentationString(x, x.refere)
                println(formatter.getRepresentationString(x, true))
                println()

                Instruction(x.address.offset, x.mnemonicString.toLowerCase(), operands)
        }
    }

    fun getData(repository: String, binary: String, addr: Long, length: Long): List<Data> {
        val program = openProgram(repository, binary)
        val formatter = CodeUnitFormat(
            CodeUnitFormatOptions.ShowBlockName.NEVER,
            CodeUnitFormatOptions.ShowNamespace.NEVER)

        val api = FlatProgramAPI(program)
        val gAddr = api.toAddr(addr)

        val iter = program.listing.getData(gAddr, true)
        return iter.map { x -> Data(formatter.getDataValueRepresentationString(x), x.address.offset) }
            .take(length.toInt())

    }

    fun getSymbolAddr(repository: String, binary: String, symbol: String): Long {
        val program = openProgram(repository, binary)
        return program.symbolTable.getSymbol(symbol).address.offset
    }


}

fun Route.routesFor(svc: BinaryService) {
    route("binary") {

        // curl "http://localhost:8000/api/binary/functions?repository=TEST&binary=challenge"
        get("functions") {
            val repository = call.field("repository")
            val binary = call.field("binary")
            call.respond(svc.getFunctions(repository, binary))
        }

        get("code") {
            val repository = call.field("repository")
            val binary = call.field("binary")
            val addr = call.maybeField("addr")
            val fnname = call.maybeField("fnName")
            call.respond(svc.getCode(repository, binary, addr?.toLong(), fnname))
        }

        get("asm") {
            val repository = call.field("repository")
            val binary = call.field("binary")
            val addr = call.field("addr")
            val length = call.field("length")
            call.respond(svc.getAsm(repository, binary, addr.toLong(), length.toLong()))
        }

        get("data") {
            val repository = call.field("repository")
            val binary = call.field("binary")
            val addr = call.field("addr")
            val length = call.field("length")
            call.respond(svc.getData(repository, binary, addr.toLong(), length.toLong()))
        }

        get("symbol_addr") {
            val repository = call.field("repository")
            val binary = call.field("binary")
            val symbol = call.field("symbol")
            call.respond(svc.getSymbolAddr(repository, binary, symbol))
        }

        post("rename/var") {

        }

        post("rename/function") {

        }
    }
}


class DecompilerXML : DecompInterface() {
    fun decompileFunctionXML(func: ghidra.program.model.listing.Function, timeoutSecs: Int, monitor: TaskMonitor): InputStream? {
        decompileMessage = ""
        var res: LimitedByteBuffer? = null

        if (monitor.isCancelled) return null;
        if (program == null) return null;
        monitor.addCancelledListener(monitorListener)

        try {
            val funcEntry = func.entryPoint;
            decompCallback.setFunction(func, funcEntry, null)
            val addrString = Varnode.buildXMLAddress(funcEntry)
            verifyProcess()
            res = decompProcess.sendCommand1ParamTimeout("decompileAt", addrString.toString(), timeoutSecs)
            decompileMessage = decompCallback.nativeMessage
        }
        catch (ex: java.lang.Exception) {
            decompileMessage = "Exception while decompiling ${func.entryPoint}: ${ex.message}"
        }
        finally{
            monitor.removeCancelledListener(monitorListener);
        }

        val processState = if (decompProcess != null) {
            if(DecompileProcess.DisposeState.NOT_DISPOSED == decompProcess.disposeState)
                flushCache()
            decompProcess.disposeState
        }
        else { DecompileProcess.DisposeState.DISPOSED_ON_CANCEL }

        return res?.inputStream;
    }
}
