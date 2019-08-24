package routes

import ghidra.app.decompiler.ClangNode
import ghidra.app.decompiler.DecompInterface
import ghidra.app.decompiler.DecompileProcess
import ghidra.app.decompiler.LimitedByteBuffer
import ghidra.app.util.PseudoDisassembler
import ghidra.app.util.PseudoFlowProcessor
import ghidra.app.util.PseudoInstruction
import ghidra.program.model.address.Address
import ghidra.program.model.listing.CodeUnitFormat
import ghidra.program.model.listing.CodeUnitFormatOptions
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.Varnode
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
import model.Asm
import util.field
import java.io.InputStream


class BinaryService : Service() {
    fun getFunctions(repository: String, binary: String): List<model.Function> {
        val project = openProject(repository, true)
        val file = project.rootFolder.getFile(binary)
        val program = file.getDomainObject(this, true, true, TaskMonitor.DUMMY) as Program

        return program.listing.getFunctions(true).map {
            model.Function(it.name, it.entryPoint.offset, it.signature.prototypeString) }
    }

    fun getCode(repository: String, binary: String, addr: Long): String {
        val project = openProject(repository, true)
        val file = project.rootFolder.getFile(binary)

        val program = file.getDomainObject(this, true, true, TaskMonitor.DUMMY) as Program

        val decompiler = DecompilerXML()
        decompiler.openProgram(program)

        val functions = program.listing.getFunctions(true)
        val function = functions.find { it.entryPoint.offset == addr } ?: throw NotFoundException("No function found at 0x${addr.toString(16)}")

        val stream = decompiler.decompileFunctionXML(function, -1, TaskMonitor.DUMMY)?.readAllBytes()
            ?: throw Exception("Decompile output empty")
        return String(stream)
    }

    fun getAsm(repository: String, binary: String, addr: Long, length: Long): List<Asm> {
        val project = openProject(repository, true)
        val file = project.rootFolder.getFile(binary)

        val program = file.getDomainObject(this, true, true, TaskMonitor.DUMMY) as Program

        val disas = PseudoDisassembler(program)

        val gAddr = program.addressFactory.defaultAddressSpace.getAddress(addr)
        val asm = mutableListOf<Asm>()

        val flows = disas.followSubFlows(gAddr, length.toInt(), object : PseudoFlowProcessor {
            override fun followFlows(instr: PseudoInstruction?): Boolean {
                return true
            }

            override fun process(instr: PseudoInstruction?): Boolean {
                if (instr == null) return false;
                val formatter = CodeUnitFormat(
                    CodeUnitFormatOptions.ShowBlockName.NEVER,
                    CodeUnitFormatOptions.ShowNamespace.NEVER)
                asm.add(Asm(formatter.getRepresentationString(instr), instr.address.offset))
                return true;
            }
        })

        return asm
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
            val addr = call.field("addr")
            call.respond("what code?")
            //call.respond(svc.getCode(repository, binary, addr.toLong()))
        }

        get("asm") {
            val repository = call.field("repository")
            val binary = call.field("binary")
            val addr = call.field("addr")
            val length = call.field("length")
            call.respond(svc.getAsm(repository, binary, addr.toLong(), length.toLong()))
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
