package routes

import ghidra.app.decompiler.ClangNode
import ghidra.app.decompiler.DecompInterface
import ghidra.app.decompiler.DecompileProcess
import ghidra.app.decompiler.LimitedByteBuffer
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.Varnode
import ghidra.util.task.TaskMonitor
import io.ktor.application.call
import io.ktor.request.queryString
import io.ktor.response.respond
import io.ktor.routing.Route
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.routing.route
import java.io.InputStream

data class Function(val name: String, val addr: Long, val signature: String)

class BinaryService : Service() {
    fun getFunctions(repository: String, binary: String): List<Function> {
        val project = openProject(repository, true)
        val file = project.rootFolder.getFile(binary)
        val program = file.getDomainObject(this, true, true, TaskMonitor.DUMMY) as Program

        return program.listing.getFunctions(true).map {
            Function(it.name, it.entryPoint.offset, it.signature.prototypeString) }
    }

    fun getCode(repository: String, binary: String): String {
        val project = openProject(repository, true)
        val file = project.rootFolder.getFile(binary)

        val program = file.getDomainObject(this, true, true, TaskMonitor.DUMMY) as Program

        val decompiler = DecompilerXML()
        decompiler.openProgram(program)

        val functions = program.listing.getFunctions(true).toList()
        val main = functions.find { it.name == "main" } ?: functions.first()

        val stream = decompiler.decompileFunctionXML(main, -1, TaskMonitor.DUMMY)?.readAllBytes()
            ?: throw Exception("Decompile output empty")
        return String(stream)
    }


}

fun Route.binary(svc: BinaryService) {
    route("binary") {

        // curl "http://localhost:8000/api/binary/functions?repository=TEST&binary=challenge"
        get("functions") {
            val repository = call.request.queryParameters["repository"] ?: throw Exception("repository not found")
            val binary = call.request.queryParameters["binary"] ?: throw Exception("binary not found")
            call.respond(svc.getFunctions(repository, binary))
        }

        get("code") {
            val repository = call.request.queryParameters["repository"] ?: throw Exception("repository not found")
            val binary = call.request.queryParameters["binary"] ?: throw Exception("binary not found")
            call.respond(svc.getCode(repository, binary))
        }

        get("asm") {

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
