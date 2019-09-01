package routes

import ghidra.framework.data.CheckinHandler
import ghidra.framework.model.ProjectData
import ghidra.framework.protocol.ghidra.GhidraURLConnection
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.util.Msg
import ghidra.util.task.TaskMonitor
import ghidra.util.task.TaskMonitorAdapter
import io.ktor.application.ApplicationCall
import io.ktor.features.NotFoundException
import io.ktor.http.content.PartData
import io.ktor.http.content.forEachPart
import io.ktor.request.isMultipart
import io.ktor.request.receiveMultipart
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.runBlocking
import kotlinx.io.core.Input
import model.Event
import util.ParamException
import util.ParamType
import util.randomSecret
import java.net.URL

class Task<T>(val block: suspend Task<T>.() -> T) {
    val events = Channel<Event>()
    val id = randomSecret()

    fun monitor(): TaskMonitor {
        return TaskMonitorImpl(this)
    }

    suspend fun execute() {

        val result = block()
        events.offer(Event.Completed(result))
        events.close()
    }

    private class TaskMonitorImpl<T>(val task: Task<T>) : TaskMonitorAdapter() {
        private var max = 0L

        override fun initialize(max: Long) {
            this.max = max
            super.setMaximum(max)
        }

        override fun setMessage(msg: String?) {
            if(msg != null)
                task.events.offer(Event.Message(msg))
        }

        override fun setProgress(value: Long) {
            task.events.offer(Event.Progress(value, max))
        }

        override fun setIndeterminate(indeterminate: Boolean) {
            if(indeterminate)
                task.events.offer(Event.Indeterminate)
        }
    }
}

fun <T> task(block: suspend Task<T>.() -> T): Task<T> {
    return Task(block)
}

open class Service {

    fun fnRef(fnAddr: Long?, fnName: String?): String {
        return if (fnAddr == null) {
            "with name `$fnName`"
        }
        else {
            "with address 0x${fnAddr.toString(16)}"
        }
    }

    fun functionFrom(program: Program, fnname: String?, addr: Long?): Function {
        val functions = program.listing.getFunctions(true)
        return functions.find {
            if (fnname != null) { it.name == fnname } else { it.entryPoint.offset == addr} } ?: throw NotFoundException("No function found at 0x${addr?.toString(16)}")
    }

    fun editProgram(repository: String, binary: String, msg: String, monitor: TaskMonitor, block: (Program) -> Unit): Program  {
        val project = openProject(repository, false)
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

    class CheckinWithComment(val cmt: String): CheckinHandler {
        override fun getComment() = cmt
        override fun createKeepFile() = false
        override fun keepCheckedOut() = false
    }

    fun openProject(repoName: String, readOnly: Boolean): ProjectData {
        val repo = GhidraURLConnection(URL("ghidra", "localhost", "/$repoName"))
        repo.isReadOnly = readOnly
        return repo.projectData ?: throw Exception("Project data not found")
    }

    fun openProgram(repository: String, binary: String): Program {
        val project = openProject(repository, true)
        val file = project.rootFolder.getFile(binary)
        val program = file.getDomainObject(this, true, true, TaskMonitor.DUMMY) as Program
        return program
    }

}

class Form {
    val fields = HashMap<String, String>();
    val files = HashMap<String, PartData.FileItem>();
    val blobs = HashMap<String, PartData.BinaryItem>();

    fun field(name: String): String {
        return fields[name] ?: throw ParamException(name)
    }

    fun maybeField(name: String): String? {
        return fields[name]
    }

    fun file(name: String): PartData.FileItem {
        return files[name] ?: throw ParamException(name, ParamType.FILE)
    }

    fun blob(name: String): PartData.BinaryItem {
        return blobs[name] ?: throw ParamException(name, ParamType.BINARY)
    }
}

suspend fun ApplicationCall.receiveForm(): Form {
    val form = Form()
    if(!request.isMultipart()) { return form; }
    val multipart = receiveMultipart();
    multipart.forEachPart { part ->
        when (part) {
            is PartData.FormItem -> {
                form.fields[part.name.orEmpty()] = part.value;
            }
            is PartData.FileItem -> {
                form.files[part.name.orEmpty()] = part;
            }
            is PartData.BinaryItem -> {
                form.blobs[part.name.orEmpty()] = part;
            }
        }
    }
    return form;
}
