package routes

import ghidra.framework.model.ProjectData
import ghidra.framework.protocol.ghidra.GhidraURLConnection
import ghidra.util.Msg
import ghidra.util.task.TaskMonitor
import ghidra.util.task.TaskMonitorAdapter
import io.ktor.application.ApplicationCall
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
import java.net.URL

class Task<T>(val block: suspend Task<T>.() -> T) {
    val events = Channel<Event>()

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
                runBlocking { task.events.send(Event.Message(msg)) }
        }

        override fun setProgress(value: Long) {
            runBlocking { task.events.send(Event.Progress(value, max)) }
        }

        override fun setIndeterminate(indeterminate: Boolean) {
            if(indeterminate)
                runBlocking { task.events.send(Event.Indeterminate) }
        }
    }
}

fun <T> task(block: suspend Task<T>.() -> T): Task<T> {
    return Task(block)
}

open class Service {

    fun openProject(repoName: String, readOnly: Boolean): ProjectData {
        val repo = GhidraURLConnection(URL("ghidra", "localhost", "/$repoName"))
        repo.isReadOnly = readOnly
        return repo.projectData ?: throw Exception("Project data not found")
    }

}

class Form {
    val fields = HashMap<String, String>();
    val files = HashMap<String, PartData.FileItem>();
    val blobs = HashMap<String, PartData.BinaryItem>();

    fun field(name: String): String {
        return fields[name] ?: throw ParamException(name)
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
