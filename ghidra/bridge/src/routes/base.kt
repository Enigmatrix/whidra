package routes

import ghidra.framework.model.ProjectData
import ghidra.framework.protocol.ghidra.GhidraURLConnection
import ghidra.util.Msg
import ghidra.util.task.TaskMonitor
import ghidra.util.task.TaskMonitorAdapter
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.runBlocking
import model.Event
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