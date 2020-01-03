package utils

import ghidra.util.task.TaskMonitor
import ghidra.util.task.TaskMonitorAdapter
import io.ktor.application.ApplicationCall
import io.ktor.application.call
import io.ktor.response.respond
import io.ktor.util.pipeline.PipelineContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import models.Event
import session.genRandomId
import session.appSession

fun<T> chooseInDev(inDev: T, notInDev: T): T {
    val isDev = (System.getenv("MODE") ?: "dev") == "dev"
    return if (isDev) { inDev } else { notInDev }
}

suspend fun <T> PipelineContext<Unit, ApplicationCall>.task(block: suspend Task<T>.() -> T) {
    val (_, taskMgr) = call.appSession()
    val task = Task(block)

    taskMgr.tasks.send(task)

    coroutineScope {
        withContext(Dispatchers.Default){
            call.respond(task.execute())
        }
    }
}

class TaskManager {
    val tasks = Channel<Task<*>>(Channel.UNLIMITED)
}

class Task<T>(val block: suspend Task<T>.() -> T) {
    val events = Channel<Event>()
    val id = genRandomId()

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