package routes

import ghidra.util.Msg
import ghidra.util.task.TaskMonitor
import ghidra.util.task.TaskMonitorAdapter
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.runBlocking
import model.Event

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
    val t = Task(block)
    return t
}

open class Service {

}