package models

sealed class TaskEvent(val kind: String) {
    object Indeterminate : TaskEvent("indeterminate")
    class Progress(val current: Long, val max: Long) : TaskEvent("progress")
    class Message(val msg: String) : TaskEvent("message")
    class Completed<T>(val value: T) : TaskEvent("completed")
}

sealed class WsOut(val kind: String) {
    class TaskProgress(val taskId: String, val event: TaskEvent) : WsOut("progress")
}