package models

data class Project(val name: String, val binaries: List<Binary>)

data class Binary(val name: String)


sealed class Event(val kind: String) {
    object Indeterminate : Event("indeterminate")
    class Progress(val current: Long, val max: Long) : Event("progress")
    class Message(val msg: String) : Event("message")
    class Completed<T>(val value: T) : Event("completed")
}