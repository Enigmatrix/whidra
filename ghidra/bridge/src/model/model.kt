package model

data class Asm(val line: String, val addr: Long)

data class Data(val value: String, val addr: Long)

data class Function(val name: String, val addr: Long, val signature: String)

data class Repository(val name: String, val binaries: List<Binary>)

data class Binary(val name: String/*, val iconType: IconType*/)

sealed class Event(val kind: String) {
    object Indeterminate : Event("indeterminate")
    class Progress(val current: Long, val max: Long) : Event("progress")
    class Message(val msg: String) : Event("message")
    class Completed<T>(val value: T) : Event("completed")
}
