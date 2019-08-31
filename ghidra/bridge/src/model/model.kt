package model


enum class OpPartType(val p: Int) {
    Char(1),
    Register(2),
    Label(3),
    Variable(4),
    Scalar(5),
    Unknown(6)
}
data class OpPart(val value: Any, val type: OpPartType)

data class Instruction(val addr: Long, val mnemonic: String, val operands: List<List<OpPart>>)

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
