package org.whidra.model

data class Repository(val name: String, val binaries: List<Binary>)

data class Binary(val name: String)

data class Function(val name: String, val signature: String, val addr: String, val inline: Boolean, val thunk: Boolean, val external: Boolean)

data class User(val name: String)

enum class OpPartType(val p: Int) {
    Char(1),
    Register(2),
    Label(3),
    Variable(4),
    Scalar(5),
    Unknown(6)
}

data class OpPart(val value: Any, val type: OpPartType)

data class Comments(val pre: String?, val post: String?, val inline: String?, val eol: String?, val repeat: String?)

sealed class ListingField(val kind: String, val addr: String, val comments: Comments) {
    class Instruction(
        val mnemonic: String,
        val operands: List<List<OpPart>>,
        addr: String,
        comments: Comments) : ListingField("instr", addr, comments)

    class Data(
        val type: String,
        val value: String,
        addr: String,
        comments: Comments) : ListingField("data", addr, comments)
}