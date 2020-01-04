package models

data class Project(val name: String, val binaries: List<Binary>)

data class Binary(val name: String)

data class Function(val name: String, val signature: String, val addr: String, val inline: Boolean, val thunk: Boolean, val external: Boolean)

data class User(val name: String)

