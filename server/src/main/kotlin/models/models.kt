package models

data class Project(val name: String, val binaries: List<Binary>)

data class Binary(val name: String)
