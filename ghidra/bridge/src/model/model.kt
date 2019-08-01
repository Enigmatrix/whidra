package model

data class Repository(val name: String, val binaries: List<Binary>)

data class Binary(val name: String/*, val iconType: IconType*/)