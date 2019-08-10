package util
enum class ParamType {
    QUERY, FORM, FILE, BINARY
}
class ParamException(param: String, type: ParamType = ParamType.FORM) : Throwable("`$param` ${type.toString().toLowerCase()} field should not be undefined") { }
