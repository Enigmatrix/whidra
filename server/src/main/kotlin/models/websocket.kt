package models


sealed class WsOut(val kind: String) {
    class Progress(val taskId: String, val event: Event) : WsOut("progress")
}