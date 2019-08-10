package model

sealed class WsIncomingMessage(val kind: String) {
    class Cancel(val taskId: String) : WsIncomingMessage("cancel")
}

sealed class WsOutgoingMessage(val kind: String) {
    class Progress(val taskId: String, val event: Event) : WsOutgoingMessage("progress")
}
