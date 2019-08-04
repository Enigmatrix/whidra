package tool

import ghidra.util.Msg
import ghidra.util.task.TaskMonitorAdapter

class WhidraTaskMonitor(taskName: String) : TaskMonitorAdapter() {
    private var max: Long = 0
    private var taskName: String = taskName

    override fun initialize(max: Long) {
        this.max = max
        super.setMaximum(max)
    }

    override fun setMessage(msg: String?) {
        Msg.info(taskName, msg)
    }

    override fun setProgress(value: Long) {
        Msg.info(taskName, "Progress set to: $value/$max")
    }

    override fun incrementProgress(incrementAmount: Long) {
        // Msg.info(taskName, "Increment progress by: $incrementAmount")
    }
}