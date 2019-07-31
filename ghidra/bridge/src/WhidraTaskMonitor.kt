import ghidra.util.task.TaskMonitorAdapter
import ghidra.util.Msg
import ghidra.util.exception.CancelledException

class WhidraTaskMonitor : TaskMonitorAdapter() {
    var max: Long = 0

    override fun initialize(max: Long) {
        this.max = max
        super.setMaximum(max)
    }

    override fun setMessage(msg: String?) {
        Msg.info(this, msg)
    }

    override fun setProgress(value: Long) {
        Msg.info(this, "Progress set to: $value/$max")
    }

    override fun incrementProgress(incrementAmount: Long) {
        // Msg.info(this, "Increment progress by: $incrementAmount")
    }
}