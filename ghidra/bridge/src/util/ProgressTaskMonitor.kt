package util

import ghidra.util.task.TaskMonitorAdapter
import kotlinx.coroutines.channels.Channel
import routes.Progress

class ProgressTaskMonitor : TaskMonitorAdapter() {
    private var max = 0L
    val progress = Channel<Progress>()

    override fun initialize(max: Long) {
        this.max = max
        super.setMaximum(max)
    }

    override fun setMessage(msg: String?) {
        if(msg != null)
            progress.offer(Progress.Message(msg))
    }

    override fun setProgress(value: Long) {
        progress.offer(Progress.Value(value, max))
    }

    override fun setIndeterminate(indeterminate: Boolean) {
        if(indeterminate)
            progress.offer(Progress.Indeterminate)
    }
}