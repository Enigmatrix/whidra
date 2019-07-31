package tool

import ghidra.framework.data.CheckinHandler
import ghidra.program.model.listing.Program
import ghidra.util.Msg
import ghidra.util.exception.CancelledException
import ghidra.util.exception.VersionException
import ghidra.util.task.TaskMonitor
import util.RepositoryUtil
import java.io.IOException

object CommitProgramTool {
    fun commitProgram(repoName: String, program: Program, comment: String, monitor: TaskMonitor) {
        val repo = RepositoryUtil.repository(repoName)
        repo.connect()

        val df = program.domainFile
        when {
            df.canAddToRepository() -> try {
                df.addToVersionControl(comment, false, monitor)
                Msg.info(null, "REPORT: Added file to repository: " + df.pathname)
            } catch (e: IOException) {
                Msg.error(null, df.pathname + ": File check-in failed - " + e.message)
                throw e
            } catch (e: CancelledException) {
                // this can never happen because there is no user interaction in headless!
            }

            df.canCheckin() -> try {
                df.checkin(object : CheckinHandler {
                    @Throws(CancelledException::class)
                    override fun keepCheckedOut(): Boolean {
                        return true
                    }

                    @Throws(CancelledException::class)
                    override fun getComment(): String {
                        return comment
                    }

                    @Throws(CancelledException::class)
                    override fun createKeepFile(): Boolean {
                        return false
                    }
                }, true, monitor)
                Msg.info(null, "REPORT: Committed file changes to repository: " + df.pathname)
            } catch (e: IOException) {
                Msg.error(null, df.pathname + ": File check-in failed - " + e.message)
                throw e
            } catch (e: VersionException) {
                Msg.error(
                    null,
                    df.pathname + ": File check-in failed - version error occurred"
                )
            } catch (e: CancelledException) {
                // this can never happen because there is no user interaction in headless!
            }
            else -> Msg.error(null, df.pathname + ": Unable to commit file")
        }

        repo.disconnect()
    }
}