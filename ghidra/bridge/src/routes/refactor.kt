package routes

import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import io.ktor.application.call
import io.ktor.features.NotFoundException
import io.ktor.response.respond
import io.ktor.routing.Route
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.routing.route
import util.field


class RefactorService : Service() {

    fun renameVariable(repository: String, binary: String, fnAddr: Long?, fnName: String?, oldVarName: String, newVarName: String) {
        val fnRef = fnRef(fnAddr, fnName)
        editProgram(repository, binary, "Rename variable $oldVarName -> $newVarName in function $fnRef", TaskMonitor.DUMMY) { p ->
            val function = functionFrom(p, fnName, fnAddr)
            val variable = function.allVariables.find { it.name == oldVarName } ?: throw NotFoundException("Variable $oldVarName not found in $fnRef")
            variable.setName(newVarName, SourceType.USER_DEFINED)
        }
    }

    fun renameSymbol(repository: String, binary: String, oldSymName: String, newSymName: String) {
        editProgram(repository, binary, "Rename symbol $oldSymName -> $newSymName", TaskMonitor.DUMMY) { p ->
            val symbol = p.symbolTable.getSymbol(oldSymName)
            symbol.setName(newSymName, SourceType.USER_DEFINED)
        }
    }

    fun renameFunction(repository: String, binary: String, fnAddr: Long?, fnName: String?, newFnName: String) {
        val fnRef = fnRef(fnAddr, fnName)
        editProgram(repository, binary, "Rename variable $fnRef -> $newFnName", TaskMonitor.DUMMY) { p ->
            val function = functionFrom(p, fnName, fnAddr)
            function.setName(newFnName, SourceType.USER_DEFINED)
        }
    }

}

fun Route.routesFor(svc: RefactorService) {
    route("refactor") {
        route("rename") {
            post("variable") {
                val form = call.receiveForm()
                val repository = form.field("repository")
                val binary = form.field("binary")
                val fnAddr = form.maybeField("fnAddr")
                val fnName = form.maybeField("fnName")
                val oldVarName = form.field("oldVarName")
                val newVarName = form.field("newVarName")

                call.respond(svc.renameVariable(repository, binary, fnAddr?.toLong(), fnName, oldVarName, newVarName))
            }
            post("symbol") {
                val form = call.receiveForm()
                val repository = form.field("repository")
                val binary = form.field("binary")
                val oldSymName = form.field("oldSymName")
                val newSymName = form.field("newSymName")

                call.respond(svc.renameSymbol(repository, binary, oldSymName, newSymName))
            }
            post("function") {
                val form = call.receiveForm()
                val repository = form.field("repository")
                val binary = form.field("binary")
                val fnAddr = form.maybeField("fnAddr")
                val fnName = form.maybeField("fnName")
                val newFnName = form.field("newFnName")

                call.respond(svc.renameFunction(repository, binary, fnAddr?.toLong(), fnName, newFnName))
            }
        }
    }
}
