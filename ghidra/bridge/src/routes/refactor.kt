package routes

import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import io.ktor.features.NotFoundException


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
