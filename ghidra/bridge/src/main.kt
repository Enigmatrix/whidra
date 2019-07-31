import ghidra.GhidraJarApplicationLayout
import ghidra.framework.Application
import ghidra.framework.HeadlessGhidraApplicationConfiguration
import tool.*
import util.RepositoryUtil.initServer


fun main() {
    init()
    val monitor = WhidraTaskMonitor()
    val program = ImportBinaryTool.importBinary("testRepo", "bins/heapschool", monitor)
    AutoAnalysisTool.analyzeProgram(program, monitor)
    DisassemblerTool.disassemble(program, 0x400e05)
    CommitProgramTool.commitProgram("testRepo", program, "Add ${program.name} to version control", monitor)
}

fun init() {
    if (!Application.isInitialized())
        Application.initializeApplication(
            GhidraJarApplicationLayout(),
            HeadlessGhidraApplicationConfiguration()
        )

    initServer()
}


