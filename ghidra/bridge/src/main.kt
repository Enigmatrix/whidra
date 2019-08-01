import ghidra.GhidraJarApplicationLayout
import ghidra.framework.Application
import ghidra.framework.HeadlessGhidraApplicationConfiguration
import ghidra.util.Msg
import tool.*
import util.RepositoryUtil.initServer


fun main() {
    init()

    Msg.info("Main", "Start: Import Binary")
    val program = ImportBinaryTool.importBinary("testRepo", "bins/heapschool", WhidraTaskMonitor("Import Binary"))
    Msg.info("Main>", "End: Import Binary")

    Msg.info("Main", "Start: Analyze Program")
    AutoAnalysisTool.analyzeProgram(program, WhidraTaskMonitor("Analyze Program"))
    Msg.info("Main", "End: Analyze Program")

    Msg.info("Main", "Start: Disassemble")
    DisassemblerTool.disassemble(program, 0x400e05)
    Msg.info("Main", "End: Disassemble")

    Msg.info("Main", "Start: Commit Program")
    CommitProgramTool.commitProgram(
        "testRepo",
        program,
        "Add ${program.name} to version control",
        WhidraTaskMonitor("Commit Program")
    )
    Msg.info("Main", "End: Commit Program")
}

fun init() {
    if (!Application.isInitialized())
        Application.initializeApplication(
            GhidraJarApplicationLayout(),
            HeadlessGhidraApplicationConfiguration()
        )

    initServer()
}


