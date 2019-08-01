package tool

import ghidra.app.util.PseudoDisassembler
import ghidra.app.util.PseudoFlowProcessor
import ghidra.app.util.PseudoInstruction
import ghidra.program.model.listing.CodeUnitFormat
import ghidra.program.model.listing.CodeUnitFormatOptions
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program

object DisassemblerTool {
    fun disassemble(program: Program, functionAddress: Int) {
        val f = this.getFunction(program, functionAddress);
        if (f == null) {
            System.err.println(String.format("Function not found at 0x%x", functionAddress));
            return;
        }

        val pDis = PseudoDisassembler(program);
        pDis.followSubFlows(f.entryPoint, 4000, object : PseudoFlowProcessor {
            override fun followFlows(instr: PseudoInstruction?): Boolean {
                return true;
            }

            override fun process(instr: PseudoInstruction?): Boolean {
                val formatter =
                    CodeUnitFormat(CodeUnitFormatOptions.ShowBlockName.NEVER, CodeUnitFormatOptions.ShowNamespace.NEVER)

                if (instr == null) {
                    return false;
                }
                val fType = instr.flowType;
                if (fType.isTerminal) {
                    if (instr.mnemonicString.compareTo("ret", true) == 0) {
                        return false;
                    }
                }

                println(String.format("%s: %s", instr.address, formatter.getRepresentationString(instr)));
                return true;
            }
        });
    }

    private fun getFunction(program: Program, address: Int): Function? {
        val listing = program.listing
        val iterator = listing.getFunctions(true);
        while (iterator.hasNext()) {
            val f = iterator.next();
            if (f.isExternal) {
                continue;
            }

            val entry = f.entryPoint;
            if (entry != null && entry.offset == address.toLong()) {
                return f;
            }
        }
        return null;
    }
}