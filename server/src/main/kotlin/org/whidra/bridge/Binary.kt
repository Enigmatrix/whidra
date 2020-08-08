package org.whidra.bridge

import ghidra.program.flatapi.FlatProgramAPI
import ghidra.program.model.listing.*

class Binary(val program: Program) {
    val api = FlatProgramAPI(program)

}