// Copyright (C) 2019 Guillaume Valadon <guillaume@valadon.net>
// This program is published under a GPLv2 license

/*
 * Disassemble a function with Ghidra
 *
 * analyzeHeadless . Test.gpr -import $BINARY_NAME -postScript GhidraDisassembler.java $FUNCTION_ADDRESS -deleteProject
 *
 * ./support/analyzeHeadless ghidra://localhost/<PROJECT> -process '' -postScript /opt/ghidra/custom_scripts/GhidraDisassembler.java 400984 -p -readonly
 *
*/

import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoFlowProcessor;
import ghidra.app.util.PseudoInstruction;

import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;

import ghidra.app.util.headless.HeadlessScript;
import ghidra.util.task.TaskMonitor;

import java.io.*;

import java.util.ArrayList;

public class GhidraDisassembler extends HeadlessScript {

  @Override
  public void run() throws Exception {

    // Stop after this headless script
    setHeadlessContinuationOption(HeadlessContinuationOption.ABORT);

    // Get the function address from the script arguments
    String[] args = getScriptArgs();

    if (args.length == 0) {
      System.err.println("Please specify a function address!");
      System.err.println("Note: use c0ffe instead of 0xcoffee");
      return;
    }

    int functionAddress;
    try {
      functionAddress = Integer.parseInt(args[0], 16);
    }
    catch (NumberFormatException e) {
      System.err.println(String.format("Invalid hex address: %s", args[0]));
      return;
    }

    Function f = this.getFunction(functionAddress);
    if (f == null) {
      System.err.println(String.format("Function not found at 0x%x", functionAddress));
      return;
    }

    PseudoDisassembler pdis = new PseudoDisassembler(getCurrentProgram());
    pdis.followSubFlows(f.getEntryPoint(), 4000, new PseudoFlowProcessor() {
        @Override
        public boolean followFlows(PseudoInstruction instr) {
            return true;
        }

        @Override
        public boolean process(PseudoInstruction instr) {
            if (instr == null) {
                return false;
            }
            FlowType ftype = instr.getFlowType();
            if (ftype.isTerminal()) {
                if (instr.getMnemonicString().compareToIgnoreCase("ret") == 0) {
                    return false;
                    // Scalar scalar = instr.getScalar(0);
                    // if (scalar != null) {
                    //     return false;
                    // }
                }
            }
            
            println(String.format("%s: %s", instr.getAddress(), instr));
            return true;
        }
    });
  }

  protected Function getFunction(int address) {
    // Logic from https://github.com/cea-sec/Sibyl/blob/master/ext/ghidra/ExportFunction.java

    Listing listing = currentProgram.getListing();
    FunctionIterator iter = listing.getFunctions(true);
    while (iter.hasNext() && !monitor.isCancelled()) {
      Function f = iter.next();
      if (f.isExternal()) {
        continue;
      }

      Address entry = f.getEntryPoint();
      if (entry != null && entry.getOffset() == address) {
        return f;
      }
    }
    return null;
  }
}