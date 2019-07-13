// Copyright (C) 2019 Guillaume Valadon <guillaume@valadon.net>
// This program is published under a GPLv2 license

/*
 * Decompile a function with Ghidra
 *
 * analyzeHeadless . Test.gpr -import $BINARY_NAME -postScript GhidraDecompiler.java $FUNCTION_ADDRESS -deleteProject -noanalysis
 *
 * ./support/analyzeHeadless ghidra://localhost/<PROJECT> -process '' -postScript /opt/ghidra/custom_scripts/GhidraDecompiler.java 400984 -p -readonly
 *
*/

import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompileProcess;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.LimitedByteBuffer;
import ghidra.app.decompiler.PrettyPrinter;
import ghidra.app.decompiler.component.DecompilerUtils;

import ghidra.app.util.headless.HeadlessScript;
import ghidra.util.task.TaskMonitor;


import ghidra.program.model.lang.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.*;

import java.io.*;

import java.util.ArrayList;
import com.google.gson.*;
import java.lang.reflect.*;
import java.io.*;

public class GhidraDecompiler extends HeadlessScript {
  @Override
  public void run() throws Exception {

    // Stop after this headless script
    setHeadlessContinuationOption(HeadlessContinuationOption.ABORT);

    // Get the function address from the script arguments
    String[] args = getScriptArgs();
    println(String.format("Array length: %d", args.length)); // DEBUG

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
    println(String.format("Address: %x", functionAddress)); // DEBUG

    DecompInterfaceWithStream di = new DecompInterfaceWithStream();
    println("Simplification style: " + di.getSimplificationStyle()); // DEBUG
    println("Debug enables: " + di.debugEnabled());

    Function f = this.getFunction(functionAddress);
    if (f == null) {
      System.err.println(String.format("Function not found at 0x%x", functionAddress));
      return;
    }

    println(String.format("Decompiling %s() at 0x%x", f.getName(), functionAddress));

    println("Program: " + di.openProgram(f.getProgram())); // DEBUG

    // Decompile with a 5-seconds timeout
    println("DECOMP RESULT START");
    di.decompileFunctionXML(f, 5, null);
    println("DECOMP RESULT END");
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


  private class DecompInterfaceWithStream extends DecompInterface {
    /**
     * Decompile function
     * @param func function to be decompiled
     * @param timeoutSecs if decompile does not complete in this time a null value
     * will be returned and a timeout error set.
     * @param monitor optional task monitor which may be used to cancel decompile
     * @return decompiled function text
     * @throws CancelledException operation was cancelled via monitor
     */
    public synchronized void decompileFunctionXML(Function func, int timeoutSecs,
      TaskMonitor monitor) {

      decompileMessage = "";
      if (monitor != null && monitor.isCancelled()) {
        return;
      }

      LimitedByteBuffer res = null;
      if (monitor != null) {
        monitor.addCancelledListener(monitorListener);
      }

      if (program == null) {
        return;
      }

      try {
        Address funcEntry = func.getEntryPoint();
        decompCallback.setFunction(func, funcEntry, null);
        String addrstring = Varnode.buildXMLAddress(funcEntry);
        verifyProcess();
        res =
          decompProcess.sendCommand1ParamTimeout("decompileAt", addrstring.toString(),
            timeoutSecs);
        decompileMessage = decompCallback.getNativeMessage();
      }
      catch (Exception ex) {
        decompileMessage = "Exception while decompiling " +func.getEntryPoint() + ": "+ ex.getMessage() + '\n';
      }
      finally {
        if (monitor != null) {
          monitor.removeCancelledListener(monitorListener);
        }
      }

      DecompileProcess.DisposeState processState;
      if (decompProcess != null) {
        processState = decompProcess.getDisposeState();
        if (decompProcess.getDisposeState() == DecompileProcess.DisposeState.NOT_DISPOSED) {
          flushCache();
        }
      }
      else {
        processState = DecompileProcess.DisposeState.DISPOSED_ON_CANCEL;
      }

      InputStream stream = null;
      if (res != null)
        stream = res.getInputStream();
      dumpResults(stream);
    }

    private void dumpResults(InputStream stream) {
      if (stream == null) {
        return;
      }
      try {
        System.out.write(stream.readAllBytes());
        System.out.flush();
        System.out.close();
      }
      catch (IOException e) {
        e.printStackTrace();
      }
    }
  }
}
