// Copyright (C) 2019 Guillaume Valadon <guillaume@valadon.net>
// This program is published under a GPLv2 license

/*
 * Decompile a function with Ghidra
 *
 * analyzeHeadless ghidra://whidra.hats.sg/<project name> -process '<process>' -postScript FunctionListing.java -readonly -noanalysis
 *
*/

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.app.util.headless.HeadlessScript;

public class FunctionListing extends HeadlessScript {

	@Override
	public void run() throws Exception {
		// Find and print found functions
		Listing listing = currentProgram.getListing();
		FunctionIterator iter = listing.getFunctions(true);
		while (iter.hasNext() && !monitor.isCancelled()) {
			Function f = iter.next();
			if (f.isExternal()) {
				continue;
			}
			/*
			 * Let's consider already labeled functions
			String fName = f.getName();
			if (!fName.startsWith("FUN_")) {
				continue;
			}
			*/
			Address entry = f.getEntryPoint();
			if (entry != null) {
				System.out.printf("%s\t0x%x\n", f.getName(), entry.getOffset());
			}
		}
		setHeadlessContinuationOption(HeadlessContinuationOption.ABORT_AND_DELETE);

	}

}
