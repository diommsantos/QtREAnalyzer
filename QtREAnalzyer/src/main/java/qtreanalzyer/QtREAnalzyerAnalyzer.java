/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package qtreanalzyer;

import java.util.Iterator;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class QtREAnalzyerAnalyzer extends AbstractAnalyzer {
	
	boolean analyzed = false;
	
	static MessageLog messageLog;
	
	public QtREAnalzyerAnalyzer() {

		// TODO: Name the analyzer and give it a description.

		super("QtREAnalyzer", "An analyzer to reverse engineer Qt binaries.", AnalyzerType.DATA_ANALYZER);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {

		// TODO: Return true if analyzer should be enabled by default

		return false;
	}

	@Override
	public boolean canAnalyze(Program program) {

		// TODO: Examine 'program' to determine of this analyzer should analyze it.  Return true
		// if it can.

		return true;
	}

	@Override
	public void registerOptions(Options options, Program program) {

		// TODO: If this analyzer has custom options, register them here

		//options.registerOption("Option name goes here", false, null,
		//	"Option description goes here");
	}
	
	@Override
	public void analysisEnded(Program program) {
		analyzed = false;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		if(analyzed)
			return true;
		messageLog = log;
		SymbolTable symbolTable = program.getSymbolTable();
		QtTypesManager qtTypesManager = new QtTypesManager(program);
		Iterator<GhidraClass> classNamespacesIterator = symbolTable.getClassNamespaces();
		initializeTaskMonitor(monitor, symbolTable);
		while(classNamespacesIterator.hasNext()) {
			QtClass ghidraClass = new QtClass(classNamespacesIterator.next());
			if(ghidraClass.isQtClass())
				ghidraClass.solve();
			monitor.incrementProgress();
		}
		return (analyzed = true);
	}
	
	public static MessageLog getMessageLog() {
		return messageLog;
	}
	
	private void initializeTaskMonitor(TaskMonitor monitor, SymbolTable symbolTable) {
		Iterator<GhidraClass> classNamespacesIterator = symbolTable.getClassNamespaces();
		int i = 0;
		for ( ; classNamespacesIterator.hasNext() ; ++i ) classNamespacesIterator.next();
		monitor.initialize(i);
	}
}
