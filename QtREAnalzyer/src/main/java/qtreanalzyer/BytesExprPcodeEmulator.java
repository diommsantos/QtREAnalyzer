/*
 * Code taken from the GhidraDocs/GhidraClass/Debugger/ghidra_scripts/ModelingScript.java
 * Only the {@link ExprPcodeArithmetic} and {@link ExprSpace#whenNull(long, int)} method in ExprSpace 
 * were modified.
 */

package qtreanalzyer;

import java.math.BigInteger;
import java.util.*;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.tuple.Pair;

import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.emu.auxiliary.AuxEmulatorPartsFactory;
import ghidra.pcode.emu.auxiliary.AuxPcodeEmulator;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

interface Expr {
}

interface UnExpr extends Expr {
	Expr u();
}

interface BinExpr extends Expr {
	Expr l();

	Expr r();
}

record LitExpr(BigInteger val, int size) implements Expr {
}

record VarExpr(Varnode vn) implements Expr {
	public VarExpr(AddressSpace space, long offset, int size) {
		this(space.getAddress(offset), size);
	}

	public VarExpr(Address address, int size) {
		this(new Varnode(address, size));
	}
}

record InvExpr(Expr u) implements UnExpr {
}

record AddExpr(Expr l, Expr r) implements BinExpr {
}

record SubExpr(Expr l, Expr r) implements BinExpr {
}

record MultExpr(Expr l, Expr r) implements BinExpr {
}

record AndExpr(Expr l, Expr r) implements BinExpr {
}

// ----------------------

enum ExprPcodeArithmetic implements PcodeArithmetic<Expr> {
	BE(Endian.BIG), LE(Endian.LITTLE);

	public static ExprPcodeArithmetic forEndian(Endian endian) {
		return endian.isBigEndian() ? BE : LE;
	}

	public static ExprPcodeArithmetic forLanguage(Language language) {
		return language.isBigEndian() ? BE : LE;
	}

	private final Endian endian;

	private ExprPcodeArithmetic(Endian endian) {
		this.endian = endian;
	}

	@Override
	public Endian getEndian() {
		return endian;
	}

	@Override
	public Expr unaryOp(int opcode, int sizeout, int sizein1, Expr in1) {
		return switch (opcode) {
			case PcodeOp.COPY -> in1;
			case PcodeOp.INT_SEXT -> in1;
			case PcodeOp.INT_NEGATE -> new InvExpr(in1);
			case PcodeOp.BOOL_NEGATE -> in1;
			case PcodeOp.POPCOUNT -> in1;
			default -> in1;
			//default -> throw new UnsupportedOperationException(PcodeOp.getMnemonic(opcode));
		};
	}

	@Override
	public Expr binaryOp(int opcode, int sizeout, int sizein1, Expr in1, int sizein2,
			Expr in2) {
		return switch (opcode) {
			case PcodeOp.INT_EQUAL -> new LitExpr(BigInteger.valueOf(1), sizeout);
			case PcodeOp.INT_SLESS -> new LitExpr(BigInteger.valueOf(1), sizeout);
			case PcodeOp.INT_LESS -> new LitExpr(BigInteger.valueOf(1), sizeout);
			case PcodeOp.INT_ADD -> new AddExpr(in1, in2);
			case PcodeOp.INT_SUB -> new SubExpr(in1, in2);
			case PcodeOp.INT_CARRY -> new LitExpr(BigInteger.valueOf(1), sizeout);
			case PcodeOp.INT_SCARRY -> new LitExpr(BigInteger.valueOf(1), sizeout);
			case PcodeOp.INT_SBORROW -> new LitExpr(BigInteger.valueOf(1), sizeout);
			case PcodeOp.INT_AND -> new AndExpr(in1, in2);
			case PcodeOp.INT_MULT -> new MultExpr(in1, in2);
			case PcodeOp.BOOL_OR -> new LitExpr(BigInteger.valueOf(1), sizeout);
			default -> new LitExpr(BigInteger.valueOf(1), sizeout);
			//default -> throw new UnsupportedOperationException(PcodeOp.getMnemonic(opcode));
		};
	}

	@Override
	public Expr modBeforeStore(int sizeout, int sizeinAddress, Expr inAddress, int sizeinValue,
			Expr inValue) {
		return inValue;
	}

	@Override
	public Expr modAfterLoad(int sizeout, int sizeinAddress, Expr inAddress, int sizeinValue,
			Expr inValue) {
		return inValue;
	}

	@Override
	public Expr fromConst(byte[] value) {
		if (endian.isBigEndian()) {
			return new LitExpr(new BigInteger(1, value), value.length);
		}
		byte[] reversed = Arrays.copyOf(value, value.length);
		ArrayUtils.reverse(reversed);
		return new LitExpr(new BigInteger(1, reversed), reversed.length);
	}

	@Override
	public Expr fromConst(BigInteger value, int size, boolean isContextreg) {
		return new LitExpr(value, size);
	}

	@Override
	public Expr fromConst(long value, int size) {
		return fromConst(BigInteger.valueOf(value), size);
	}

	@Override
	public byte[] toConcrete(Expr value, Purpose purpose) {
		throw new UnsupportedOperationException();
	}

	@Override
	public long sizeOf(Expr value) {
		throw new UnsupportedOperationException();
	}
}

// ----------------------
/**
 * {@link ExprSpace#whenNull(long, int)} was modified
 */
class ExprSpace {
	protected final NavigableMap<Long, Expr> map;
	protected final AddressSpace space;

	protected ExprSpace(AddressSpace space, NavigableMap<Long, Expr> map) {
		this.space = space;
		this.map = map;
	}

	public ExprSpace(AddressSpace space) {
		this(space, new TreeMap<>());
	}

	public void clear() {
		map.clear();
	}

	public void set(long offset, Expr val) {
		// TODO: Handle overlaps / offcut gets and sets
		map.put(offset, val);
	}

	public Expr get(long offset, int size) {
		// TODO: Handle overlaps / offcut gets and sets
		Expr expr = map.get(offset);
		return expr != null ? expr : whenNull(offset, size);
	}

	protected Expr whenNull(long offset, int size) {
		return new LitExpr(BigInteger.valueOf(offset), size); //only line modified in the code
	}
}

abstract class AbstractBytesExprPcodeExecutorStatePiece<S extends ExprSpace>
		extends
		AbstractLongOffsetPcodeExecutorStatePiece<byte[], Expr, S> {

	protected final AbstractSpaceMap<S> spaceMap = newSpaceMap();

	public AbstractBytesExprPcodeExecutorStatePiece(Language language) {
		super(language, BytesPcodeArithmetic.forLanguage(language),
			ExprPcodeArithmetic.forLanguage(language));
	}

	protected abstract AbstractSpaceMap<S> newSpaceMap();

	@Override
	public MemBuffer getConcreteBuffer(Address address, Purpose purpose) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void clear() {
		for (S space : spaceMap.values()) {
			space.clear();
		}
	}

	@Override
	protected S getForSpace(AddressSpace space, boolean toWrite) {
		return spaceMap.getForSpace(space, toWrite);
	}

	@Override
	protected void setInSpace(ExprSpace space, long offset, int size, Expr val) {
		space.set(offset, val);
	}

	@Override
	protected Expr getFromSpace(S space, long offset, int size, Reason reason) {
		return space.get(offset, size);
	}

	@Override
	protected Map<Register, Expr> getRegisterValuesFromSpace(S s, List<Register> registers) {
		throw new UnsupportedOperationException();
	}
}

class ExprPcodeExecutorStatePiece
		extends AbstractBytesExprPcodeExecutorStatePiece<ExprSpace> {
	public ExprPcodeExecutorStatePiece(Language language) {
		super(language);
	}

	@Override
	protected AbstractSpaceMap<ExprSpace> newSpaceMap() {
		return new SimpleSpaceMap<ExprSpace>() {
			@Override
			protected ExprSpace newSpace(AddressSpace space) {
				return new ExprSpace(space);
			}
		};
	}
}

class BytesExprPcodeExecutorState extends PairedPcodeExecutorState<byte[], Expr> {
	public BytesExprPcodeExecutorState(PcodeExecutorStatePiece<byte[], byte[]> concrete) {
		super(new PairedPcodeExecutorStatePiece<>(concrete,
			new ExprPcodeExecutorStatePiece(concrete.getLanguage())));
	}
}

// ----------------------

enum BytesExprEmulatorPartsFactory implements AuxEmulatorPartsFactory<Expr> {
	INSTANCE;

	@Override
	public PcodeArithmetic<Expr> getArithmetic(Language language) {
		return ExprPcodeArithmetic.forLanguage(language);
	}

	@Override
	public PcodeUseropLibrary<Pair<byte[], Expr>> createSharedUseropLibrary(
			AuxPcodeEmulator<Expr> emulator) {
		return PcodeUseropLibrary.nil();
	}

	@Override
	public PcodeUseropLibrary<Pair<byte[], Expr>> createLocalUseropStub(
			AuxPcodeEmulator<Expr> emulator) {
		return PcodeUseropLibrary.nil();
	}

	@Override
	public PcodeUseropLibrary<Pair<byte[], Expr>> createLocalUseropLibrary(
			AuxPcodeEmulator<Expr> emulator, PcodeThread<Pair<byte[], Expr>> thread) {
		return PcodeUseropLibrary.nil();
	}

	@Override
	public PcodeExecutorState<Pair<byte[], Expr>> createSharedState(
			AuxPcodeEmulator<Expr> emulator, BytesPcodeExecutorStatePiece concrete) {
		return new BytesExprPcodeExecutorState(concrete);
	}

	@Override
	public PcodeExecutorState<Pair<byte[], Expr>> createLocalState(
			AuxPcodeEmulator<Expr> emulator, PcodeThread<Pair<byte[], Expr>> thread,
			BytesPcodeExecutorStatePiece concrete) {
		return new BytesExprPcodeExecutorState(concrete);
	}
}

public class BytesExprPcodeEmulator extends AuxPcodeEmulator<Expr> {
	public BytesExprPcodeEmulator(Language language) {
		super(language);
	}

	@Override
	protected AuxEmulatorPartsFactory<Expr> getPartsFactory() {
		return BytesExprEmulatorPartsFactory.INSTANCE;
	}
}