
"""
Collections of eBPF instructions
"""

import abc
from typing import (
    Any,
    ClassVar,
    Mapping,
    Optional,
    Protocol,
    Tuple,
    Union,
    cast,
)

import bitstring
from pyvex.lifting.util import Instruction, Type, JumpKind, VexValue

REGISTER_TYPE = cast(str, Type.int_64)

BPF_CALL_STACK_BASE = 0x100000
BPF_EXIT_SENTINEL = 0x100100
BPF_CALLER_SAVE_BASE = 0x100200
BPF_CALLER_SAVE_FRAME_SIZE = 80
BPF_STACK_FRAME_SIZE = 512

SKB_DATA_OFFSET = 76
SKB_DATA_END_OFFSET = 80

class InstructionProtocol(Protocol):
    """Typing helper representing an Instruction"""

    data: Union[Mapping[str, str], Any]

    @property
    def name(self) -> str:
        ...

    def get(self, reg: Union[int, str], typ: Any) -> VexValue:
        ...

    def put(self, val: VexValue, reg: Union[int, str]) -> None:
        ...

    def load(self, addr: VexValue, ty: str) -> VexValue:
        ...

    def store(self, val: VexValue, addr: VexValue) -> None:
        ...

    def constant(self, val: int, typ: Any) -> VexValue:
        ...

    def fetch_operands(self) -> Tuple[VexValue, ...]:
        ...

    def jump(
        self, condition: Optional[VexValue], to_addr: VexValue, jumpkind: str = ...
    ) -> None:
        ...

class EBPFInstruction(Instruction, abc.ABC):
    """Base Instruction for eBPF"""

    src_reg_bin: ClassVar[str] = "0" * 4
    dest_reg_bin: ClassVar[str] = "0" * 4
    offset_bin: ClassVar[str] = "0" * 16
    immediate_bin: ClassVar[str] = "0" * 32

    @property
    @abc.abstractmethod
    def opcode_bin(self) -> str:
        ...

    @property
    def bin_format(self) -> str:
        ret = "".join(
            (
                self.opcode_bin,
                self.src_reg_bin,
                self.dest_reg_bin,
                self.offset_bin,
                self.immediate_bin,
            )
        )
        return ret

class WithDestRegProtocol(Protocol):
    """Typing helper for classes implementing WithDestReg"""

    @property
    def dest_reg(self: InstructionProtocol) -> int:
        ...

class WithDestReg:
    """Mixin to parse the destination register"""

    dest_reg_bin = "dddd"

    @property
    def dest_reg(self: InstructionProtocol) -> int:
        return int(self.data["d"], 2)

class InstructionWithDestRegProtocol(
    WithDestRegProtocol, InstructionProtocol, Protocol
):
    """Typing helper for classes implementing WithDestReg and Instruction"""

class WithSrcRegProtocol(Protocol):
    """Typing helper for classes implementing WithSrcReg"""

    @property
    def src_reg(self: InstructionProtocol) -> int:
        ...

class WithSrcReg:
    """Mixin to parse the source register"""

    src_reg_bin = "ssss"

    @property
    def src_reg(self: InstructionProtocol) -> int:
        return int(self.data["s"], 2)

class InstructionWithSrcRegProtocol(WithSrcRegProtocol, InstructionProtocol, Protocol):
    """Typing helper for classes implementing WithSrcReg and Instruction"""

class WithOffsetProtocol(Protocol):
    """Typing helper for classes implementing WithOffset"""

    @property
    def offset(self: InstructionProtocol) -> int:
        ...

class WithOffset:
    """Mixin to parse the offset"""

    offset_bin = "o" * 16

    @property
    def offset(self: InstructionProtocol) -> int:
        raw = self.data["o"]
        return bitstring.Bits(bin=raw).intle

class WithImmediateProtocol(Protocol):
    """Typing helper for classes implementing WithImmediate"""

    immediate_bin: ClassVar[str]

    @property
    def immediate(self) -> int:
        ...

class WithImmediate:
    """Mixin to parse the immediate value"""

    immediate_bin = "i" * 32

    @property
    def immediate(self: InstructionProtocol) -> int:
        raw = self.data["i"]
        return bitstring.Bits(bin=raw).intle

class InstructionWithImmediateProtocol(
    WithImmediateProtocol, InstructionProtocol, Protocol
):
    """Typing helper for classes implementing WithImmediate and Instruction"""

class ArithmeticOrJumpInstruction(EBPFInstruction, abc.ABC):
    """Base Instruction for ALU or jumps"""

    @property
    @abc.abstractmethod
    def class_bin(self) -> str:
        ...

    @property
    @abc.abstractmethod
    def source_bin(self) -> str:
        ...

    @property
    @abc.abstractmethod
    def operation_bin(self) -> str:
        ...

    @property
    def opcode_bin(self) -> str:
        return self.operation_bin + self.source_bin + self.class_bin

class ALUInstructionProtocol(WithDestRegProtocol, InstructionProtocol, Protocol):
    """Typing helper for classes implementing WithDestReg and Instruction"""

    @property
    def size(self) -> str:
        ...

    @property
    def size_name(self) -> str:
        ...

    @property
    def operation_name(self) -> str:
        ...

    @property
    def source_name(self) -> str:
        ...

class ALUInstruction(WithDestReg, ArithmeticOrJumpInstruction):
    """Base Instruction for ALU computations"""

    @property
    @abc.abstractmethod
    def size(self) -> str:
        ...

    @property
    @abc.abstractmethod
    def size_name(self) -> str:
        ...

    @property
    @abc.abstractmethod
    def operation_name(self) -> str:
        ...

    @property
    @abc.abstractmethod
    def source_name(self) -> str:
        ...

    @property
    def name(self) -> str:
        return f"{self.operation_name}{self.size_name}_{self.source_name}"

    def commit_result(self: ALUInstructionProtocol, res: VexValue) -> None:
        assert res.ty == self.size
        self.put(res, self.dest_reg)

class JumpInstruction(ArithmeticOrJumpInstruction):
    """Base Instruction for jumps"""

class LoadOrStoreInstruction(WithDestReg, EBPFInstruction, abc.ABC):
    """Base Instruction for load or store"""

    @property
    @abc.abstractmethod
    def class_bin(self) -> str:
        ...

    @property
    @abc.abstractmethod
    def mode_bin(self) -> str:
        ...

    @property
    @abc.abstractmethod
    def width_bin(self) -> str:
        ...

    @property
    @abc.abstractmethod
    def width_name(self) -> str:
        ...

    @property
    def opcode_bin(self) -> str:
        return self.mode_bin + self.width_bin + self.class_bin

class LoadNonStandardInstruction(LoadOrStoreInstruction):
    """Base Instruction for non standard loads"""

    class_bin = "000"

class LoadInRegisterInstruction(LoadOrStoreInstruction):
    """Base Instruction for loads into registers"""

    class_bin = "001"

class StoreImmediateInstruction(LoadOrStoreInstruction):
    """Base Instruction for store from immediate value"""

    class_bin = "010"

class StoreFromRegisterInstruction(LoadOrStoreInstruction):
    """Base Instruction for store from registers"""

    class_bin = "011"

class ALU32Instruction(ALUInstruction):
    """Base Instruction for 32bits ALU"""

    class_bin = "100"
    size = cast(str, Type.int_32)
    size_name = "32"

    def commit_result(self: ALUInstructionProtocol, res: VexValue) -> None:
        assert res.ty == self.size
        res64 = res.widen_unsigned(REGISTER_TYPE)
        self.put(res64, self.dest_reg)

class Jump64Instruction(JumpInstruction):
    """Base Instruction for 64bits jumps"""

    class_bin = "101"
    size = cast(str, Type.int_64)
    size_name = "64"

class Jump32Instruction(JumpInstruction):
    """Base Instruction for 32bits jumps"""

    class_bin = "110"
    size = cast(str, Type.int_32)
    size_name = "32"

class ALU64Instruction(ALUInstruction):
    """Base Instruction for 64bits ALU"""

    class_bin = "111"
    size = cast(str, Type.int_64)
    size_name = "64"

class ALUInstructionWithImmediateProtocol(
    WithImmediateProtocol, ALUInstructionProtocol, Protocol
):
    """Typing helper for classes implementing WithImmediate and ALUInstruction"""

class SourcedProtocol(Protocol):
    """Typing helper for classes with a source value"""

    source_name: ClassVar[str]

    @property
    def src_value(self: ALUInstructionWithImmediateProtocol) -> VexValue:
        ...

class ImmediateSource(WithImmediate):
    """Extract source value from the immediate field"""

    source_bin = "0"
    source_name = "imm"

    @property
    def src_value(self: ALUInstructionWithImmediateProtocol) -> VexValue:
        return self.constant(self.immediate, self.size)

class RegisterSource(WithSrcReg):
    """Extract source value from loading the source register"""

    source_bin = "1"
    source_name = "reg"

    @property
    def src_value(self: InstructionWithSrcRegProtocol) -> VexValue:
        src_full = self.get(self.src_reg, REGISTER_TYPE)

        if hasattr(self, "size"):
            size = cast(Any, self).size
            if size != REGISTER_TYPE:
                return src_full.narrow_low(size)
            
        return src_full

class FetchSource:
    """Fetch source value with other operands"""

    def fetch_operands(self: Any) -> Tuple[VexValue, ...]:
        return super().fetch_operands() + (self.src_value,)

class FetchDestination(WithDestReg):
    """Fetch destination register with other operands"""

    def fetch_operands(self: Any) -> Tuple[VexValue, ...]:
        dst_full = self.get(self.dest_reg, REGISTER_TYPE)

        if hasattr(self, "size"):
            if self.size != REGISTER_TYPE:
                dst_sized = dst_full.narrow_low(self.size)
                return super().fetch_operands() + (dst_sized,)
        
        return super().fetch_operands() + (dst_full,)

class FetchPC:
    """Fetch instruction pointer with other operands"""

    def fetch_operands(self: Any) -> Tuple[VexValue, ...]:
        return super().fetch_operands() + (self.get("ip", REGISTER_TYPE),)

class AddOp(FetchDestination, FetchSource):
    """Addition operation"""

    operation_bin = "0000"
    operation_name = "add"

    def compute_result(self, src, dst):
        return dst + src

class SubOp(FetchDestination, FetchSource):
    """Subtraction operation"""

    operation_bin = "0001"
    operation_name = "sub"

    def compute_result(self, src, dst):
        return dst - src

class MulOp(FetchDestination, FetchSource):
    """Multiplication operation"""

    operation_bin = "0010"
    operation_name = "mul"

    def compute_result(self, src, dst):
        return dst * src

class DivOp(FetchDestination, FetchSource):
    """Division operation"""

    operation_bin = "0011"
    operation_name = "div"

    def compute_result(self, src, dst):
        return dst // src

class OrOp(FetchDestination, FetchSource):
    """Bitwise OR operation"""

    operation_bin = "0100"
    operation_name = "or"

    def compute_result(self, src, dst):
        return dst | src

class AndOp(FetchDestination, FetchSource):
    """Bitwise AND operation"""

    operation_bin = "0101"
    operation_name = "and"

    def compute_result(self, src, dst):
        return dst & src

class LshOp(FetchDestination, FetchSource):
    """Left shift operation"""

    operation_bin = "0110"
    operation_name = "lsh"

    def compute_result(self, src, dst):
        if self.size == Type.int_64:
            masked = src & self.constant(63, Type.int_64)
        else:
            masked = src & self.constant(31, Type.int_32)
        shift_amount = masked.narrow_low(Type.int_8)
        return dst << shift_amount

class RshOp(FetchDestination, FetchSource):
    """Right logical shift instruction"""

    operation_bin = "0111"
    operation_name = "rsh"

    def compute_result(self, src, dst):
        if self.size == Type.int_64:
            masked = src & self.constant(63, Type.int_64)
        else:
            masked = src & self.constant(31, Type.int_32)
        shift_amount = masked.narrow_low(Type.int_8)
        return dst >> shift_amount

class NegOp(FetchDestination):
    """Arithmetic negation: dst = -dst.

    eBPF NEG operates on the destination register (the src field is unused);
    it is two's-complement negation, not bitwise NOT. (Previously this read the
    src register and returned ~src, which is wrong on both counts.)
    """

    operation_bin = "1000"
    operation_name = "neg"

    def compute_result(self, dst):
        return ~dst + self.constant(1, self.size)

class ModOp(FetchDestination, FetchSource):
    """Modulo operation"""

    operation_bin = "1001"
    operation_name = "mod"

    def compute_result(self, src, dst):
        return dst % src

class XorOp(FetchDestination, FetchSource):
    """Bitwise XOR operation"""

    operation_bin = "1010"
    operation_name = "xor"

    def compute_result(self, src, dst):
        return dst ^ src

class MovOp(FetchSource):
    """Mov operation"""

    operation_bin = "1011"
    operation_name = "mov"

    def compute_result(self, src):
        return src

class ArshOp(FetchDestination, FetchSource):
    """Right arithmetic shift instruction"""

    operation_bin = "1100"
    operation_name = "arsh"

    def compute_result(self, src, dst):
        if self.size == Type.int_64:
            masked = src & self.constant(63, Type.int_64)
        else:
            masked = src & self.constant(31, Type.int_32)
        shift_amount = masked.narrow_low(Type.int_8)
        return dst.sar(shift_amount)

class EndianInstruction(WithImmediate, FetchDestination, ALU32Instruction):
    """
    Base class for Endianness conversion (BPF_END).
    Encodes as BPF_ALU (0x04) | BPF_END (0xd0).
    """
    operation_bin = "1101"
    operation_name = "byteconv"

    def fetch_operands(self):
        return (self.get(self.dest_reg, REGISTER_TYPE),)

    def _swap16(self, v):
        return ((v & 0xFF) << 8) | ((v >> 8) & 0xFF)

    def _swap32(self, v):
        return (
            ((v & 0xFF) << 24) |
            ((v & 0xFF00) << 8) |
            ((v >> 8) & 0xFF00) |
            ((v >> 24) & 0xFF)
        )

    def _swap64(self, v):
        lo = v.narrow_low(Type.int_32)
        hi = (v >> 32).narrow_low(Type.int_32)

        lo_swapped = self._swap32(lo)
        hi_swapped = self._swap32(hi)

        return (lo_swapped.widen_unsigned(Type.int_64) << 32) | hi_swapped.widen_unsigned(Type.int_64)

    def compute_result(self, dst):
        width = self.immediate
        val = dst

        if width == 16:
            val = val.narrow_low(Type.int_16)
        elif width == 32:
            val = val.narrow_low(Type.int_32)
        elif width == 64:
            pass

        if self.source_bin == "1":
            if width == 16:
                val = self._swap16(val)
            elif width == 32:
                val = self._swap32(val)
            elif width == 64:
                val = self._swap64(val)

        if width != 64:
            val = val.widen_unsigned(Type.int_64)

        return val

    def commit_result(self: InstructionWithDestRegProtocol, res: Any) -> None:
        self.put(res, self.dest_reg)

class EndianLE(EndianInstruction):
    """BPF_TO_LE (0xd4)"""
    source_bin = "0"
    source_name = "le"

class EndianBE(EndianInstruction):
    """BPF_TO_BE (0xdc)"""
    source_bin = "1"
    source_name = "be"

ALU = {
    type(
        f"{op.__name__[:-2]}{cls.__name__[:-11]}{source.__name__[:3]}",
        (op, source, cls),
        {},
    )
    for op in (
        AddOp,
        SubOp,
        MulOp,
        DivOp,
        OrOp,
        AndOp,
        LshOp,
        RshOp,
        NegOp,
        ModOp,
        XorOp,
        MovOp,
        ArshOp,
    )
    for cls in (ALU32Instruction, ALU64Instruction)
    for source in (ImmediateSource, RegisterSource)
} | {EndianLE, EndianBE}

class SourcedConditionalJumpInstructionProtocol(
    SourcedProtocol, WithOffsetProtocol, InstructionProtocol, Protocol
):
    """Typing helper for classes implementing Sourced, WithOffset and Instruction"""

    @abc.abstractmethod
    def condition(self, src: VexValue, dst: VexValue) -> VexValue:
        ...

    @property
    @abc.abstractmethod
    def operation_name(self) -> str:
        ...

class ConditionalJumpOp(WithOffset, FetchDestination, FetchSource, FetchPC):
    """Jump with a condition"""

    @abc.abstractmethod
    def condition(self, src: VexValue, dst: VexValue) -> VexValue:
        ...

    @property
    @abc.abstractmethod
    def operation_name(self) -> str:
        ...

    @property
    def name(self: SourcedConditionalJumpInstructionProtocol):
        return f"{self.operation_name}_{self.source_name}"

    def compute_result(self: SourcedConditionalJumpInstructionProtocol, pc, src, dst):
        cond = self.condition(src, dst)

        off_i16 = self.constant(self.offset, Type.int_16)
        off_i64 = off_i16.widen_signed(Type.int_64)

        one = self.constant(1, Type.int_64)
        eight = self.constant(8, Type.int_64)

        target_addr = pc + (off_i64 + one) * eight
        self.jump(cond, target_addr, JumpKind.Boring)

class JeqOp(ConditionalJumpOp):
    """Jump if equals"""

    operation_bin = "0001"
    operation_name = "jeq"

    def condition(self, src, dst):
        return dst == src

class JgtOp(ConditionalJumpOp):
    """Jump if greater than (unsigned)"""

    operation_bin = "0010"
    operation_name = "jgt"

    def condition(self, src, dst):
        return dst > src

class JgeOp(ConditionalJumpOp):
    """Jump if greater than or equals (unsigned)"""

    operation_bin = "0011"
    operation_name = "jge"

    def condition(self, src, dst):
        return dst >= src

class JsetOp(ConditionalJumpOp):
    """Jump if bit is set"""

    operation_bin = "0100"
    operation_name = "jset"

    def condition(self, src, dst):
        return (dst & src) != 0

class JneOp(ConditionalJumpOp):
    """Jump if not equals"""

    operation_bin = "0101"
    operation_name = "jne"

    def condition(self, src, dst):
        return dst != src

class JltOp(ConditionalJumpOp):
    """Jump if less than (unsigned)"""
    
    operation_bin = "1010"
    operation_name = "jlt"
    
    def condition(self, src, dst):
        return dst < src

class JleOp(ConditionalJumpOp):
    """Jump if less than or equals (unsigned)"""
    
    operation_bin = "1011"
    operation_name = "jle"
    
    def condition(self, src, dst):
        return dst <= src

class JsltOp(ConditionalJumpOp):
    """Jump if less than (signed)"""
    
    operation_bin = "1100"
    operation_name = "jslt"

    def condition(self, src, dst):
        return dst.signed < src.signed

class JsleOp(ConditionalJumpOp):
    """Jump if less than or equals (signed)"""
    
    operation_bin = "1101"
    operation_name = "jsle"
    
    def condition(self, src, dst):
        return dst.signed <= src.signed

class JsgtOp(ConditionalJumpOp):
    """Jump if greater than (signed)"""

    operation_bin = "0110"
    operation_name = "jsgt"

    def condition(self, src: VexValue, dst: VexValue):
        return dst.signed > src.signed

class JsgeOp(ConditionalJumpOp):
    """Jump if greater than or equals (signed)"""

    operation_bin = "0111"
    operation_name = "jsge"

    def condition(self, src, dst):
        return dst.signed >= src.signed

class CallOp(WithSrcReg, FetchPC, ImmediateSource):
    """eBPF CALL: helper (src_reg=0) or bpf2bpf (src_reg=1)."""

    name = "call"
    operation_bin = "1000"

    def compute_result(self, pc):
        if self.src_reg == 0:
            syscall_id = self.constant(self.immediate, self.size)
            self.put(syscall_id, "syscall")
            self.jump(None, pc + 8, JumpKind.Syscall)
            return

        if self.src_reg == 1:
            next_pc = pc + 8
            eight = self.constant(8, REGISTER_TYPE)

            depth = self.get("call_depth", REGISTER_TYPE)
            stack_base = self.constant(BPF_CALL_STACK_BASE, REGISTER_TYPE)
            stack_addr = stack_base + depth * eight
            self.store(next_pc, stack_addr)

            save_base = self.constant(BPF_CALLER_SAVE_BASE, REGISTER_TYPE)
            frame_size = self.constant(BPF_CALLER_SAVE_FRAME_SIZE, REGISTER_TYPE)
            frame_addr = save_base + depth * frame_size
            for i, reg_num in enumerate((1, 2, 3, 4, 5)):
                reg_val = self.get(reg_num, REGISTER_TYPE)
                offset = self.constant(i * 8, REGISTER_TYPE)
                self.store(reg_val, frame_addr + offset)
            r10 = self.get(10, REGISTER_TYPE)
            self.store(r10, frame_addr + self.constant(40, REGISTER_TYPE))
            for i, reg_num in enumerate((6, 7, 8, 9)):
                reg_val = self.get(reg_num, REGISTER_TYPE)
                offset = self.constant(48 + i * 8, REGISTER_TYPE)
                self.store(reg_val, frame_addr + offset)
            new_r10 = r10 - self.constant(BPF_STACK_FRAME_SIZE, REGISTER_TYPE)
            self.put(new_r10, 10)

            self.put(depth + self.constant(1, REGISTER_TYPE), "call_depth")

            imm32 = self.constant(self.immediate, Type.int_32)
            off64 = imm32.widen_signed(Type.int_64)
            byte_off = off64 * eight

            target = next_pc + byte_off
            self.jump(None, target, JumpKind.Boring)
            return

        raise NotImplementedError(f"CALL with unsupported src_reg={self.src_reg}")

class CallXOp(WithImmediate, RegisterSource):
    """Call function from register"""

    name = "callx"

    operation_bin = "1000"

    def fetch_operands(self: InstructionWithImmediateProtocol):
        addr = self.constant(self.immediate, Type.int_32)
        return (self.load(addr, REGISTER_TYPE),)

    def compute_result(self: InstructionProtocol, addr):
        self.jump(None, addr, JumpKind.Call)

class Ja64(WithOffset, FetchPC, Jump64Instruction):
    """Jump ahead"""

    name = "ja"

    source_bin = "0"
    operation_bin = "0000"

    def compute_result(self, pc):
        off_i16 = self.constant(self.offset, Type.int_16)
        off_i64 = off_i16.widen_signed(Type.int_64)

        one = self.constant(1, Type.int_64)
        eight = self.constant(8, Type.int_64)

        target = pc + (off_i64 + one) * eight
        self.jump(None, target, JumpKind.Boring)

class Exit64(Jump64Instruction):
    """Exit"""

    name = "exit"

    source_bin = "0"
    operation_bin = "1001"

    def compute_result(self):
        depth = self.get("call_depth", REGISTER_TYPE)
        one = self.constant(1, REGISTER_TYPE)
        eight = self.constant(8, REGISTER_TYPE)
        new_depth = depth - one
        self.put(new_depth, "call_depth")

        stack_base = self.constant(BPF_CALL_STACK_BASE, REGISTER_TYPE)
        stack_addr = stack_base + new_depth * eight
        ret_addr = self.load(stack_addr, REGISTER_TYPE)

        save_base = self.constant(BPF_CALLER_SAVE_BASE, REGISTER_TYPE)
        frame_size = self.constant(BPF_CALLER_SAVE_FRAME_SIZE, REGISTER_TYPE)
        frame_addr = save_base + new_depth * frame_size
        for i, reg_num in enumerate((1, 2, 3, 4, 5)):
            offset = self.constant(i * 8, REGISTER_TYPE)
            reg_val = self.load(frame_addr + offset, REGISTER_TYPE)
            self.put(reg_val, reg_num)
        saved_r10 = self.load(frame_addr + self.constant(40, REGISTER_TYPE), REGISTER_TYPE)
        self.put(saved_r10, 10)
        for i, reg_num in enumerate((6, 7, 8, 9)):
            offset = self.constant(48 + i * 8, REGISTER_TYPE)
            reg_val = self.load(frame_addr + offset, REGISTER_TYPE)
            self.put(reg_val, reg_num)

        self.jump(None, ret_addr, JumpKind.Boring)

Jump = (
    {
        type(
            f"{op.__name__[:-2]}{cls.__name__[4:-11]}{source.__name__[:3]}",
            (op, source, cls),
            {},
        )
        for op in (
            JeqOp,
            JgtOp,
            JgeOp,
            JsetOp,
            JneOp,
            JsgtOp,
            JsgeOp,
            JltOp,
            JleOp,
            JsltOp,
            JsleOp,
        )
        for cls in (Jump32Instruction, Jump64Instruction)
        for source in (ImmediateSource, RegisterSource)
    }
    | {
        type(
            f"{op.__name__[:-2]}{cls.__name__[4:-11]}",
            (op, cls),
            {},
        )
        for op in (CallOp, CallXOp)
        for cls in (Jump32Instruction, Jump64Instruction)
    }
    | {Ja64, Exit64}
)

class ImmediateMode:
    """Load/Store from immediate"""

    mode_bin = "000"

class AbsoluteMode:
    """Obsolete mode"""

    mode_bin = "001"

class IndirectMode:
    """Obsolete mode"""

    mode_bin = "010"

class MemoryMode:
    """Load/Store from memory"""

    mode_bin = "011"

class AtomicMode:
    """Atomic mode modifier for store ops (encoding matches kernel spec)."""

    mode_bin = "110"

class WidthedProtocol(Protocol):
    """Typing helper representing a class with a width"""

    width: ClassVar[str]

class Word:
    """Width of 32bits"""

    width = cast(str, Type.int_32)
    width_bin = "00"
    width_name = "w"
    width_bytes = 4

class HalfWord:
    """Width of 16bits"""

    width = cast(str, Type.int_16)
    width_bin = "01"
    width_name = "h"
    width_bytes = 2

class Byte:
    """Width of 8bits"""

    width = cast(str, Type.int_8)
    width_bin = "10"
    width_name = "b"
    width_bytes = 1

class DoubleWord:
    """Width of 64bits"""

    width = cast(str, Type.int_64)
    width_bin = "11"
    width_name = "dw"
    width_bytes = 8

class WidthedInstructionProtocol(WidthedProtocol, InstructionProtocol, Protocol):
    """Typing helper for classes implementing Widthed and Instruction"""

class StoreFromRegisterOp(
    MemoryMode,
    WithOffset,
    FetchSource,
    FetchDestination,
    RegisterSource,
    StoreFromRegisterInstruction,
):
    """Store into memory from register"""

    @property
    def name(self) -> str:
        return f"stx{self.width_name}"

    def compute_result(self, dst, src):
        if self.width != REGISTER_TYPE:
            src = src.widen_unsigned(self.width)
        self.store(src, dst + self.offset)

class StoreImmediateOp(
    MemoryMode,
    WithOffset,
    WithImmediate,
    FetchDestination,
    StoreImmediateInstruction,
):
    """Store into memory from immediate"""

    @property
    def name(self) -> str:
        return f"st{self.width_name}"

    def compute_result(self, dst):
        imm = self.constant(self.immediate, self.width)
        self.store(imm, dst + self.offset)

class LoadInRegisterOp(
    MemoryMode, WithOffset, FetchSource, RegisterSource, LoadInRegisterInstruction
):
    """Load into register from memory"""

    @property
    def name(self) -> str:
        return f"ldx{self.width_name}"

    def fetch_operands(self):
        (src,) = super().fetch_operands()
        return (self.load(src + self.offset, self.width),)

    def compute_result(self, res):
        if self.width != REGISTER_TYPE:
            res = res.widen_unsigned(REGISTER_TYPE)
        return res

    def commit_result(self: InstructionWithDestRegProtocol, res):
        self.put(res, self.dest_reg)

class PacketLoadOpBase(WithImmediate, LoadNonStandardInstruction):
    """
    Base class for classic socket-filter packet-access instructions.

    These are the legacy BPF_LD_ABS / BPF_LD_IND forms emitted by LLVM's
    llvm.bpf.load.{byte,half,word} builtins. They read packet data using the
    implicit skb context rather than normal eBPF BPF_MEM addressing.
    """

    def _skb_data_bounds(self):
        skb_ptr = self.get(6, REGISTER_TYPE)
        data_off = self.constant(SKB_DATA_OFFSET, REGISTER_TYPE)
        data_end_off = self.constant(SKB_DATA_END_OFFSET, REGISTER_TYPE)

        data_ptr = self.load(skb_ptr + data_off, Type.int_32).widen_unsigned(REGISTER_TYPE)
        data_end = self.load(skb_ptr + data_end_off, Type.int_32).widen_unsigned(REGISTER_TYPE)
        return data_ptr, data_end

    def _packet_load_be(self, addr):
        byte0 = self.load(addr, Type.int_8).widen_unsigned(REGISTER_TYPE)
        if self.width_bytes == 1:
            return byte0

        byte1 = self.load(addr + self.constant(1, REGISTER_TYPE), Type.int_8).widen_unsigned(REGISTER_TYPE)
        if self.width_bytes == 2:
            return (byte0 << 8) | byte1

        byte2 = self.load(addr + self.constant(2, REGISTER_TYPE), Type.int_8).widen_unsigned(REGISTER_TYPE)
        byte3 = self.load(addr + self.constant(3, REGISTER_TYPE), Type.int_8).widen_unsigned(REGISTER_TYPE)
        return (byte0 << 24) | (byte1 << 16) | (byte2 << 8) | byte3

    def _finish_packet_load(self, packet_offset):
        data_ptr, data_end = self._skb_data_bounds()
        addr = data_ptr + packet_offset
        width_bytes = self.constant(self.width_bytes, REGISTER_TYPE)
        in_bounds = (addr + width_bytes) <= data_end

        loaded = self._packet_load_be(addr)
        return in_bounds.ite(loaded, self.constant(0, REGISTER_TYPE))

    def commit_result(self: InstructionWithDestRegProtocol, res):
        self.put(res, 0)

class AbsolutePacketLoadOp(AbsoluteMode, PacketLoadOpBase):
    """Classic BPF_LD_ABS packet load."""

    @property
    def name(self) -> str:
        return f"ldabs{self.width_name}"

    def compute_result(self):
        imm_u32 = self.constant(self.immediate & 0xFFFFFFFF, Type.int_32)
        packet_offset = imm_u32.widen_unsigned(REGISTER_TYPE)
        return self._finish_packet_load(packet_offset)

class IndirectPacketLoadOp(IndirectMode, WithSrcReg, PacketLoadOpBase):
    """Classic BPF_LD_IND packet load."""

    @property
    def name(self) -> str:
        return f"ldind{self.width_name}"

    def compute_result(self):
        imm_u32 = self.constant(self.immediate & 0xFFFFFFFF, Type.int_32).widen_unsigned(REGISTER_TYPE)
        src_off = self.get(self.src_reg, REGISTER_TYPE).narrow_low(Type.int_32).widen_unsigned(REGISTER_TYPE)
        return self._finish_packet_load(src_off + imm_u32)

class AtomicOp(
    AtomicMode,
    WithImmediate,
    WithOffset,
    FetchSource,
    FetchDestination,
    RegisterSource,
    StoreFromRegisterInstruction,
):
    BPF_ADD = 0x0
    BPF_OR = 0x40
    BPF_AND = 0x50
    BPF_XOR = 0xa0
    BPF_XCHG = 0xe0
    BPF_CMPXCHG = 0xf0
    FETCH_MOD = 0x1

    def compute_result(self, dst_addr, src_val):
        imm = self.immediate
        op_code = imm & ~self.FETCH_MOD

        addr = dst_addr + self.offset

        old = self.load(addr, self.width)

        if self.width != REGISTER_TYPE:
            src_n = src_val.narrow_low(self.width)
        else:
            src_n = src_val

        if op_code == self.BPF_ADD:
            new = old + src_n
            self.store(new, addr)
            if imm & self.FETCH_MOD:
                self.put(old.widen_unsigned(REGISTER_TYPE) if self.width != REGISTER_TYPE else old, self.src_reg)
            return

        if op_code == self.BPF_OR:
            new = old | src_n
            self.store(new, addr)
            if imm & self.FETCH_MOD:
                self.put(old.widen_unsigned(REGISTER_TYPE) if self.width != REGISTER_TYPE else old, self.src_reg)
            return

        if op_code == self.BPF_AND:
            new = old & src_n
            self.store(new, addr)
            if imm & self.FETCH_MOD:
                self.put(old.widen_unsigned(REGISTER_TYPE) if self.width != REGISTER_TYPE else old, self.src_reg)
            return

        if op_code == self.BPF_XOR:
            new = old ^ src_n
            self.store(new, addr)
            if imm & self.FETCH_MOD:
                self.put(old.widen_unsigned(REGISTER_TYPE) if self.width != REGISTER_TYPE else old, self.src_reg)
            return

        if op_code == self.BPF_XCHG:
            self.store(src_n, addr)
            if imm & self.FETCH_MOD:
                self.put(old.widen_unsigned(REGISTER_TYPE) if self.width != REGISTER_TYPE else old, self.src_reg)
            return

        if op_code == self.BPF_CMPXCHG:
            expected_full = self.get(0, REGISTER_TYPE)
            expected = expected_full.narrow_low(self.width) if self.width != REGISTER_TYPE else expected_full

            cond = (old == expected)

            new = cond.ite(src_n, old)

            self.store(new, addr)

            old_ret = old.widen_unsigned(REGISTER_TYPE) if self.width != REGISTER_TYPE else old
            self.put(old_ret, 0)

            return

        raise NotImplementedError(f"Atomic immediate encoding not implemented: 0x{imm:02x}")

def _atomic_name(self):
    op_name = "unknown"
    op_code = self.immediate & ~self.FETCH_MOD
    if op_code == self.BPF_ADD:
        op_name = "add"
    elif op_code == self.BPF_OR:
        op_name = "or"
    elif op_code == self.BPF_AND:
        op_name = "and"
    elif op_code == self.BPF_XOR:
        op_name = "xor"
    elif op_code == self.BPF_XCHG:
        op_name = "xchg"
    elif op_code == self.BPF_CMPXCHG:
        op_name = "cmpxchg"

    fetch_str = "_fetch" if (self.immediate & self.FETCH_MOD) else ""
    return f"atomic{fetch_str}_{self.width_name}_{op_name}"

AtomicOps = {
    type(
        f"{size.__name__}AtomicOp",
        (AtomicOp, size),
        {
            "width": size.width,
            "width_bin": size.width_bin,
            "width_name": size.width_name,
            "name": property(_atomic_name),
        },
    )
    for size in (Word, DoubleWord)
}

class Load64Imm(
    WithImmediate,
    DoubleWord,
    ImmediateMode,
    LoadNonStandardInstruction,
):
    """
    Load a 64-bit immediate into a register. This is a special 16-byte
    instruction in eBPF, composed of two 8-byte chunks.
    """

    immediate_bin = "i" * 96

    @property
    def name(self) -> str:
        return f"ld{self.width_name}"

    @property
    def immediate(self) -> int:
        """
        Overrides WithImmediate.immediate to correctly parse the two-part
        immediate value of the lddw instruction.
        """
        raw_bits = bitstring.Bits(bin=self.data["i"])

        imm_low = raw_bits[0:32]
        imm_high = raw_bits[64:96]

        full_imm_bits = imm_low + imm_high
        return full_imm_bits.intle

    def compute_result(self):
        return self.constant(self.immediate, Type.int_64)

    def commit_result(self, res):
        self.put(res, self.dest_reg)

LoadStore = (
    {
        type(
            f"{size.__name__}{op.__name__[:-2]}",
            (size, op),
            {},
        )
        for op in (LoadInRegisterOp, StoreImmediateOp, StoreFromRegisterOp)
        for size in (Byte, HalfWord, Word, DoubleWord)
    }
    | {
        type(
            f"{size.__name__}{op.__name__[:-2]}",
            (size, op),
            {},
        )
        for op in (AbsolutePacketLoadOp, IndirectPacketLoadOp)
        for size in (Byte, HalfWord, Word)
    }
    | {Load64Imm}
    | AtomicOps
)
