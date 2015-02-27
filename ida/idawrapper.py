#!/usr/bin/env python
"""To install, copy to $APPDATA\Hex-Rays\idapythonrc.py"""

from __future__ import print_function
import re
from idaapi import FlowChart, get_func, BADADDR
from idautils import Functions, DecodeInstruction, XrefsFrom, XrefsTo
from idc import (FindFuncEnd, GetManyBytes, GetOpnd, MakeFunction, GetFunctionName, GetFuncOffset, SetFunctionCmt,
                 GetFunctionCmt)

# check cref_t and dref_t


# TODO Need a better name for this
class UnexpectedError(ValueError):
    pass


class InvalidInstruction(ValueError):
    pass


class Xref(object):
    # XXX Need to properly represent the types, whether far or code flow
    def __init__(self, xref_t):
        self._xref = xref_t

    @property
    def to(self):
        return self._xref.to

    @property
    def frm(self):
        return self._xref.frm

    @property
    def type(self):
        # what does type represent
        return self._xref.type


OPERAND_DATA_TYPES = {
    0: 'BYTE',
    1: 'WORD',
    2: 'DWORD',
    3: 'FLOAT',
    4: 'DOUBLE',
    5: 'TBYTE',
    6: 'PACKREAL',
    7: 'QWORD',
    8: 'BYTE16',
    9: 'CODE',
    10: 'VOID',
    11: 'FWORD',
    12: 'BITFIELD',
    13: 'STRING',
    14: 'UNICODE',
}


class Operand(object):
    """Operand of a single instruction"""
    VALUE = 0

    def __init__(self, op_t, insn, opnum):
        self._op = op_t
        self._insn = insn
        self._opnum = opnum

    @classmethod
    def from_op_t(cls, op_t, insn, opnum):
        """Really an operand factory, returning the properly classed Operand"""
        for c in cls.__subclasses__():
            if c.VALUE == op_t.type:
                return c(op_t, insn, opnum)

    @property
    def offset(self):
        """Byte offset in the instruction to this operand"""
        return self._op.offb

    @property
    def opnum(self):
        """Operand number for the instruction"""
        return self._op.n

    @property
    def type(self):
        return self.__class__.VALUE

    @property
    def datatype(self):
        return self._op.dtyp

    def __str__(self):
        return GetOpnd(self._insn.addr, self._opnum)


class RegisterOperand(Operand):
    VALUE = 1

    @property
    def regnum(self):
        return self._op.reg

    @property
    def reg(self):
        return str(self)


class MemoryOperand(Operand):
    VALUE = 2

    # stack, data, etc...
    @property
    def addr(self):
        return self._op.addr


class PhraseOperand(Operand):
    VALUE = 3

    @property
    def phrase(self):
        return str(self)

    def _parse(self):
        m = re.match(r"\[(.+)([\+\-].+)\]", str(self))
        return m.groups()

    def reg(self):
        return self._parse()[0]

    def reg_offset(self):
        return self._parse()[1]


class DisplacementOperand(Operand):
    VALUE = 4

    @property
    def displacement(self):
        return self._op.value

    @property
    def addr(self):
        return self._op.addr

    def _parse(self):
        m = re.match(r"\[(.+)([\+\-].+)([\+\-].*)\]", str(self))
        return m.groups()

    def reg(self):
        return self._parse()[0]

    def idxreg(self):
        return self._parse()[1]

    def offset(self):
        return int(self._parse()[2], 16)

    @property
    def phrase(self):
        return str(self)


class ImmediateValueOperand(Operand):
    VALUE = 5


class ImmediateFarOperand(Operand):
    VALUE = 6

    @property
    def addr(self):
        return self._op.addr


class ImmediateNearOperand(Operand):
    VALUE = 7

    @property
    def addr(self):
        return self._op.addr


class Instruction(object):
    """An instruction existing at a given address"""
    def __init__(self, ea):
        self._ea = ea
        self._insn = DecodeInstruction(ea)
        if self._insn is None:
            raise InvalidInstruction("")

    @property
    def mnemonic(self):
        return self._insn.get_canon_mnem()

    @property
    def type(self):
        return self._insn.itype

    @property
    def addr(self):
        return self._insn.ea

    @property
    def size(self):
        return self._insn.size

    @property
    def bytes(self):
        return list(GetManyBytes(self.addr, self.size))

    def iter_operands(self):
        i = 0
        for o in self._insn.Operands:
            if o.type != 0:         # 0 is a void operand, meaning it's not used in IDA
                yield Operand.from_op_t(o, self, i)
            i += 1

    @property
    def operands(self):
        return list(self.iter_operands())

    def is_branch(self):
        pass

    def is_memref(self):
        pass

    def is_stackref(self):
        pass

    def __len__(self):
        return self.size

    def __str__(self):
        inst = "{0} ".format(self.mnemonic)
        for o in self.operands[:-1]:
            inst += "{0}, ".format(str(o))
        if len(self.operands) > 0:
            inst += "{0}".format(self.operands[-1])
        return inst


class CodeBlock(object):
    """Represents a logical block of code.  Note that this is distinct from a BasicBlock in that it
    does not put a limitation on branches, code flow, etc.  It is simply a container with a beginning,
    end, and list of instructions in that range.
    """
    @property
    def start(self):
        """Beginning of the block"""
        raise NotImplementedError()

    @property
    def end(self):
        # End is not uniform among blocks in IDA, so we need to subclass this to do it properly
        raise NotImplementedError()

    def iter_instructions(self):
        """Generator that yields the Instruction objects within this CodeBlock"""
        ea = self.start
        if self.end < ea:
            # XXX This is a problem
            raise UnexpectedError("end ea is before start ea")
        while ea < self.end:
            try:
                instr = Instruction(ea)
                yield instr
                ea += instr.size
            except InvalidInstruction:
                ea += 1

    @property
    def instructions(self):
        return list(self.iter_instructions())

    @property
    def bytes(self):
        """List of bytes in the code block"""
        return list(GetManyBytes(self.start, self.end - self.start))


class BasicBlock(CodeBlock):
    """Basic block (single entrance, single exit) flow of code"""
    def __init__(self, bb):
        self._bb = bb

    @property
    def start(self):
        """Beginning (first address) of the basic block"""
        return self._bb.startEA

    @property
    def end(self):
        """End (final address) of the block"""
        return self._bb.endEA

    def iter_successors(self):
        """Exit nodes for this basic block, as BasicBlocks"""
        for b in self._bb.succs():
            yield self.__class__(b)

    @property
    def successors(self):
        return list(self.iter_successors())

    def iter_predecessors(self):
        """Blocks the enter this one"""
        for b in self._bb.preds():
            yield self.__class__(b)

    @property
    def predecessors(self):
        return list(self.iter_predecessors())

    def __eq__(self, other):
        return other.start == self.start

    def __str__(self):
        return "BasicBlock(start={0:#x}, end={1:#x})".format(self.start, self.end)


# I don't really like this API yet
class Loop(object):
    """A loop in a function.  A loop is characterized by a starting basic block (the head), an ending basic block (the
    tail), and the total set of contained basic blocks containing all paths.
    """
    def __init__(self, start_block, end_block, blocks=()):
        self._start_block_ea = start_block
        self._end_block_ea = end_block
        self._blocks = {}
        # Cache the blocks for more efficient lookup
        f = get_func(start_block)
        for b in FlowChart(f):
            if b.startEA in blocks:
                self._blocks[b.startEA] = BasicBlock(b)

    @property
    def head(self):
        return self._blocks[self._start_block_ea]

    @property
    def tail(self):
        return self._blocks[self._end_block_ea]

    def add(self, block_ea):
        """Add a block (by address) to the loop"""
        if block_ea not in self._blocks:
            func = get_func(block_ea)
            for b in FlowChart(func):
                if block_ea == b.startEA:
                    self._blocks[block_ea] = BasicBlock(b)

    def update(self, loop):
        self._blocks.update(loop._blocks)

    def __str__(self):
        return "{0:#x}, {1:#x}, {2} blocks".format(self.head.start, self.tail.start, len(self._blocks))


class Function(CodeBlock):
    """Represents a function in a disassembly"""
    def __init__(self, ea):
        self._start = get_func(ea).startEA

    def __contains__(self, ea):
        return get_func(self.start).contains(ea)

    @classmethod
    def create(cls, start_ea, end_ea=BADADDR):
        """Create a new function"""
        MakeFunction(start_ea, end_ea)
        return cls(start_ea)

    @classmethod
    def iter_all(cls):
        """Iterate over all functions in the disassembly"""
        for f in Functions():
            yield cls(f)

    @property
    def name(self):
        """The name for the function.  E.g., sub_abcd1234"""
        return GetFunctionName(self.start)

    @property
    def offset(self):
        """The file offset for the function"""
        return GetFuncOffset(self.start)

    @property
    def start(self):
        return self._start

    @property
    def end(self):
        """The final EA in the function"""
        return FindFuncEnd(self.start)

    @property
    def repeatable(self):
        """Get and set the repeatable comment for the function"""
        return GetFunctionCmt(self.start, 1)

    @repeatable.setter
    def repeatable(self, cmt):
        return SetFunctionCmt(self.start, cmt, 1)

    @property
    def comment(self):
        """Get and set the non-repeatable comment for the function"""
        return GetFunctionCmt(self.start, 0)

    @comment.setter
    def comment(self, cmt):
        return SetFunctionCmt(self.start, cmt, 0)

    @property
    def no_return(self):
        return not get_func(self.start).does_return()

    def is_thunk(self):
        # TODO How do I do this other than checking for no return?
        pass

    def args(self):
        # TODO How do I do this?
        pass

    def locals(self):
        # TODO How do I do this?
        pass

    @property
    def loops(self):
        """Return the begin and end of any loops in a function"""
        # Note: This is not very efficient, but it gets the job done
        def _dfs(b, parents=[], loops={}, depth=0):
            if b.start in parents:
                lst = parents[parents.index(b.start):]
                return Loop(lst[0], lst[-1], lst)
            else:
                for n in b.successors:
                    loop = _dfs(n, parents+[b.start], loops, depth+1)
                    if loop and (loop.head.start, loop.tail.start) in loops:
                        loops[(loop.head.start, loop.tail.start)].update(loop)
                    elif loop:
                        loops[(loop.head.start, loop.tail.start)] = loop

        blocks = list(self.blocks)
        loops = {}
        _dfs(blocks[0], loops=loops)
        return loops.values()

    def iter_callers(self):
        """Return a list of Xrefs to this function"""
        for r in XrefsTo(self.start):
            yield Xref(r)

    @property
    def callers(self):
        """List of callers to the function, as Xref objects"""
        return list(self.iter_callers())

    # TODO Split this function into a worker to cleanup the API
    def iter_callees(self, recursive=False, parents=[], depth=0):
        """List of functions called by this one"""
        for i in self.instructions:
            if i.mnemonic.lower() == "call":
                # Get the call destination
                xr = list(XrefsFrom(i.addr, flags=1))[0]
                func = Function(xr.to)
                yield depth, i.addr, func
                if recursive and func.start not in parents:
                    for d, ea, f in func.iter_callees(recursive=True, parents=parents+[self.start], depth=depth+1):
                        yield d, ea, f

    @property
    def callees(self):
        """List of functions called by this function"""
        return list(self.iter_callees())

    def call_tree(self):
        """Print a pretty, recursive call tree from this function"""
        print("[{0:#x}] {1}".format(self.start, self.name))
        for d, ea, f in self.iter_callees(recursive=True, depth=1):
            print("{0}[{1:#x}] {2}".format(d * "  ", ea, f.name))

    @property
    def exit_nodes(self):
        pass

    @property
    def entrance_nodes(self):
        pass

    def iter_blocks(self):
        """Return the basic blocks in the function"""
        f = get_func(self.start)
        for b in FlowChart(f):
            yield BasicBlock(b)

    @property
    def blocks(self):
        """List of basic blocks in the function"""
        return list(self.iter_blocks())
