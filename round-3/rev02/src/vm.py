from enum import Enum
from dataclasses import dataclass


class Reg(Enum):
    A = 0
    B = 1
    C = 2
    SP = 3


class Label(str):
    pass


@dataclass
class Op:
    # name: str
    nargs: int
    has_imm: bool

    code: int
    arg1: Reg | None = None
    arg2: Reg | None = None
    imm: int | Label | None = None

    def __init__(self, a=None, b=None):
        if type(a) == Reg:
            self.arg1 = a
        elif type(a) in (int, Label):
            self.imm = a

        if type(b) == Reg:
            self.arg2 = b
        elif type(b) in (int, Label):
            self.imm = b

    def __str__(self):
        rv = f"{type(self).__name__}"
        rv += "".join(f" {r.name}" for r in [self.arg1, self.arg2][:self.nargs])
        fmt = "04x" if type(self.imm) == int else ""
        rv += f" {self.imm:{fmt}}" if self.imm is not None else ""
        return rv

    def to_bytes(self):
        rv = [self.code << 4]
        if self.arg1 is not None:
            rv[0] |= self.arg1.value << 2
        if self.arg2 is not None:
            rv[0] |= self.arg2.value
        if self.imm is not None:
            if type(self.imm) == Label:
                raise ValueError(f"Label {self.imm} not resolved")
            rv.append(self.imm >> 8)
            rv.append(self.imm & 0xFF)
        return bytes(rv)

    def __len__(self):
        return 3 if self.has_imm else 1


HALT = type("HALT", (Op,), {"code": 0, "nargs": 0, "has_imm": False})
LOAD = type("LOAD", (Op,), {"code": 1, "nargs": 1, "has_imm": True})
LOAD_PTR = type("LOAD_PTR", (Op,), {"code": 2, "nargs": 1, "has_imm": False})
STORE = type("STORE", (Op,), {"code": 3, "nargs": 2, "has_imm": False})
CMP_LT = type("CMP_LT", (Op,), {"code": 4, "nargs": 2, "has_imm": False})
ADD = type("ADD", (Op,), {"code": 5, "nargs": 2, "has_imm": False})
SUB = type("SUB", (Op,), {"code": 6, "nargs": 2, "has_imm": False})
CALL = type("CALL", (Op,), {"code": 7, "nargs": 0, "has_imm": True})
RET = type("RET", (Op,), {"code": 8, "nargs": 0, "has_imm": False})
JMP = type("JMP", (Op,), {"code": 9, "nargs": 0, "has_imm": True})
JZ = type("JZ", (Op,), {"code": 10, "nargs": 1, "has_imm": True})
JNZ = type("JNZ", (Op,), {"code": 11, "nargs": 1, "has_imm": True})
PUSH = type("PUSH", (Op,), {"code": 12, "nargs": 1, "has_imm": False})
POP = type("POP", (Op,), {"code": 13, "nargs": 1, "has_imm": False})
AND = type("AND", (Op,), {"code": 14, "nargs": 2, "has_imm": False})
NOT = type("NOT", (Op,), {"code": 15, "nargs": 1, "has_imm": False})


class Asm:
    def __init__(self):
        self.labels: dict[Label, int] = {}
        self.ops: list[Op] = []
        self.current_addr: int = 0

    def add_op(self, a: Op | Label):
        if type(a) == Label:
            if a in self.labels:
                raise ValueError(f"Label {a} already defined")
            self.labels[a] = self.current_addr
        else:
            self.ops.append(a)
            self.current_addr += len(a)

    def add_ops(self, *ops: Op | Label):
        for op in ops:
            self.add_op(op)

    # def add_label(self, label: Label):
    #     if label in self.labels:
    #         raise ValueError(f"Label {label} already defined")
    #     self.labels[label] = self.current_addr

    def __add__(self, o: "Asm") -> "Asm":
        if self.labels.keys() & o.labels.keys():
            raise ValueError(
                f"Labels {self.labels.keys() & o.labels.keys()} defined in both Asm objects"
            )
        rv = type(self)()
        rv.labels = {**self.labels}
        for l, a in o.labels.items():
            rv.labels[l] = a + self.current_addr
        rv.ops = self.ops + o.ops
        rv.current_addr = self.current_addr + o.current_addr
        return rv

    def to_bytes(self):
        for op in self.ops:
            if op.has_imm and type(op.imm) == Label:
                op.imm = self.labels[op.imm]

        return b"".join(op.to_bytes() for op in self.ops)

    def __str__(self):
        return "\n".join(str(op) for op in self.ops)


###
entry = Asm()
entry.add_ops(
    CALL(Label("main")),
    HALT(),
)

func_or = Asm()
func_or.add_ops(
    Label("or"),
    PUSH(Reg.B),
    NOT(Reg.A, Reg.A),
    NOT(Reg.B, Reg.B),
    AND(Reg.A, Reg.B),
    NOT(Reg.A, Reg.A),
    POP(Reg.B),
    RET(),
)

func_xor = Asm()
func_xor.add_ops(
    Label("xor"),
    PUSH(Reg.C),
    PUSH(Reg.B),
    PUSH(Reg.A),
    NOT(Reg.B, Reg.B),
    AND(Reg.A, Reg.B),
    POP(Reg.B),
    POP(Reg.C),
    NOT(Reg.B, Reg.B),
    AND(Reg.B, Reg.C),
    CALL(Label("or")),
    PUSH(Reg.C),
    POP(Reg.B),
    POP(Reg.C),
    RET(),
)

func_xor += func_or


def test():
    func_main = Asm()
    func_main.add_ops(
        Label("main"),
        LOAD(Reg.A, 0b1010),
        LOAD(Reg.B, 0b1100),
        CALL(Label("xor")),
        RET(),
    )

    return (entry + func_xor + func_main).to_bytes()
