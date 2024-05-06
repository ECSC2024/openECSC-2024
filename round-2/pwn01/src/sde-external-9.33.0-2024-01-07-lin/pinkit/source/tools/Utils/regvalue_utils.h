/*
 * Copyright (C) 2013-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#ifndef REGVALUE_UTILS_H
#define REGVALUE_UTILS_H

/////////////////////
// INCLUDES
/////////////////////

#include <string>
#include <ostream>
#include "pin.H"

using std::ostream;
using std::string;

/////////////////////
// GLOBAL VARIABLES
/////////////////////

// Booleans indicating the supported ISA extensions.
extern const bool hasAvxSupport;
extern const bool hasAvx512fSupport;

///////////////////////////
// TYPES DECLARATIONS
///////////////////////////

const UINT32 MAX_BYTES_PER_PINTOOL_WIDE_REG   = 1024;
const UINT32 MAX_WORDS_PER_PINTOOL_WIDE_REG   = (MAX_BYTES_PER_PINTOOL_WIDE_REG / 2);
const UINT32 MAX_DWORDS_PER_PINTOOL_WIDE_REG  = (MAX_WORDS_PER_PINTOOL_WIDE_REG / 2);
const UINT32 MAX_QWORDS_PER_PINTOOL_WIDE_REG  = (MAX_DWORDS_PER_PINTOOL_WIDE_REG / 2);
const UINT32 MAX_FLOATS_PER_PINTOOL_WIDE_REG  = (MAX_BYTES_PER_PINTOOL_WIDE_REG / sizeof(float));
const UINT32 MAX_DOUBLES_PER_PINTOOL_WIDE_REG = (MAX_BYTES_PER_PINTOOL_WIDE_REG / sizeof(double));

const UINT32 MAX_BYTES_PER_PINTOOL_REG   = 64;
const UINT32 MAX_WORDS_PER_PINTOOL_REG   = (MAX_BYTES_PER_PINTOOL_REG / 2);
const UINT32 MAX_DWORDS_PER_PINTOOL_REG  = (MAX_WORDS_PER_PINTOOL_REG / 2);
const UINT32 MAX_QWORDS_PER_PINTOOL_REG  = (MAX_DWORDS_PER_PINTOOL_REG / 2);
const UINT32 MAX_FLOATS_PER_PINTOOL_REG  = (MAX_BYTES_PER_PINTOOL_REG / sizeof(float));
const UINT32 MAX_DOUBLES_PER_PINTOOL_REG = (MAX_BYTES_PER_PINTOOL_REG / sizeof(double));

/*
 * PINTOOL_REGISTER is a container large enough to access all type of X86 registers (up to the size of the largest register)
 * This data structure is implemented as a union to allow viewing the value as different types (signed/unsigned
 * integer or floating point) and allow access in blocks of various sizes.
 * PINTOOL_REGISTER* can be used instead of UINT8* inside analysis routines (for convenient access) for these IARGS:
 *  o IARG_REG_REFERENCE
 *  o IARG_REG_CONST_REFERENCE
 */
union PINTOOL_REGISTER
{
    UINT8 byte[MAX_BYTES_PER_PINTOOL_WIDE_REG];
    UINT16 word[MAX_WORDS_PER_PINTOOL_WIDE_REG];
    UINT32 dword[MAX_DWORDS_PER_PINTOOL_WIDE_REG];
    UINT64 qword[MAX_QWORDS_PER_PINTOOL_WIDE_REG];

    INT8 s_byte[MAX_BYTES_PER_PINTOOL_WIDE_REG];
    INT16 s_word[MAX_WORDS_PER_PINTOOL_WIDE_REG];
    INT32 s_dword[MAX_DWORDS_PER_PINTOOL_WIDE_REG];
    INT64 s_qword[MAX_QWORDS_PER_PINTOOL_WIDE_REG];

    FLT32 flt[MAX_FLOATS_PER_PINTOOL_WIDE_REG];
    FLT64 dbl[MAX_DOUBLES_PER_PINTOOL_WIDE_REG];
};

///////////////////////////
// FUNCTION DECLARATIONS
///////////////////////////

// Returns a string of the hex representation of the given "value" of length "size" bytes.
string Val2Str(const void* value, unsigned int size);

// Compare two values of length "size" bytes.
bool CompareValues(const void* value, const void* expected, unsigned int size, ostream& ost);

// Assign a PINTOOL_REGISTER object with a new value.
void AssignNewPinRegisterValue(PINTOOL_REGISTER* pinreg, const UINT64* newval, UINT qwords);

#endif // REGVALUE_UTILS_H
