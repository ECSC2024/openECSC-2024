//
// Copyright (C) 2022-2022 Intel Corporation.
// SPDX-License-Identifier: MIT
//

#ifndef _SDE_EMULATING_
#define _SDE_EMULATING_
#include "pin.H"
#include "sde-base-types.H"
#include "sde-portability.h"
namespace INSTLIB
{
// call set emulated API to indicate that some emulator is emulating the PC associated
// with this instruction.
void sde_set_emulated(INS ins);

// call is emulated API to find out if an instruction is being emulated by
// some SDE emulator.
bool sde_is_emulated(sde_uint64_t pc);

// mark that the address range from:to has no emulated instructions
// this is useful after IMG was unloaded from memory
void sde_clear_emulated_range(sde_uint64_t from, sde_uint64_t to);

} // namespace INSTLIB
#endif
