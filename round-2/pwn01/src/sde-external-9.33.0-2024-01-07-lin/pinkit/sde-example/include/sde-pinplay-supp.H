//
// Copyright (C) 2017-2021 Intel Corporation.
// SPDX-License-Identifier: MIT
//
#if !defined(_SDE_PINPLAY_SUPP_H_)
#define _SDE_PINPLAY_SUPP_H_

#include <list>
#include "pin.H"
#include "pinplay.H"
#include "control_manager.H"

using namespace CONTROLLER;

class ISIMPOINT;

// callback definitions
typedef VOID (*INS_FETCH_CALLBACK)(ADDRINT pc, UINT8* instruction_bytes);
typedef VOID (*REG_MODIFY_CALLBACK)(REG reg, UINT8* value);
typedef VOID (*MEMORY_READ_CALLBACK)(ADDRINT addr, UINT32 size, UINT8* value);
typedef VOID (*MEMORY_WRITE_CALLBACK)(ADDRINT addr, UINT32 size, UINT8* value);

// Vectors of callbacks
typedef std::list<INS_FETCH_CALLBACK>    INS_FETCH_CALLBACK_LIST;
typedef std::list<REG_MODIFY_CALLBACK>   REG_MODIFY_CALLBACK_LIST;
typedef std::list<MEMORY_READ_CALLBACK>  MEMORY_READ_CALLBACK_LIST;
typedef std::list<MEMORY_WRITE_CALLBACK> MEMORY_WRITE_CALLBACK_LIST;

void sde_tracing_activate(int argc, char* argv[]);
void sde_isimpoint_activate(int argc, char* argv[]);
PINPLAY_ENGINE* sde_tracing_get_pinplay_engine();
ISIMPOINT* sde_tracing_get_isimpoint();
bool sde_is_tracing_active();
bool sde_is_replayer_active();
bool sde_is_logger_active();

// Thread id translation callback and accessors
void sde_set_thread_trans_callback(THREAD_TRANS_CALLBACK thread_trans_callback);
THREAD_TRANS_CALLBACK sde_get_thread_trans_callback();
THREADID sde_get_translated_tid(THREADID tid);

// Ring0 
bool sde_replay_ring0_active();

// instruction fetch callback accessors
void sde_add_ins_fetch_callback(INS_FETCH_CALLBACK ins_fetch_callback);
bool sde_found_ins_fetch_callback();
INS_FETCH_CALLBACK_LIST& sde_get_ins_fetch_callback_list();

// reg modify callback accessors
void sde_add_reg_modify_callback(REG_MODIFY_CALLBACK reg_modify_callback);
bool sde_found_reg_modify_callback();
REG_MODIFY_CALLBACK_LIST& sde_get_reg_modify_callback_list();

// virtual memory read callback accessors
void sde_add_vmemory_read_callback(MEMORY_READ_CALLBACK memory_read_callback);
bool sde_found_vmemory_read_callback();
MEMORY_READ_CALLBACK_LIST& sde_get_vmemory_read_callback_list();

// virtual memory write callback accessors
void sde_add_vmemory_write_callback(MEMORY_WRITE_CALLBACK memory_write_callback);
bool sde_found_vmemory_write_callback();
MEMORY_WRITE_CALLBACK_LIST& sde_get_vmemory_write_callback_list();

// physical memory read callback accessors
void sde_add_pmemory_read_callback(MEMORY_READ_CALLBACK memory_read_callback);
bool sde_found_pmemory_read_callback();
MEMORY_READ_CALLBACK_LIST& sde_get_pmemory_read_callback_list();

// physical memory write callback accessors
void sde_add_pmemory_write_callback(MEMORY_WRITE_CALLBACK memory_write_callback);
bool sde_found_pmemory_write_callback();
MEMORY_WRITE_CALLBACK_LIST& sde_get_pmemory_write_callback_list();

#endif
