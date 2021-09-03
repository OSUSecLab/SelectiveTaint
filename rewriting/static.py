#!/usr/bin/python3

import angr
from IPython import embed
import capstone
from capstone import *
from capstone.x86_const import *
from capstone.x86 import *
import argparse
import os
import sys
from angr import SimProcedure
import time
import copy
import filecmp
import archinfo
import random
import subprocess
import gc
import networkx as nx
import time


class Info(object):
	def __init__(self):

		self.args = None
		
		self.binaryfile = None
		self.asmfile = None
		self.hexdumpfile = None
		self.readelffile = None
		
		self.funcaddr_para_access_map_tmp_file = None
		self.insn_para_access_map_tmp_file = None
		self.insn_stack_offset_map_tmp_file = None
		self.callsite_para_access_map_tmp_file = None
		self.deadcode_tmp_file = None
		self.func_summary_map_tmp_file = None
		self.insn_summary_map_tmp_file = None
		self.tainted_insn_output_file = None
		
		self.tainted_insn = None

		self.picflag = None
		self.project = None

		# a list of [section_name, section_type, section_address, section_offset, section_size]
		self.sectionsinfo = []

		# a dict from section_name to [section_name, section_type, section_address, section_offset, section_size]
		self.sectionsinfo_name_map = {}
		
		# data section names
		self.data_section_names = [".rodata", ".niprod", ".nipd", ".bss", ".tbss", ".data.rel.ro", ".data"]
		
		self.cond_uncond_jump_insn_oprands = ["jmp", "js", "jnp", "jge", "jbe", "jb", "jns", "jp", "jl", "ja", "jle", "jne", "jg", "je", "jae"]
		self.cond_uncond_jump_insn_addresses = []
		self.func_cond_uncond_jump_insn_addresses_map = {}
		
		self.uncond_jump_insn_oprands = ["jmp"]
		self.uncond_jump_insn_addresses = []
		self.func_uncond_jump_insn_addresses_map = {}

		self.cond_jump_insn_oprands = ["js", "jnp", "jge", "jbe", "jb", "jns", "jp", "jl", "ja", "jle", "jne", "jg", "je", "jae"]
		self.cond_jump_insn_addresses = []
		self.func_cond_jump_insn_addresses_map = {}
		
		self.func_explicit_non_fall_through_control_flow_targets_map = {}
		self.callsite_explicit_call_targets_map = {}

		# capstone insn list
		self.insns = []
		# instruction address to capstone insn map
		self.insnsmap = {}
		# list of instruction addresses
		self.insnaddrs = []
		# instruction address to objdump insn string line map
		self.insnlinesmap = {}
		# instruction address to objdump insn string line (excluding address and bytes) map
		self.insnstringsmap = {}

		self.func_list = []
		self.func_name_map = {}
		self.func_addr_map = {}
		self.func_addrs = []
		self.first_insn_addr = None
		self.last_insn_addr = None

		# func addr to a list of ret instruction addresses
		# [] if no ret
		self.func_rets_map = {}
		self.func_callsites_map = {}
		self.ret_insn_addresses = []
		self.func_ret_insn_addresses_map = {}
		self.jmp_insn_addresses = []
		self.func_jmp_insn_addresses_map = {}
		self.call_insn_addresses = []
		self.func_call_insn_addresses_map = {}

		
		# insn addr to its func addr map
		self.insn_func_map = {}
		
		self.func_name_argcount_map = {}
		self.func_addr_argcount_map = {}
		
		self.cfg = None
		
		# an insn addr to current rsp offset (from rsp in function start addr)
		# number to represent the offset
		self.insn_stack_offset_map = {}
		
		# a func addr to the parameter it accesses
		# 1 - 10 for ten parameters
		self.funcaddr_para_access_map = {}
		# insn addr to the parameter it accesses
		# 1 - 10 for ten parameters
		self.insn_para_access_map = {}
		
		# a func addr to a list of 0/1
		# 0: type not determined
		# 1: pointer
		self.funcaddr_para_details_map = {}

		self.bbendaddr_bbstartaddr_map = {}
		self.bbstartaddr_bbendaddr_map = {}
		
		self.unsolved_call_site_addrs = []
		self.unsolved_call_site_bb_addrs = []
		self.call_site_addrs = []
		self.call_site_bb_addrs = []
		self.unsolved_jmp_site_bb_addrs = []
		
		# call site addr (or unsolved jmp site addr) to the parameter it accesses
		# 1 - 10 for ten parameters
		self.callsite_para_access_map = {}
		
		# call site addr to a list of 0/1
		# 0: type not determined
		# 1: pointer
		self.callsite_para_details_map = {}
		
		# insn addr to a list of tainted global addresses map
		self.insn_addr_tainted_global_addresses_map = {}
		# insn addr to a list of registers map
		self.insn_addr_tainted_registers_map = {}
		# insn addr to a list of heap addresses (use malloc site) map
		self.insn_addr_tainted_heap_addresses_map = {}
		
		# insn addr to tainted or not
		self.insn_tainted_map = {}
		
		self.gpr = ["eax", "ebx", "ecx", "edx", "edi", "esi", "esp", "ebp"]
		
		# func addr to func summary map
		# func summary:
		# reg, stack (including paras), global or heap to a set of regs, stack(including paras), globals, or heaps
		# register is eax, ebx, ecx, edx, edi, esi, esp, ebp
		# stack is a number relative to esp at the function beginning state
		# note paras are stack variables, 0x4, 0x8, 0xc, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x28
		# global is address (0xyyyyyyyy or speical values GLOBAL_POINTER_0xyyyyyyyy)
		# heap is malloc insn addr (speical values HEAP_POINTER_0xyyyyyyyy and speical values HEAP_0xyyyyyyyy)
		# a special CLEAR for overwritten by some intermediate results
		# special values for called function side effects: CALLSITE_P1(-P10)_0x(callsite) and CALLSITE_EAX_0x(callsite)
		# the first is after the function
		# the second is before the function
		self.func_summary_map = {}
		
		# a more detailed summary for each insn
		self.insn_summary_map = {}

		# a networkx directed graph, each node is a func addr
		self.concise_callgraph = nx.DiGraph()
		
		# a simplified directed acyclic graph from self.concise_callgraph
		# by pruning some edges
		self.concise_callgraph_acyclic = nx.DiGraph()
		
		# call site addr to a set of callee addresses map
		self.callsite_map = {}
		
		# func addresses in reversed topological order (i.e., reversed CFG edges)
		self.ordered_func_addresses = []
		
		# how many times this funciton is processed in calculating summary
		# 0 if not processed
		#self.func_summary_proc_times_map = {}
		
		# code inside a function somehow can not be accessed within the function
		# might due to incomplete CFG within function, and not considering inter-procedural control flow transfer
		# or just dead code
		# a map from each insn to True/False
		# True: deadcode False: not deadcode
		self.deadcode = {}
		
		# tainted func is a function that might be tainted, might have one or more insn tainted
		# this is a map from tainted func addr to a set of value indicating where its taint comes from and goes to
		# might be paras 0x4, 0x8, 0xc, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x28, or "eax"
		# or from call sites: special values: CALLSITE_P1(-P10)_0x(callsite) and CALLSITE_EAX_0x(callsite)
		# or global or heap variable
		self.func_taintedvar_map = {}
		
		# a slim version of func_taintedvar_map, which do not consider any caller tainted vars
		# i.e., only summarize the tainted var by itself and callees
		#self.func_taintedvar_summary_map = {}
		
		# tainted func addr to a set of its tainted insn addr map
		#self.tainted_func_addr_tainted_insn_addr_map = {}
		
		# tainted insn addr to the a set of tainted value
		#self.tainted_insn_addr_tainted_value_map = {}
		
		# all tainted insn addresses
		self.tainted_insn_addresses = set()
		
		
		# typed
		self.mmin_data_section_addr = None
		self.mmax_data_section_addr = None
		
		self.func_summary_map_typed_tmp_file = None
		self.insn_summary_map_typed_tmp_file = None
		self.func_summary_map_typed = {}
		self.insn_summary_map_typed = {}
		
		self.tainted_insn_typed_output_file = None
		self.func_taintedvar_map_typed = {}
		self.tainted_insn_addresses_typed = set()
		
global info
info = Info()



def binary_static_taint():

	# check each function in reversed topological order
	# whether its paras, callees, globals, heaps are tainted and propagate
	# fix-point when info.func_taintedvar_map remains unchanged

	# data structure initialization
	info.func_taintedvar_map = {}
	#info.func_taintedvar_summary_map = {}
	info.tainted_insn_addresses = set()
	
	for func_addr in info.ordered_func_addresses:
		info.func_taintedvar_map[func_addr] = set()
		#info.func_taintedvar_summary_map[func_addr] = set()

	# taint source initialization
	for taintsource in info.args.taintsources:
		if taintsource == "read":
			#print(hex(info.func_name_map["read@plt"][0]))
			info.func_taintedvar_map[info.func_name_map["read@plt"][0]] = set([0x8])
			#info.func_taintedvar_summary_map[info.func_name_map["read@plt"][0]] = set([0x8])
		elif taintsource == "fread":
			#print(hex(info.func_name_map["fread@plt"][0]))
			info.func_taintedvar_map[info.func_name_map["fread@plt"][0]] = set([0x4])
			#info.func_taintedvar_summary_map[info.func_name_map["fread@plt"][0]] = set([0x4])
		elif taintsource == "fgetc":
			#print(hex(info.func_name_map["fgetc@plt"][0]))
			info.func_taintedvar_map[info.func_name_map["fgetc@plt"][0]] = set(["eax"])
			#info.func_taintedvar_summary_map[info.func_name_map["fgetc@plt"][0]] = set(["eax"])
		elif taintsource == "_IO_getc":
			#print(hex(info.func_name_map["fgetc@plt"][0]))
			info.func_taintedvar_map[info.func_name_map["_IO_getc@plt"][0]] = set(["eax"])
		elif taintsource == "fgets":
			#print(hex(info.func_name_map["fgetc@plt"][0]))
			info.func_taintedvar_map[info.func_name_map["fgets@plt"][0]] = set([0x4, "eax"])
		elif taintsource == "__isoc99_fscanf":
			#print(hex(info.func_name_map["fgetc@plt"][0]))
			info.func_taintedvar_map[info.func_name_map["__isoc99_fscanf@plt"][0]] = set([0x8, 0xc, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24])
		elif taintsource == "fscanf":
			#print(hex(info.func_name_map["fgetc@plt"][0]))
			info.func_taintedvar_map[info.func_name_map["fscanf@plt"][0]] = set([0xc, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x28])
		elif taintsource == "_ZNSi4readEPci":
			#print(hex(info.func_name_map["fgetc@plt"][0]))
			info.func_taintedvar_map[info.func_name_map["_ZNSi4readEPci@plt"][0]] = set([0x4])
		elif taintsource == "readv":
			info.func_taintedvar_map[info.func_name_map["readv@plt"][0]] = set([0x8])
		elif taintsource == "readlink":
			info.func_taintedvar_map[info.func_name_map["readlink@plt"][0]] = set([0x8])			
		elif taintsource == "pread64":
			info.func_taintedvar_map[info.func_name_map["pread64@plt"][0]] = set([0x8])	
		elif taintsource == "__fread_chk":
			info.func_taintedvar_map[info.func_name_map["__fread_chk@plt"][0]] = set([0x4])
		elif taintsource == "wgetch":
			info.func_taintedvar_map[info.func_name_map["wgetch@plt"][0]] = set(["eax"])
		elif taintsource == "getline":
			info.func_taintedvar_map[info.func_name_map["getline@plt"][0]] = set([0x4])
		elif taintsource == "__isoc99_scanf":
			info.func_taintedvar_map[info.func_name_map["__isoc99_scanf@plt"][0]] = set([0x8, 0xc, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24])
		elif taintsource == "recv":
			info.func_taintedvar_map[info.func_name_map["recv@plt"][0]] = set([0x8])
		elif taintsource == "gnutls_record_recv":
			info.func_taintedvar_map[info.func_name_map["gnutls_record_recv@plt"][0]] = set([0x8])	
		#jpeg_read_header
		#jpeg_read_raw_data
		#png_read_image




	# iterate
	#for i in range(1):
	while True:
	
		old_tainted_insn_addresses = copy.deepcopy(info.tainted_insn_addresses)
	
		# in reversed topological order
		for func_addr in info.ordered_func_addresses:
			func_name = info.func_addr_map[func_addr][0]
			func_end_addr = info.func_addr_map[func_addr][1]
			#print("binary_static_taint")
			#print("*")
			#print(func_name)
			#print(hex(func_addr))
			#print(hex(func_end_addr))
			
			if func_addr not in info.insnsmap:
				continue
			if func_addr not in info.cfg.kb.functions:
				continue
			if func_addr not in info.func_addr_map:
				continue
			#if func_addr != 0x807e0e0:
			#	continue
			#if func_addr != 0x8049b0e:
			#	continue
			#if func_addr != 0x8049baf:
			#	continue
			#if func_addr != 0x8049c25:
			#	continue
			#if func_addr != 0x8048ed0:
			#	continue
			#if func_addr != 0x804c410:
			#	continue
			#if func_addr != 0x804b271:
			#	continue
			
			#print("*")
			#print(func_name)
			#print(hex(func_addr))
			#print(hex(func_end_addr))



			# analyze each function and propagate
			
			#print(func_name)
			
			
			
			# find all callsites
			callsites = sorted(info.func_callsites_map[func_addr])
			
			#print("*")
			#print(hex(func_addr))
			#for callsite in callsites:
			#	print(hex(callsite))
			
			# find all func paras value
			func_para_values = []

			if func_addr in info.funcaddr_para_access_map:
				func_para_access = info.funcaddr_para_access_map[func_addr]
				func_para_index_set = set(range(func_para_access)).union(set([func_para_access])) - set([0])
				for func_para_index in sorted(func_para_index_set):
					func_para_values.append(int(4 * func_para_index))
			
			#print("**")
			#for func_para_value in func_para_values:
			#	print(hex(func_para_value))

			# find all call site paras value
			callsite_para_values_map = {}
			for callsite in callsites:
				# get esp value
				if callsite in info.insn_stack_offset_map:
					esp_value = info.insn_stack_offset_map[callsite]
					if callsite in info.callsite_para_access_map:
						callsite_para_access = info.callsite_para_access_map[callsite]
						callsite_para_values = []
						for callsite_para_index in range(callsite_para_access):
							callsite_para_values.append(int(4 * callsite_para_index + esp_value))
						callsite_para_values_map[callsite] = copy.deepcopy(callsite_para_values)
			
			#print("***")
			#for callsite in callsites:
			#	print(hex(callsite))
			#	for callsite_para_value in callsite_para_values_map[callsite]:
			#		print(hex(callsite_para_value))
			
			#print("1")
			#print(hex(func_addr))
			#print(info.func_taintedvar_map[func_addr])
			#print(info.func_taintedvar_summary_map[func_addr])
			
			while_true_start = time.time()
			while True:
				old_func_taintedvar_map = copy.deepcopy(info.func_taintedvar_map[func_addr])
				
				#print("2")
				#print(info.func_taintedvar_map[func_addr])
				#print(info.func_taintedvar_summary_map[func_addr])
				
				
				
				if not func_name.endswith("@plt"):
					# for each para
					#if func_addr in info.funcaddr_para_access_map and func_addr in info.func_summary_map:
					#	for func_para_value in func_para_values:
					#		if func_para_value in info.func_summary_map[func_addr]:
					#			if len(info.func_summary_map[func_addr][func_para_value].intersection(info.func_taintedvar_map[func_addr])) != 0:
					#				info.func_taintedvar_map[func_addr].add(func_para_value)
					# for ret
					#if func_addr in info.func_summary_map and "eax" in info.func_summary_map[func_addr]:
					#	if len(info.func_summary_map[func_addr]["eax"].intersection(info.func_taintedvar_map[func_addr])) != 0:
					#		info.func_taintedvar_map[func_addr].add("eax")
					
					# for each call site
					for callsite in callsites:
						#print(hex(callsite))
						if callsite in callsite_para_values_map and callsite in info.insn_summary_map and callsite in info.insn_stack_offset_map:
							#print(hex(callsite))
							esp_value = info.insn_stack_offset_map[callsite]
							
							# for each call site parameter
							for callsite_para_value in callsite_para_values_map[callsite]:
								
								# check how func paras flow to callsites
								# caller -> callee
								if callsite_para_value in info.insn_summary_map[callsite]:
									if len(info.insn_summary_map[callsite][callsite_para_value].intersection(info.func_taintedvar_map[func_addr])) != 0:
										#print("2.1")
										# add CALLSITE_P1(-P10)_0x(callsite) to caller
										callsite_para_index = int((callsite_para_value - esp_value) / 4 + 1)
										value = "CALLSITE_P" + str(callsite_para_index) + "_" + hex(callsite)
										info.func_taintedvar_map[func_addr].add(value)
										#print("2.2")
										# add para offset value to callee
										callee_para_value = int(callsite_para_index * 4)
										if callsite in info.callsite_map:
											for callee in sorted(info.callsite_map[callsite]):
												info.func_taintedvar_map[callee].add(callee_para_value)
												
												# update tainted call site parameter update
												# we do it here since we do not process plt func as non-plt func
												if callee in info.func_addr_map:
													callee_name = info.func_addr_map[callee][0]
													# if plt func
													if callee_name.endswith("@plt"):
														if callee_name == "memmove@plt":
															if 0x8 in info.func_taintedvar_map[callee] \
																and 0x4 not in info.func_taintedvar_map[callee]:
																info.func_taintedvar_map[callee] = copy.deepcopy( \
																	info.func_taintedvar_map[callee].union(set([0x4])))
														elif callee_name == "memcopy@plt":
															if 0x8 in info.func_taintedvar_map[callee] \
																and 0x4 not in info.func_taintedvar_map[callee]:
																info.func_taintedvar_map[callee] = copy.deepcopy( \
																info.func_taintedvar_map[callee].union(set([0x4])))
														elif callee_name == "memset@plt":
															if 0x8 in info.func_taintedvar_map[callee] \
																and 0x4 not in info.func_taintedvar_map[callee]:
																info.func_taintedvar_map[callee] = copy.deepcopy( \
																info.func_taintedvar_map[callee].union(set([0x4])))
														elif callee_name == "strcpy@plt":
															if 0x8 in info.func_taintedvar_map[callee] \
																and 0x4 not in info.func_taintedvar_map[callee]:
																info.func_taintedvar_map[callee] = copy.deepcopy( \
																info.func_taintedvar_map[callee].union(set([0x4])))
														elif callee_name == "strncpy@plt":
															if 0x8 in info.func_taintedvar_map[callee] \
																and 0x4 not in info.func_taintedvar_map[callee]:
																info.func_taintedvar_map[callee] = copy.deepcopy( \
																info.func_taintedvar_map[callee].union(set([0x4])))
														elif callee_name == "strtol@plt":
															if 0x4 in info.func_taintedvar_map[callee] \
																and (0x8 not in info.func_taintedvar_map[callee] \
																or "eax" not in info.func_taintedvar_map[callee]):
																info.func_taintedvar_map[callee] = copy.deepcopy( \
																info.func_taintedvar_map[callee].union(set([0x8, "eax"])))
														elif callee_name == "gcvt@plt":
															if 0x4 in info.func_taintedvar_map[callee] \
																and 0xc not in info.func_taintedvar_map[callee]:
																info.func_taintedvar_map[callee] = copy.deepcopy( \
																info.func_taintedvar_map[callee].union(set([0xc])))
												
										#print("2.3")		
										# add ret offset value to callee
										#if callsite in info.callsite_map:
										#	for callee in sorted(info.callsite_map[callsite]):
										#		if callee in info.func_summary_map and "eax" in info.func_summary_map[callee] \
										#			and callee_para_value in info.func_summary_map[callee]["eax"]:
										#			info.func_taintedvar_map[callee].add("eax")
													
								# check how callsites paras and rets flow to caller
								# callee -> caller
								callsite_para_index = int((callsite_para_value - esp_value) / 4 + 1)
								para_value = "CALLSITE_P" + str(callsite_para_index) + "_" + hex(callsite)
								# CALLSITE_EAX_0x(callsite)
								ret_value = "CALLSITE_EAX_" + hex(callsite)
								callee_para_value = int(callsite_para_index * 4)
								#print(hex(callsite))
								if callsite in info.callsite_map:
									for callee in sorted(info.callsite_map[callsite]):
										# if callee paras are tainted, add it to caller
										if callee_para_value in info.func_taintedvar_map[callee]:
											#print("2.4")
											#if isinstance(callee_para_value, int):
											#	print(hex(callee_para_value))
										
											# add CALLSITE_P1(-P10)_0x(callsite)
											info.func_taintedvar_map[func_addr].add(para_value)
											# add callsite_para_value
											info.func_taintedvar_map[func_addr].add(callsite_para_value)
											# add values inside callsite_para_value
											if callsite_para_value in info.insn_summary_map[callsite]:
												for stack_contained_value in info.insn_summary_map[callsite][callsite_para_value]:
													if stack_contained_value != "eax":
														info.func_taintedvar_map[func_addr].add(stack_contained_value)
													#if isinstance(stack_contained_value, int):
													#	print(hex(stack_contained_value))
										# if callee return value is tainted, add it to caller
										if "eax" in info.func_taintedvar_map[callee]:
											#print("2.5")
											# add CALLSITE_EAX_0x(callsite)
											info.func_taintedvar_map[func_addr].add(ret_value)
							
							# if callsite has no para
							if len(callsite_para_values_map[callsite]) == 0:
								#print(hex(callsite))
								ret_value = "CALLSITE_EAX_" + hex(callsite)
								if callsite in info.callsite_map:
									for callee in sorted(info.callsite_map[callsite]):
										# if callee return value is tainted, add it to caller
										if "eax" in info.func_taintedvar_map[callee]:
											#print("2.5")
											# add CALLSITE_EAX_0x(callsite)
											info.func_taintedvar_map[func_addr].add(ret_value)
							
							
						# after analyzing each call site, clear plt func taints except taint source func
						if callsite in info.callsite_map:
							for callee in sorted(info.callsite_map[callsite]):
								if callee in info.func_addr_map:
									callee_name = info.func_addr_map[callee][0]
									if callee_name.endswith("@plt"):
										callee_short_name = callee_name[:callee_name.index("@plt")]
										if callee_short_name not in info.args.taintsources:
											info.func_taintedvar_map[callee] = set()
				
				#print("3")
				#print(info.func_taintedvar_map[func_addr])
				#print(info.func_taintedvar_summary_map[func_addr])
				
				# add var containing tainted var to tainted vars
				func_gvars = set()
				addr = func_addr
				while addr <= func_end_addr and addr != -1:
					#print(hex(addr))
					if addr in info.insn_summary_map:
						for ab_loc in info.insn_summary_map[addr]:
							for ab_loc_1 in info.insn_summary_map[addr][ab_loc]:
								if ab_loc_1 in info.func_taintedvar_map[func_addr]:
									info.func_taintedvar_map[func_addr].add(ab_loc)
									
									#if ab_loc in info.gpr:
									#	#if ab_loc in info.insn_summary_map[addr][ab_loc]:
									#	#	info.func_taintedvar_map[func_addr].add(ab_loc)
									#	info.func_taintedvar_map[func_addr].add(ab_loc)
									#else:
									#	info.func_taintedvar_map[func_addr].add(ab_loc)
									
									#print("*")
									#if isinstance(ab_loc, int):
									#	print(hex(ab_loc))
									#else:
									#	print(ab_loc)
									#if isinstance(ab_loc_1, int):
									#	print(hex(ab_loc_1))
									#else:
									#	print(ab_loc_1)
									#break
						
							# collect gvars
							if isinstance(ab_loc, int) and ab_loc >= info.mmin_data_section_addr and ab_loc <= info.mmax_data_section_addr:
								func_gvars.add(ab_loc)
								#print("*")
								#print(hex(addr))
								#print(hex(ab_loc))
					addr = findnextinsaddr(addr)
				
				#print("4")
				#print(info.func_taintedvar_map[func_addr])
				
				# if global in tainted var, add global+0x100 to tainted var
				to_addr_gvars = set()
				for tainted_var in info.func_taintedvar_map[func_addr]:
					if isinstance(tainted_var, int):
						#print(hex(tainted_var))
						if tainted_var >= info.mmin_data_section_addr and tainted_var <= info.mmax_data_section_addr:
							for func_gvar in func_gvars:
								if isinstance(func_gvar, int):
									if func_gvar > tainted_var and func_gvar <= tainted_var + 0x100:
										to_addr_gvars.add(func_gvar)
				
				#for to_add_gvar in sorted(to_addr_gvars):
				#	print(hex(to_add_gvar))
					
				info.func_taintedvar_map[func_addr] = info.func_taintedvar_map[func_addr].union(to_addr_gvars)
				
				#print("5")
				#print(info.func_taintedvar_map[func_addr])
				
				#print("*")
				#for tainted_var in info.func_taintedvar_map[func_addr]:
				#	if isinstance(tainted_var, int):
				#		print(hex(tainted_var))
				#	else:
				#		print(tainted_var)
				
				if info.func_taintedvar_map[func_addr] == old_func_taintedvar_map:
						break
				# if time-out, also break
				while_true_end = time.time()
				while_true_time = while_true_end - while_true_start
				if while_true_time > 60:
					break
			
			#print("6")
			#print(info.func_taintedvar_map[func_addr])
			
			# update other functions using global variables
			tainted_gvars = set()
			for tainted_var in info.func_taintedvar_map[func_addr]:
				if isinstance(tainted_var, int):
					#print(hex(tainted_var))
					if tainted_var >= info.mmin_data_section_addr and tainted_var <= info.mmax_data_section_addr:
						tainted_gvars.add(tainted_var)
			
			for func_addr_1 in info.ordered_func_addresses:
				#func_name_1 = info.func_addr_map[func_addr_1][0]
				#func_end_addr_1 = info.func_addr_map[func_addr_1][1]
				#print("*")
				#print(func_name_1)
				#print(hex(func_addr_1))
				#print(hex(func_end_addr_1))
				if func_addr_1 not in info.insnsmap:
					continue
				if func_addr_1 not in info.cfg.kb.functions:
					continue
				if func_addr_1 not in info.func_addr_map:
					continue
				info.func_taintedvar_map[func_addr_1] = info.func_taintedvar_map[func_addr_1].union(tainted_gvars)
			
			
			
			# identify tainted insn based on tainted values for this function
			finish_to_next_insn_addr = False
			addr = func_addr
			while addr <= func_end_addr and addr != -1:
				
				ab_locs_containing_tainted_value = set()
				
				for ab_loc in info.insn_summary_map[addr]:
					# some ab loc contains tainted values
					if len(info.func_taintedvar_map[func_addr].intersection(info.insn_summary_map[addr][ab_loc])) != 0 and addr in info.insnsmap:
						ab_locs_containing_tainted_value.add(ab_loc)
						
						
				# check whether the tainted value is actually read/written in this insn
				# check ab_loc is register, stack, or glbal/heap
				
				# find all values used in insn
				values_used_set = set()
			
				if len(ab_locs_containing_tainted_value) != 0 and addr in info.insnsmap:
					insn = info.insnsmap[addr]
					# insn has one operand
					if len(insn.operands) == 1 and insn.operands[0].type == X86_OP_REG:
						#print("*")
						#print(hex(addr))
						#print(insn.mnemonic)
						#print(insn.op_str)
						#print(insn.reg_name(insn.operands[0].value.reg))
						reg_name = insn.reg_name(insn.operands[0].value.reg)
						if reg_name in info.gpr:
							#print(reg_name)
							values_used_set.add(reg_name)
					elif len(insn.operands) == 2:
						#print("*")
						#print(hex(addr))
						#print(insn.mnemonic)
						#print(insn.op_str)
						#print(insn.operands[0].type)
						#print(insn.operands[1].type)
						if insn.mnemonic.startswith("test") or insn.mnemonic.startswith("cmp"):
							pass
						elif insn.mnemonic.startswith("mov") or insn.mnemonic.startswith("cmove") or insn.mnemonic.startswith("lea"):
							#print("*")
							#print(hex(addr))
							#print(insn.mnemonic)
							#print(insn.op_str)
							#print(insn.operands[0].type)
							#print(insn.operands[1].type)
							if insn.operands[0].type == X86_OP_REG and insn.operands[1].type == X86_OP_REG:
								dest_reg_name = insn.reg_name(insn.operands[0].value.reg)
								src_reg_name = insn.reg_name(insn.operands[1].value.reg)
								values_used_set.add(dest_reg_name)
								values_used_set.add(src_reg_name)
										
							elif insn.operands[0].type == X86_OP_REG and insn.operands[1].type == X86_OP_MEM:
								dest_reg_name = insn.reg_name(insn.operands[0].value.reg)
								src_op = insn.operands[1]
								#print("*")
								#print(hex(addr))
								#print(insn.mnemonic)
								#print(insn.op_str)
								#print(insn.operands[0].type)
								#print(insn.operands[1].type)
								
								# lea insn
								if insn.mnemonic.startswith("lea") and dest_reg_name in info.gpr:
									# lea insn: check whether lea global var addr and generate global var pointer
									if src_op.value.mem.disp >= info.mmin_data_section_addr \
									and src_op.value.mem.disp <= info.mmax_data_section_addr:
										#print("*")
										#print(hex(addr))
										#print(hex(src_op.value.mem.disp))
										values_used_set.add(dest_reg_name)
										values_used_set.add(value)
										# add global var pointer to dest op reg
										value = "GLOBAL_POINTER_" + hex(src_op.value.mem.disp)
										values_used_set.add(dest_reg_name)
										values_used_set.add(value)
									else:
										values_used_set.add(dest_reg_name)
								
								# mov/cmov insn
								if (insn.mnemonic.startswith("mov") or insn.mnemonic.startswith("cmove")) and dest_reg_name in info.gpr:
									
									if src_op.value.mem.base != 0:
										src_op_base_reg_name = info.insnsmap[addr].reg_name(src_op.value.mem.base)
										
										# mov stack var via base
										if src_op_base_reg_name == "esp" and src_op.value.mem.index == 0:
											#print(src_op.value.mem.disp)
											if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
												value = info.insn_stack_offset_map[addr] + src_op.value.mem.disp
												#print("*")
												#print(hex(addr))
												#print(value)
												values_used_set.add(dest_reg_name)
												values_used_set.add(value)
											else:
												values_used_set.add(dest_reg_name)
										
										# mov global var via disp
										elif src_op.value.mem.disp >= info.mmin_data_section_addr \
											and src_op.value.mem.disp <= info.mmax_data_section_addr:
											#print("*")
											#print(hex(addr))
											#print(hex(src_op.value.mem.disp))
											# add global var to dest op reg
											value = src_op.value.mem.disp
											values_used_set.add(dest_reg_name)
											values_used_set.add(value)
										
										# mov global/heap var via base, i.e., dereference global/heap var pointer
										elif addr in info.insn_summary_map and src_op_base_reg_name in info.insn_summary_map[addr]:
											dereference = False
											for base_reg_value in info.insn_summary_map[addr][src_op_base_reg_name]:
												if not isinstance(base_reg_value, int):
													# global pointer dereference
													if base_reg_value.startswith("GLOBAL_POINTER_"):
														gvar_addr_string = base_reg_value[15:]
														gvar_addr = int(gvar_addr_string, 16)
														#print("*")
														#print(hex(addr))
														#print(gvar_addr_string)
														#print(hex(gvar_addr))
														
														# add global var to dest op reg
														value = gvar_addr
														values_used_set.add(dest_reg_name)
														values_used_set.add(value)
														dereference = True
														break
														
													# heap pointer dereference
													elif base_reg_value.startswith("HEAP_POINTER_"):
														hvar_addr_string = base_reg_value[13:]
														hvar_addr = int(hvar_addr_string, 16)
														#print("*")
														#print(hex(addr))
														#print(hvar_addr_string)
														#print(hex(hvar_addr))
														
														# add global var to dest op reg
														value = "HEAP_" + hex(hvar_addr)
														values_used_set.add(dest_reg_name)
														values_used_set.add(value)
														dereference = True
														break
											if dereference == False:
												values_used_set.add(dest_reg_name)
										else:
											values_used_set.add(dest_reg_name)

									elif src_op.value.mem.base == 0:
										# mov stack var via index
										if src_op.value.mem.index != 0 and info.insnsmap[addr].reg_name(src_op.value.mem.index) == "esp":
											if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
												value = info.insn_stack_offset_map[addr] * src_op.value.mem.scale + src_op.value.mem.disp
												#print(info.insn_stack_offset_map[addr])
												#print(op.value.mem.scale)
												#print(op.value.mem.disp)
												#print("*")
												#print(hex(addr))
												#print(value)
												values_used_set.add(dest_reg_name)
												values_used_set.add(value)
										# mov stack/global via disp
										elif src_op.value.mem.index == 0:
											#print("*")
											#print(hex(addr))
											#print(insn.mnemonic)
											#print(insn.op_str)
											#print(hex(src_op.value.mem.disp))
											
											# stack or global var dereference
											value = src_op.value.mem.disp
											values_used_set.add(dest_reg_name)
											values_used_set.add(value)
										else:
											values_used_set.add(dest_reg_name)
									else:
										values_used_set.add(dest_reg_name)
							elif insn.operands[0].type == X86_OP_REG and insn.operands[1].type == X86_OP_IMM:
								dest_reg_name = insn.reg_name(insn.operands[0].value.reg)
								if dest_reg_name in info.gpr:
									values_used_set.add(dest_reg_name)
							elif insn.operands[0].type == X86_OP_MEM and insn.operands[1].type == X86_OP_REG:
								src_reg_name = insn.reg_name(insn.operands[1].value.reg)
								dest_op = insn.operands[0]
								
								# all mov/cmov, no lea, as dest is mem
								
								if dest_op.value.mem.base != 0 and src_reg_name in info.gpr:
								
									dest_op_base_reg_name = info.insnsmap[addr].reg_name(dest_op.value.mem.base)
								
									# mov into stack var via base
									if dest_op_base_reg_name == "esp" and dest_op.value.mem.index == 0:
										#print(dest_op.value.mem.disp)
										if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
											value = info.insn_stack_offset_map[addr] + dest_op.value.mem.disp
											#print("*")
											#print(hex(addr))
											#print(value)
											values_used_set.add(src_reg_name)
											values_used_set.add(value)
												
									# mov into global var via disp
									elif dest_op.value.mem.disp >= info.mmin_data_section_addr \
										and dest_op.value.mem.disp <= info.mmax_data_section_addr:
										#print("*")
										#print(hex(addr))
										#print(hex(dest_op.value.mem.disp))
										# add global var to dest
										value = dest_op.value.mem.disp
										values_used_set.add(src_reg_name)
										values_used_set.add(value)
									
									# mov global/heap var via base, i.e., dereference global/heap var pointer
									elif addr in info.insn_summary_map and dest_op_base_reg_name in info.insn_summary_map[addr]:
										for base_reg_value in info.insn_summary_map[addr][dest_op_base_reg_name]:
											if not isinstance(base_reg_value, int):
												# global pointer dereference
												if base_reg_value.startswith("GLOBAL_POINTER_"):
													gvar_addr_string = base_reg_value[15:]
													gvar_addr = int(gvar_addr_string, 16)
													#print("*")
													#print(hex(addr))
													#print(gvar_addr_string)
													#print(hex(gvar_addr))
													
													# add global var to dest op reg
													value = gvar_addr
													#print("*")
													#print(hex(addr))
													#print(insn.mnemonic)
													#print(insn.op_str)
													#print(hex(dest_op.value.mem.disp))
													values_used_set.add(src_reg_name)
													values_used_set.add(value)
													break
													
												# heap pointer dereference
												elif base_reg_value.startswith("HEAP_POINTER_"):
													hvar_addr_string = base_reg_value[13:]
													hvar_addr = int(hvar_addr_string, 16)
													#print("*")
													#print(hex(addr))
													#print(hvar_addr_string)
													#print(hex(hvar_addr))
													
													# add global var to dest op reg
													value = hvar_addr
													#print("*")
													#print(hex(addr))
													#print(insn.mnemonic)
													#print(insn.op_str)
													#print(hex(dest_op.value.mem.disp))
													values_used_set.add(src_reg_name)
													values_used_set.add(value)
													break	
									
									
								elif dest_op.value.mem.base == 0 and src_reg_name in info.gpr:

									# mov into stack var via index
									if dest_op.value.mem.index != 0 and info.insnsmap[addr].reg_name(dest_op.value.mem.index) == "esp":
										if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
											value = info.insn_stack_offset_map[addr] * dest_op.value.mem.scale + dest_op.value.mem.disp
											#print(info.insn_stack_offset_map[addr])
											#print(op.value.mem.scale)
											#print(op.value.mem.disp)
											#print("*")
											#print(hex(addr))
											#print(value)
											values_used_set.add(src_reg_name)
											values_used_set.add(value)
									# mov into stack/global via disp
									elif dest_op.value.mem.index == 0:
										value = dest_op.value.mem.disp
										#print("*")
										#print(hex(addr))
										#print(insn.mnemonic)
										#print(insn.op_str)
										#print(hex(dest_op.value.mem.disp))
										values_used_set.add(src_reg_name)
										values_used_set.add(value)
														
							elif insn.operands[0].type == X86_OP_MEM and insn.operands[1].type == X86_OP_IMM:
								dest_op = insn.operands[0]
								
								# all mov/cmov, no lea, as dest is mem
								
								if dest_op.value.mem.base != 0:
									dest_op_base_reg_name = info.insnsmap[addr].reg_name(dest_op.value.mem.base)
									
									# mov into stack var via base
									if dest_op_base_reg_name == "esp" and dest_op.value.mem.index == 0:
										#print(dest_op.value.mem.disp)
										if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
											value = info.insn_stack_offset_map[addr] + dest_op.value.mem.disp
											#print("*")
											#print(hex(addr))
											#print(value)
											values_used_set.add(value)
									
									# mov into global var via disp
									elif dest_op.value.mem.disp >= info.mmin_data_section_addr \
										and dest_op.value.mem.disp <= info.mmax_data_section_addr:
										#print("*")
										#print(hex(addr))
										#print(hex(dest_op.value.mem.disp))
										# clear dest
										value = dest_op.value.mem.disp
										values_used_set.add(value)
									
									# mov global/heap var via base, i.e., dereference global/heap var pointer
									elif addr in info.insn_summary_map and dest_op_base_reg_name in info.insn_summary_map[addr]:
										for base_reg_value in info.insn_summary_map[addr][dest_op_base_reg_name]:
											if not isinstance(base_reg_value, int):
												# global pointer dereference
												if base_reg_value.startswith("GLOBAL_POINTER_"):
													gvar_addr_string = base_reg_value[15:]
													gvar_addr = int(gvar_addr_string, 16)
													#print("*")
													#print(hex(addr))
													#print(gvar_addr_string)
													#print(hex(gvar_addr))
													# clear dest op reg
													value = gvar_addr
													values_used_set.add(value)
													break
												# heap pointer dereference
												elif base_reg_value.startswith("HEAP_POINTER_"):
													hvar_addr_string = base_reg_value[13:]
													hvar_addr = int(hvar_addr_string, 16)
													#print("*")
													#print(hex(addr))
													#print(hvar_addr_string)
													#print(hex(hvar_addr))
													# clear dest op reg
													value = hvar_addr
													values_used_set.add(value)
													break
								else:
									# mov into stack var via index
									if dest_op.value.mem.index != 0 and info.insnsmap[addr].reg_name(dest_op.value.mem.index) == "esp":
										if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
											value = info.insn_stack_offset_map[addr] * dest_op.value.mem.scale + dest_op.value.mem.disp
											#print(info.insn_stack_offset_map[addr])
											#print(op.value.mem.scale)
											#print(op.value.mem.disp)
											#print("*")
											#print(hex(addr))
											#print(value)
											values_used_set.add(value)
									
									# mov into stack/global via disp
									elif dest_op.value.mem.index == 0:
										value = dest_op.value.mem.disp
										#print("*")
										#print(hex(addr))
										#print(hex(value))
										values_used_set.add(value)
														
						else:
							if insn.operands[0].type == X86_OP_REG:
								dest_reg_name = insn.reg_name(insn.operands[0].value.reg)
								if dest_reg_name in info.gpr:
									values_used_set.add(dest_reg_name)
							elif insn.operands[0].type == X86_OP_MEM:
								dest_op = insn.operands[0]
								
								value = None
								
								if dest_op.value.mem.base != 0:
									dest_op_base_reg_name = info.insnsmap[addr].reg_name(dest_op.value.mem.base)
									
									# dest mem: stack var via base
									if info.insnsmap[addr].reg_name(dest_op.value.mem.base) == "esp" and dest_op.value.mem.index == 0:
										#print(dest_op.value.mem.disp)
										if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
											value = info.insn_stack_offset_map[addr] + dest_op.value.mem.disp
											#print("*")
											#print(hex(addr))
											#print(value)
											values_used_set.add(value)
											
									# dest mem: global var via disp
									elif dest_op.value.mem.disp >= info.mmin_data_section_addr \
										and dest_op.value.mem.disp <= info.mmax_data_section_addr:
										#print("*")
										#print(hex(addr))
										#print(hex(dest_op.value.mem.disp))
										# clear dest
										value = dest_op.value.mem.disp
										values_used_set.add(value)
										
									# dest mem: global/heap var via base, i.e., dereference global/heap var pointer
									elif addr in info.insn_summary_map and dest_op_base_reg_name in info.insn_summary_map[addr]:
										for base_reg_value in info.insn_summary_map[addr][dest_op_base_reg_name]:
											if not isinstance(base_reg_value, int):
												# global pointer dereference
												if base_reg_value.startswith("GLOBAL_POINTER_"):
													gvar_addr_string = base_reg_value[15:]
													gvar_addr = int(gvar_addr_string, 16)
													#print("*")
													#print(hex(addr))
													#print(gvar_addr_string)
													#print(hex(gvar_addr))
													# clear dest op reg
													value = gvar_addr
													values_used_set.add(value)
													break
												# heap pointer dereference
												elif base_reg_value.startswith("HEAP_POINTER_"):
													hvar_addr_string = base_reg_value[13:]
													hvar_addr = int(hvar_addr_string, 16)
													#print("*")
													#print(hex(addr))
													#print(hvar_addr_string)
													#print(hex(hvar_addr))
													# clear dest op reg
													value = hvar_addr
													values_used_set.add(value)
													break
								
								else:
									# dest mem: stack var via index
									if dest_op.value.mem.index != 0 and info.insnsmap[addr].reg_name(dest_op.value.mem.index) == "esp":
										if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
											value = info.insn_stack_offset_map[addr] * dest_op.value.mem.scale + dest_op.value.mem.disp
											#print(info.insn_stack_offset_map[addr])
											#print(op.value.mem.scale)
											#print(op.value.mem.disp)
											#print("*")
											#print(hex(addr))
											#print(value)
											values_used_set.add(value)
									# dest mem: stack/global via disp
									elif dest_op.value.mem.index == 0:
										value = dest_op.value.mem.disp
										#print("*")
										#print(hex(addr))
										#print(hex(value))
										values_used_set.add(value)
								
				if len(values_used_set.intersection(ab_locs_containing_tainted_value)) != 0:
					info.tainted_insn_addresses.add(addr)
					#print("*")
					#print(hex(addr))
					#print(values_used_set)
					#print(ab_locs_containing_tainted_value)

				
				# add original taint sources to tainted insn addresses
				if addr in info.callsite_map and len(info.callsite_map[addr]) >= 1:
					callee_addr = list(info.callsite_map[addr])[0]
					if callee_addr in info.func_addr_map:
						callee_name = list(info.func_addr_map[callee_addr])[0]
						if callee_name.endswith("@plt"):
							callee_short_name = callee_name[:callee_name.index("@plt")]
							if callee_short_name in info.args.taintsources:
								info.tainted_insn_addresses.add(addr)
				
				addr = findnextinsaddr(addr)
				
			
			#for tainted_insn_addr in sorted(info.tainted_insn_addresses):
			#	print(hex(tainted_insn_addr))
				

				
		if info.tainted_insn_addresses == old_tainted_insn_addresses:
			break
			
		
	#for func_addr in info.func_taintedvar_map:
	#	print("*")
	#	print(hex(func_addr))
	#	for ab_loc in info.func_taintedvar_map[func_addr]:
	#		if isinstance(ab_loc, int):
	#			print(hex(ab_loc))
	#		else:
	#			print(ab_loc)
				
			

	#print("+++++")
	#for tainted_insn_addr in sorted(info.tainted_insn_addresses):
	#	print(hex(tainted_insn_addr))

	info.tainted_insn_output_file = info.binaryfile + "_tainted_insn_output_file"
	f = open(info.tainted_insn_output_file, "w")
	for tainted_insn_addr in sorted(info.tainted_insn_addresses):
		f.write(hex(tainted_insn_addr) + "\n")
	f.close()


def generate_function_summary():


	info.func_summary_map_tmp_file = info.binaryfile + "_func_summary_map_tmp_file"
	info.insn_summary_map_tmp_file = info.binaryfile + "_insn_summary_map_tmp_file"

	if os.path.exists(info.func_summary_map_tmp_file) and os.path.exists(info.insn_summary_map_tmp_file):
	
		info.func_summary_map = {}
		for func_addr in sorted(info.func_addr_map):
			info.func_summary_map[func_addr] = {}

		f = open(info.func_summary_map_tmp_file, "r")
		lines = f.readlines()

		func_addr = None
		key = None
		value = set()
		
		line_num = 0
		
		parse_func_addr = False
		parse_key = False
		parse_value = False
		
		key_count = 0
		value_count = None


		for line in lines:
			#print(line)
			l = line.strip()
			#print(l)
			if "*" in line:
				if func_addr:
					if key_count != 0:
						info.func_summary_map[func_addr][key] = copy.deepcopy(value)
					func_addr = None
					key = None
					value = set()
					key_count = 0
					parse_value = False
				parse_func_addr = True
			elif parse_func_addr == True:
				func_addr = int(l, 16)
				parse_func_addr = False
			elif line.startswith("+"):
				value_count = int(l[1:-1], 10)
				parse_value = False
				parse_key = True
				if key_count != 0:
					info.func_summary_map[func_addr][key] = copy.deepcopy(value)
				key_count = key_count + 1
			elif parse_key == True:
				try:
					key = int(l, 16)
				except:
					key = l
				value = set()
				parse_key = False
				parse_value = True
			elif parse_value == True:
				try:
					value.add(int(l, 16))
				except:
					value.add(l)
			if line_num == len(lines) - 1:
				if key_count != 0:
					info.func_summary_map[func_addr][key] = copy.deepcopy(value)
				func_addr = None
				key = None
				value = set()
				key_count = 0
				parse_value = False

			line_num = line_num + 1

		f.close()
		
		#for addr in sorted(info.func_summary_map):
		#	print("*")
		#	print(hex(addr))
		#	for ab_loc in info.func_summary_map[addr]:
		#		print("+" + str(len(info.func_summary_map[addr][ab_loc])) + "+")
		#		if isinstance(ab_loc, int):
		#			print(hex(ab_loc))
		#		else:
		#			print(ab_loc)
		#		for ab_loc_1 in info.func_summary_map[addr][ab_loc]:
		#			if isinstance(ab_loc_1, int):
		#				print(hex(ab_loc_1))
		#			else:
		#				print(ab_loc_1)


		info.insn_summary_map = {}
		
		for func_addr in info.ordered_func_addresses:
			func_name = info.func_addr_map[func_addr][0]
			func_end_addr = info.func_addr_map[func_addr][1]
			#print("*")
			#print(func_name)
			#print(hex(func_addr))
			#print(hex(func_end_addr))
			
			if func_addr not in info.insnsmap:
				continue
			if func_addr not in info.cfg.kb.functions:
				continue
			if func_addr not in info.func_addr_map:
				continue
			
			#print("*")
			#print(func_name)
			#print(hex(func_addr))
			#print(hex(func_end_addr))
			
			addr = func_addr
			while addr <= func_end_addr and addr != -1:
				info.insn_summary_map[addr] = {}
				addr = findnextinsaddr(addr)
		
		f = open(info.insn_summary_map_tmp_file, "r")
		lines = f.readlines()

		addr = None
		key = None
		value = set()
		
		line_num = 0
		
		parse_addr = False
		parse_key = False
		parse_value = False
		
		key_count = 0
		value_count = None


		for line in lines:
			#print(line)
			l = line.strip()
			#print(l)
			if "*" in line:
				if addr:
					if key_count != 0:
						info.insn_summary_map[addr][key] = copy.deepcopy(value)
					addr = None
					key = None
					value = set()
					key_count = 0
					parse_value = False
				parse_addr = True
			elif parse_addr == True:
				addr = int(l, 16)
				parse_addr = False
			elif line.startswith("+"):
				value_count = int(l[1:-1], 10)
				parse_value = False
				parse_key = True
				if key_count != 0:
					info.insn_summary_map[addr][key] = copy.deepcopy(value)
				key_count = key_count + 1
			elif parse_key == True:
				try:
					key = int(l, 16)
				except:
					key = l
				value = set()
				parse_key = False
				parse_value = True
			elif parse_value == True:
				try:
					value.add(int(l, 16))
				except:
					value.add(l)
			if line_num == len(lines) - 1:
				if key_count != 0:
					info.insn_summary_map[addr][key] = copy.deepcopy(value)
				addr = None
				key = None
				value = set()
				key_count = 0
				parse_value = False

			line_num = line_num + 1

		f.close()
		
		#for addr in sorted(info.insn_summary_map):
		#	print("*")
		#	print(hex(addr))
		#	for ab_loc in info.insn_summary_map[addr]:
		#		print("+" + str(len(info.insn_summary_map[addr][ab_loc])) + "+")
		#		if isinstance(ab_loc, int):
		#			print(hex(ab_loc))
		#		else:
		#			print(ab_loc)
		#		for ab_loc_1 in info.insn_summary_map[addr][ab_loc]:
		#			if isinstance(ab_loc_1, int):
		#				print(hex(ab_loc_1))
		#			else:
		#				print(ab_loc_1)

		return


	# check whether CFG is updated
	if len(info.ordered_func_addresses) == 0:
		update_CFG()

	for func_addr in sorted(info.func_addr_map):
		info.func_summary_map[func_addr] = {}


	# generate func summary for all functions first

	# iterate
	for i in range(1):
		# in reversed topological order
		for func_addr in info.ordered_func_addresses:
			func_name = info.func_addr_map[func_addr][0]
			func_end_addr = info.func_addr_map[func_addr][1]
			#print("*")
			#print(func_name)
			#print(hex(func_addr))
			#print(hex(func_end_addr))
			
			if func_addr not in info.insnsmap:
				continue
			if func_addr not in info.cfg.kb.functions:
				continue
			if func_addr not in info.func_addr_map:
				continue
			#if func_addr != 0x807e0e0:
			#	continue
			#if func_addr != 0x8049b0e:
			#	continue
			#if func_addr != 0x8049baf:
			#	continue
			#if func_addr != 0x8049c25:
			#	continue
			#if func_addr != 0x8048ed0:
			#	continue
			#if func_addr != 0x804d7c0:
			#	continue
			
			#print("*")
			#print(func_name)
			#print(hex(func_addr))
			#print(hex(func_end_addr))
			
			# run liveness analysis on each function
			
			# local bookkeeping
			# insn addr to insn summary map
			# insn summary:
			# reg, stack (including paras), global or heap to a set of regs, stack(including paras), globals, or heaps
			# register is eax, ebx, ecx, edx, edi, esi, esp, ebp
			# stack is a number relative to esp at the function beginning state
			# note paras are stack variables, 0x4, 0x8, 0xc, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x28
			# global is address (0xyyyyyyyy or speical values GLOBAL_POINTER_0xyyyyyyyy)
			# heap is malloc insn addr (speical values HEAP_POINTER_0xyyyyyyyy and speical values HEAP_0xyyyyyyyy)
			# a special CLEAR for overwritten by some intermediate results
			# special values for called function side effects: CALLSITE_P1(-P10)_0x(callsite) and CALLSITE_EAX_0x(callsite)
			# the first is after the instructions up to and excluding current insn
			# the second is the function beginning state
			insn_summary_map = {}
			
			addr = func_addr
			while addr <= func_end_addr and addr != -1:
				insn_summary_map[addr] = {}
				info.insn_summary_map[addr] = {}
				addr = findnextinsaddr(addr)
			
			insn_summary_map[func_addr] = {}
			
			# traverse the CFG
			for j in range(1):
				addr = func_addr
				while addr <= func_end_addr and addr != -1:
					#print("*")
					#print(hex(addr))
					# update which successor
					succs = []
					is_call_insn = False
					callsite_para_ab_locs = []
					
					if addr not in info.bbendaddr_bbstartaddr_map:
						if findnextinsaddr(addr) != -1:
							nextaddr = findnextinsaddr(addr)
							if nextaddr >= func_addr and nextaddr <= func_end_addr:
								succs.append(nextaddr)
					else:
						if addr in info.insnsmap:
							insn = info.insnsmap[addr]
							# skip the call for now
							if insn.mnemonic.startswith("call"):
								# find out fall through address
								if findnextinsaddr(addr) != -1:
									nextaddr = findnextinsaddr(addr)
									if nextaddr >= func_addr and nextaddr <= func_end_addr:
										succs.append(nextaddr)
										
								#print("*")
								#print(hex(func_addr))
								#print(hex(addr))
								#print(str(info.callsite_para_access_map[addr]))
								#print(info.insn_stack_offset_map[addr])
								#print("+")
								is_call_insn = True
								if addr in info.callsite_para_access_map and addr in info.insn_stack_offset_map:
									call_insn_para_access = info.callsite_para_access_map[addr]
									call_insn_esp_value = info.insn_stack_offset_map[addr]
									for index in range(call_insn_para_access):
										ab_loc = call_insn_esp_value + index * 4
										#print(str(ab_loc))
										callsite_para_ab_locs.append([int(ab_loc), int(index + 1)])
									#print(callsite_para_ab_locs)
							else:
								if func_addr in info.cfg.kb.functions:
									#print(hex(addr))
									if info.cfg.model.get_any_node(info.bbendaddr_bbstartaddr_map[addr]) != None:
										for succ in info.cfg.model.get_any_node(info.bbendaddr_bbstartaddr_map[addr]).successors:
											if succ.addr >= func_addr and succ.addr <= func_end_addr:
												succs.append(succ.addr)
					
					#print(hex(findnextinsaddr(addr)))
					#print("succs:")
					#for succ in succs:
					#	print(hex(succ))
					#print("*")
					

					# update each successor insn
					for succ in succs:
					
						# deadcode do not flow to non-dead code
						#if info.deadcode[addr] == True and info.deadcode[succ] == False:
						#	continue
							
						#print("*")
						#print(hex(addr))
						#print(info.deadcode[addr])
						#print(hex(succ))
						#print(info.deadcode[succ])
					
						# old insn summary, this might come from other incoming edges
						old = copy.deepcopy(insn_summary_map[succ])
						
						# copy whole thing first, we'll remove some copied values later
						for ab_loc in insn_summary_map[addr]:
							if ab_loc not in insn_summary_map[succ]:
								insn_summary_map[succ][ab_loc] = set()
							insn_summary_map[succ][ab_loc] = insn_summary_map[succ][ab_loc].union(copy.deepcopy(insn_summary_map[addr][ab_loc]))
						
						#if addr == 0x807e13f and succ == 0x807e118:
						#	print("*")
						#	print(insn_summary_map[addr])
						#	print(insn_summary_map[succ])
						
						# if addr is call insn, add special function parameters and return values to succ
						if is_call_insn == True:
						
							# check the callees' summary, see whether they affect the parameters and return values (whether they return)
							#para_count = len(callsite_para_ab_locs)
							#para_affected = set()
							#func_return = False
							#to_bbs = []
							
							#if addr in info.unsolved_call_site_addrs:
							#	para_affected = copy.deepcopy((para_affected.union(set(range(para_count))) - set([0])).union(set([para_count])))
							#	func_return = True
							#else:
							#	call_insn_bb_addr = info.bbendaddr_bbstartaddr_map[addr]
							#	from_bb = info.cfg.model.get_any_node(call_insn_bb_addr)
							#	to_bbs = []
							#	if from_bb != None:
							#		to_bbs = from_bb.successors
								
							#	if len(to_bbs) == 0:
							#		para_affected = copy.deepcopy((para_affected.union(set(range(para_count))) - set([0])).union(set([para_count])))
							#		func_return = True
							#	else:
									
							#		for to_bb in to_bbs:
							#			to_func_addr = to_bb.addr
							#			for para in range(para_count):
							#				if (para + 1) * 4 in info.func_summary_map[to_func_addr]:
							#					para_affected.add(para + 1)
							#			if "eax" in info.func_summary_map[to_func_addr]:
							#				func_return = True
							
							
							#print("*")
							#print(hex(addr))
							#print(hex(succ))
							#print(para_affected)
							#print(func_return)
							#print(info.insn_stack_offset_map[addr])
							#print(callsite_para_ab_locs)
							#if len(to_bbs) != 0:
							#	print("+")
							#	for to_bb in sorted(to_bbs):
							#		print(hex(to_bb.addr))
								
							# update value in callsite paras ab locs
							for callsite_para_ab_loc in callsite_para_ab_locs:
								#if callsite_para_ab_loc[1] in para_affected:
								#print(callsite_para_ab_loc)
								added_value = "CALLSITE_P" + str(callsite_para_ab_loc[1]) + "_" + hex(addr)
								added_value_set = set()
								added_value_set.add(added_value)
								
								
								ab_loc = callsite_para_ab_loc[0]
								if ab_loc not in insn_summary_map[succ]:
									insn_summary_map[succ][ab_loc] = set()
								if ab_loc not in insn_summary_map[addr]:
									insn_summary_map[addr][ab_loc] = set([ab_loc])
								if ab_loc not in old:
									old[ab_loc] = set()
								#insn_summary_map[succ][ab_loc] = \
								#	copy.deepcopy((insn_summary_map[succ][ab_loc].union(added_value_set) - \
								#	insn_summary_map[addr][ab_loc]).union(old[ab_loc]))
									
								insn_summary_map[succ][ab_loc] = \
									copy.deepcopy(insn_summary_map[succ][ab_loc].union(added_value_set))
									
								#print("*")
								#print(hex(succ))
								#print(hex(ab_loc))
								#print(insn_summary_map[succ][ab_loc])
								
								# also update value in ab locs contained in callsite paras ab locs
								ab_loc_copy = ab_loc
								for ab_loc in insn_summary_map[addr][ab_loc_copy]:
									# update every ab loc except "CLEAR"
									if ab_loc != "CLEAR":
										if ab_loc not in insn_summary_map[succ]:
											insn_summary_map[succ][ab_loc] = set()
										if ab_loc not in insn_summary_map[addr]:
											insn_summary_map[addr][ab_loc] = set([ab_loc])
										if ab_loc not in old:
											old[ab_loc] = set()
										#insn_summary_map[succ][ab_loc] = \
										#	copy.deepcopy((insn_summary_map[succ][ab_loc].union(added_value_set) - \
										#	insn_summary_map[addr][ab_loc]).union(old[ab_loc]))
											
										insn_summary_map[succ][ab_loc] = \
											copy.deepcopy(insn_summary_map[succ][ab_loc].union(added_value_set))
											
										#print("*")
										#print(hex(succ))
										#if isinstance(ab_loc, int):
										#	print(hex(ab_loc))
										#else:
										#	print(ab_loc)
										#print(insn_summary_map[succ][ab_loc])	
								
							# update return value eax in call fall through insn
							#if func_return == True:
							added_value = ""
							
							# malloc, calloc, realloc returns a heap var pointer in eax, this is a special value
							if addr in info.insnstringsmap and "malloc@plt" in info.insnstringsmap[addr] or \
								"calloc@plt" in info.insnstringsmap[addr] or "realloc@plt" in info.insnstringsmap[addr]:
								#print("*")
								#print(hex(addr))
								#print(info.insnstringsmap[addr])
								added_value = "HEAP_POINTER_" + hex(addr)
							# normal call insn		
							else:
								added_value = "CALLSITE_EAX_" + hex(addr)
							
							added_value_set = set([added_value])
							ab_loc = "eax"
							if ab_loc not in insn_summary_map[succ]:
								insn_summary_map[succ][ab_loc] = set()
							if ab_loc not in insn_summary_map[addr]:
								#print("*")
								#print(hex(addr))
								#print(insn_summary_map[addr])
								insn_summary_map[addr][ab_loc] = set([ab_loc])
							if ab_loc not in old:
								old[ab_loc] = set()
							insn_summary_map[succ][ab_loc] = \
								copy.deepcopy((insn_summary_map[succ][ab_loc].union(added_value_set) - \
								insn_summary_map[addr][ab_loc]).union(old[ab_loc]))
							#print("*")
							#print(hex(succ))
							#print(ab_loc)
							#print(insn_summary_map[succ][ab_loc])
						
						
						# update value sets	
						if addr in info.insnsmap:
							insn = info.insnsmap[addr]
							if len(insn.operands) == 1 and insn.operands[0].type == X86_OP_REG:
								#print("*")
								#print(hex(addr))
								#print(insn.mnemonic)
								#print(insn.op_str)
								#print(insn.reg_name(insn.operands[0].value.reg))
								reg_name = insn.reg_name(insn.operands[0].value.reg)
								if reg_name in info.gpr:
									#print(reg_name)

									if insn.mnemonic.startswith("push"):
										if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
											write_to_stack_addr = info.insn_stack_offset_map[addr] - 4
											if reg_name not in insn_summary_map[addr]:
												insn_summary_map[addr][reg_name] = set([reg_name])
											if write_to_stack_addr not in insn_summary_map[succ]:
												insn_summary_map[succ][write_to_stack_addr] = set()
											if write_to_stack_addr not in insn_summary_map[addr]:
												insn_summary_map[addr][write_to_stack_addr] = set([write_to_stack_addr])
											if write_to_stack_addr not in old:
												old[write_to_stack_addr] = set()
											insn_summary_map[succ][write_to_stack_addr] = \
												copy.deepcopy((insn_summary_map[succ][write_to_stack_addr].union(insn_summary_map[addr][reg_name]) \
												- insn_summary_map[addr][write_to_stack_addr]).union(old[write_to_stack_addr]))
								
									elif insn.mnemonic.startswith("pop"):
										if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
											read_from_stack_addr = info.insn_stack_offset_map[addr]
											if read_from_stack_addr not in insn_summary_map[addr]:
												insn_summary_map[addr][read_from_stack_addr] = set([read_from_stack_addr])
											if reg_name not in insn_summary_map[succ]:
												insn_summary_map[succ][reg_name] = set()
											if reg_name not in insn_summary_map[addr]:
												insn_summary_map[addr][reg_name] = set([reg_name])
											if reg_name not in old:
												old[reg_name] = set()
											insn_summary_map[succ][reg_name] = \
												copy.deepcopy((insn_summary_map[succ][reg_name].union(insn_summary_map[addr][read_from_stack_addr]) \
												- insn_summary_map[addr][reg_name]).union(old[reg_name]))
									elif insn.mnemonic.startswith("inc") or insn.mnemonic.startswith("neg"):
										insn_summary_map[succ][reg_name] = set(["CLEAR"])
									
												
							elif len(insn.operands) == 2:
								#print("*")
								#print(hex(addr))
								#print(insn.mnemonic)
								#print(insn.op_str)
								#print(insn.operands[0].type)
								#print(insn.operands[1].type)
								if insn.mnemonic.startswith("test") or insn.mnemonic.startswith("cmp"):
									pass
								elif insn.mnemonic.startswith("mov") or insn.mnemonic.startswith("cmove") or insn.mnemonic.startswith("lea"):
									#print("*")
									#print(hex(addr))
									#print(insn.mnemonic)
									#print(insn.op_str)
									#print(insn.operands[0].type)
									#print(insn.operands[1].type)
									if insn.operands[0].type == X86_OP_REG and insn.operands[1].type == X86_OP_REG:
										dest_reg_name = insn.reg_name(insn.operands[0].value.reg)
										src_reg_name = insn.reg_name(insn.operands[1].value.reg)
										if dest_reg_name in info.gpr and src_reg_name in info.gpr:
											if src_reg_name not in insn_summary_map[addr]:
												insn_summary_map[addr][src_reg_name] = set([src_reg_name])
											if dest_reg_name not in insn_summary_map[succ]:
												insn_summary_map[succ][dest_reg_name] = set()
											if dest_reg_name not in insn_summary_map[addr]:
												insn_summary_map[addr][dest_reg_name] = set([dest_reg_name])
											if dest_reg_name not in old:
												old[dest_reg_name] = set()
											insn_summary_map[succ][dest_reg_name] = \
												copy.deepcopy((insn_summary_map[succ][dest_reg_name].union(insn_summary_map[addr][src_reg_name]) \
												- insn_summary_map[addr][dest_reg_name]).union(old[dest_reg_name]))
												
									elif insn.operands[0].type == X86_OP_REG and insn.operands[1].type == X86_OP_MEM:
										dest_reg_name = insn.reg_name(insn.operands[0].value.reg)
										src_op = insn.operands[1]
										#print("*")
										#print(hex(addr))
										#print(insn.mnemonic)
										#print(insn.op_str)
										#print(insn.operands[0].type)
										#print(insn.operands[1].type)
										
										# lea insn
										if insn.mnemonic.startswith("lea") and dest_reg_name in info.gpr:
											# lea insn: check whether lea global var addr and generate global var pointer
											if src_op.value.mem.disp >= info.mmin_data_section_addr \
											and src_op.value.mem.disp <= info.mmax_data_section_addr:
												#print("*")
												#print(hex(addr))
												#print(hex(src_op.value.mem.disp))
												
												# add global var pointer to dest op reg
												value = "GLOBAL_POINTER_" + hex(src_op.value.mem.disp)
												if dest_reg_name not in insn_summary_map[succ]:
													insn_summary_map[succ][dest_reg_name] = set()
												if dest_reg_name not in insn_summary_map[addr]:
													insn_summary_map[addr][dest_reg_name] = set([dest_reg_name])
												if dest_reg_name not in old:
													old[dest_reg_name] = set()
												insn_summary_map[succ][dest_reg_name] = \
													copy.deepcopy((insn_summary_map[succ][dest_reg_name].union(set([value])) \
													- insn_summary_map[addr][dest_reg_name]).union(old[dest_reg_name]))
											else:
												insn_summary_map[succ][dest_reg_name] = set(["CLEAR"])
										
										# mov/cmov insn
										if (insn.mnemonic.startswith("mov") or insn.mnemonic.startswith("cmove")) and dest_reg_name in info.gpr:
											
											if src_op.value.mem.base != 0:
												src_op_base_reg_name = info.insnsmap[addr].reg_name(src_op.value.mem.base)
												
												# mov stack var via base
												if src_op_base_reg_name == "esp" and src_op.value.mem.index == 0:
													#print(src_op.value.mem.disp)
													if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
														value = info.insn_stack_offset_map[addr] + src_op.value.mem.disp
														#print("*")
														#print(hex(addr))
														#print(value)
														if value not in insn_summary_map[addr]:
															insn_summary_map[addr][value] = set([value])
														if dest_reg_name not in insn_summary_map[succ]:
															insn_summary_map[succ][dest_reg_name] = set()
														if dest_reg_name not in insn_summary_map[addr]:
															insn_summary_map[addr][dest_reg_name] = set([dest_reg_name])
														if dest_reg_name not in old:
															old[dest_reg_name] = set()
														insn_summary_map[succ][dest_reg_name] = \
															copy.deepcopy((insn_summary_map[succ][dest_reg_name].union( \
															insn_summary_map[addr][value]) \
															- insn_summary_map[addr][dest_reg_name]).union(old[dest_reg_name]))
													else:
														insn_summary_map[succ][dest_reg_name] = set(["CLEAR"])
												
												# mov global var via disp
												elif src_op.value.mem.disp >= info.mmin_data_section_addr \
													and src_op.value.mem.disp <= info.mmax_data_section_addr:
													#print("*")
													#print(hex(addr))
													#print(hex(src_op.value.mem.disp))
													# add global var to dest op reg
													value = src_op.value.mem.disp
													if dest_reg_name not in insn_summary_map[succ]:
														insn_summary_map[succ][dest_reg_name] = set()
													if dest_reg_name not in insn_summary_map[addr]:
														insn_summary_map[addr][dest_reg_name] = set([dest_reg_name])
													if dest_reg_name not in old:
														old[dest_reg_name] = set()
													insn_summary_map[succ][dest_reg_name] = \
														copy.deepcopy((insn_summary_map[succ][dest_reg_name].union( \
														set([value])) \
														- insn_summary_map[addr][dest_reg_name]).union(old[dest_reg_name]))
												
												# mov global/heap var via base, i.e., dereference global/heap var pointer
												elif addr in insn_summary_map and src_op_base_reg_name in insn_summary_map[addr]:
													dereference = False
													for base_reg_value in insn_summary_map[addr][src_op_base_reg_name]:
														if not isinstance(base_reg_value, int):
															# global pointer dereference
															if base_reg_value.startswith("GLOBAL_POINTER_"):
																gvar_addr_string = base_reg_value[15:]
																gvar_addr = int(gvar_addr_string, 16)
																#print("*")
																#print(hex(addr))
																#print(gvar_addr_string)
																#print(hex(gvar_addr))
																
																# add global var to dest op reg
																value = gvar_addr
																if dest_reg_name not in insn_summary_map[succ]:
																	insn_summary_map[succ][dest_reg_name] = set()
																if dest_reg_name not in insn_summary_map[addr]:
																	insn_summary_map[addr][dest_reg_name] = set([dest_reg_name])
																if dest_reg_name not in old:
																	old[dest_reg_name] = set()
																insn_summary_map[succ][dest_reg_name] = \
																	copy.deepcopy((insn_summary_map[succ][dest_reg_name].union( \
																	set([value])) \
																	- insn_summary_map[addr][dest_reg_name]).union(old[dest_reg_name]))
																dereference = True
																break
																
															# heap pointer dereference
															elif base_reg_value.startswith("HEAP_POINTER_"):
																hvar_addr_string = base_reg_value[13:]
																hvar_addr = int(hvar_addr_string, 16)
																#print("*")
																#print(hex(addr))
																#print(hvar_addr_string)
																#print(hex(hvar_addr))
																
																# add global var to dest op reg
																value = "HEAP_" + hex(hvar_addr)
																if dest_reg_name not in insn_summary_map[succ]:
																	insn_summary_map[succ][dest_reg_name] = set()
																if dest_reg_name not in insn_summary_map[addr]:
																	insn_summary_map[addr][dest_reg_name] = set([dest_reg_name])
																if dest_reg_name not in old:
																	old[dest_reg_name] = set()
																insn_summary_map[succ][dest_reg_name] = \
																	copy.deepcopy((insn_summary_map[succ][dest_reg_name].union( \
																	set([value])) \
																	- insn_summary_map[addr][dest_reg_name]).union(old[dest_reg_name]))
																dereference = True
																break
													if dereference == False:
														insn_summary_map[succ][dest_reg_name] = set(["CLEAR"])
												else:
													insn_summary_map[succ][dest_reg_name] = set(["CLEAR"])

											elif src_op.value.mem.base == 0:
												# mov stack var via index
												if src_op.value.mem.index != 0 and info.insnsmap[addr].reg_name(src_op.value.mem.index) == "esp":
													if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
														value = info.insn_stack_offset_map[addr] * src_op.value.mem.scale + src_op.value.mem.disp
														#print(info.insn_stack_offset_map[addr])
														#print(op.value.mem.scale)
														#print(op.value.mem.disp)
														#print("*")
														#print(hex(addr))
														#print(value)
														if value not in insn_summary_map[addr]:
															insn_summary_map[addr][value] = set([value])
														if dest_reg_name not in insn_summary_map[succ]:
															insn_summary_map[succ][dest_reg_name] = set()
														if dest_reg_name not in insn_summary_map[addr]:
															insn_summary_map[addr][dest_reg_name] = set([dest_reg_name])
														if dest_reg_name not in old:
															old[dest_reg_name] = set()
														insn_summary_map[succ][dest_reg_name] = \
															copy.deepcopy((insn_summary_map[succ][dest_reg_name].union( \
															insn_summary_map[addr][value]) \
															- insn_summary_map[addr][dest_reg_name]).union(old[dest_reg_name]))
												# mov stack/global via disp
												elif src_op.value.mem.index == 0:
													#print("*")
													#print(hex(addr))
													#print(insn.mnemonic)
													#print(insn.op_str)
													#print(hex(src_op.value.mem.disp))
													
													# stack or global var dereference
													value = src_op.value.mem.disp
													if value not in insn_summary_map[addr]:
														insn_summary_map[addr][value] = set([value])
													if dest_reg_name not in insn_summary_map[succ]:
														insn_summary_map[succ][dest_reg_name] = set()
													if dest_reg_name not in insn_summary_map[addr]:
														insn_summary_map[addr][dest_reg_name] = set([dest_reg_name])
													if dest_reg_name not in old:
														old[dest_reg_name] = set()
													insn_summary_map[succ][dest_reg_name] = \
														copy.deepcopy((insn_summary_map[succ][dest_reg_name].union( \
														insn_summary_map[addr][value]) \
														- insn_summary_map[addr][dest_reg_name]).union(old[dest_reg_name]))
												else:
													insn_summary_map[succ][dest_reg_name] = set(["CLEAR"])	
											else:
												insn_summary_map[succ][dest_reg_name] = set(["CLEAR"])
									elif insn.operands[0].type == X86_OP_REG and insn.operands[1].type == X86_OP_IMM:
										dest_reg_name = insn.reg_name(insn.operands[0].value.reg)
										if dest_reg_name in info.gpr:
											insn_summary_map[succ][dest_reg_name] = set(["CLEAR"])
									elif insn.operands[0].type == X86_OP_MEM and insn.operands[1].type == X86_OP_REG:
										src_reg_name = insn.reg_name(insn.operands[1].value.reg)
										dest_op = insn.operands[0]
										
										# all mov/cmov, no lea, as dest is mem
										
										if dest_op.value.mem.base != 0 and src_reg_name in info.gpr:
										
											dest_op_base_reg_name = info.insnsmap[addr].reg_name(dest_op.value.mem.base)
										
											# mov into stack var via base
											if dest_op_base_reg_name == "esp" and dest_op.value.mem.index == 0:
												#print(dest_op.value.mem.disp)
												if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
													value = info.insn_stack_offset_map[addr] + dest_op.value.mem.disp
													#print("*")
													#print(hex(addr))
													#print(value)
													if src_reg_name not in insn_summary_map[addr]:
														insn_summary_map[addr][src_reg_name] = set([src_reg_name])
													if value not in insn_summary_map[succ]:
														insn_summary_map[succ][value] = set()
													if value not in insn_summary_map[addr]:
														insn_summary_map[addr][value] = set([value])
													if value not in old:
														old[value] = set()
													insn_summary_map[succ][value] = \
														copy.deepcopy((insn_summary_map[succ][value].union(insn_summary_map[addr][src_reg_name]) \
														- insn_summary_map[addr][value]).union(old[value]))
														
											# mov into global var via disp
											elif dest_op.value.mem.disp >= info.mmin_data_section_addr \
												and dest_op.value.mem.disp <= info.mmax_data_section_addr:
												#print("*")
												#print(hex(addr))
												#print(hex(dest_op.value.mem.disp))
												# add global var to dest
												value = dest_op.value.mem.disp
												if src_reg_name not in insn_summary_map[addr]:
													insn_summary_map[addr][src_reg_name] = set([src_reg_name])
												if value not in insn_summary_map[succ]:
													insn_summary_map[succ][value] = set()
												if value not in insn_summary_map[addr]:
													insn_summary_map[addr][value] = set([value])
												if value not in old:
													old[value] = set()
												insn_summary_map[succ][value] = \
													copy.deepcopy((insn_summary_map[succ][value].union(insn_summary_map[addr][src_reg_name]) \
													- insn_summary_map[addr][value]).union(old[value]))
											
											# mov global/heap var via base, i.e., dereference global/heap var pointer
											elif addr in insn_summary_map and dest_op_base_reg_name in insn_summary_map[addr]:
												for base_reg_value in insn_summary_map[addr][dest_op_base_reg_name]:
													if not isinstance(base_reg_value, int):
														# global pointer dereference
														if base_reg_value.startswith("GLOBAL_POINTER_"):
															gvar_addr_string = base_reg_value[15:]
															gvar_addr = int(gvar_addr_string, 16)
															#print("*")
															#print(hex(addr))
															#print(gvar_addr_string)
															#print(hex(gvar_addr))
															
															# add global var to dest op reg
															value = gvar_addr
															#print("*")
															#print(hex(addr))
															#print(insn.mnemonic)
															#print(insn.op_str)
															#print(hex(dest_op.value.mem.disp))
															if src_reg_name not in insn_summary_map[addr]:
																insn_summary_map[addr][src_reg_name] = set([src_reg_name])
															if value not in insn_summary_map[succ]:
																insn_summary_map[succ][value] = set()
															if value not in insn_summary_map[addr]:
																insn_summary_map[addr][value] = set([value])
															if value not in old:
																old[value] = set()
															insn_summary_map[succ][value] = \
																copy.deepcopy((insn_summary_map[succ][value].union( \
																insn_summary_map[addr][src_reg_name]) \
																- insn_summary_map[addr][value]).union(old[value]))
															break
															
														# heap pointer dereference
														elif base_reg_value.startswith("HEAP_POINTER_"):
															hvar_addr_string = base_reg_value[13:]
															hvar_addr = int(hvar_addr_string, 16)
															#print("*")
															#print(hex(addr))
															#print(hvar_addr_string)
															#print(hex(hvar_addr))
															
															# add global var to dest op reg
															value = hvar_addr
															#print("*")
															#print(hex(addr))
															#print(insn.mnemonic)
															#print(insn.op_str)
															#print(hex(dest_op.value.mem.disp))
															if src_reg_name not in insn_summary_map[addr]:
																insn_summary_map[addr][src_reg_name] = set([src_reg_name])
															if value not in insn_summary_map[succ]:
																insn_summary_map[succ][value] = set()
															if value not in insn_summary_map[addr]:
																insn_summary_map[addr][value] = set([value])
															if value not in old:
																old[value] = set()
															insn_summary_map[succ][value] = \
																copy.deepcopy((insn_summary_map[succ][value].union( \
																insn_summary_map[addr][src_reg_name]) \
																- insn_summary_map[addr][value]).union(old[value]))
															break	
											
											
										elif dest_op.value.mem.base == 0 and src_reg_name in info.gpr:

											# mov into stack var via index
											if dest_op.value.mem.index != 0 and info.insnsmap[addr].reg_name(dest_op.value.mem.index) == "esp":
												if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
													value = info.insn_stack_offset_map[addr] * dest_op.value.mem.scale + dest_op.value.mem.disp
													#print(info.insn_stack_offset_map[addr])
													#print(op.value.mem.scale)
													#print(op.value.mem.disp)
													#print("*")
													#print(hex(addr))
													#print(value)
													if src_reg_name not in insn_summary_map[addr]:
														insn_summary_map[addr][src_reg_name] = set([src_reg_name])
													if value not in insn_summary_map[succ]:
														insn_summary_map[succ][value] = set()
													if value not in insn_summary_map[addr]:
														insn_summary_map[addr][value] = set([value])
													if value not in old:
														old[value] = set()
													insn_summary_map[succ][value] = \
														copy.deepcopy((insn_summary_map[succ][value].union(insn_summary_map[addr][src_reg_name]) \
														- insn_summary_map[addr][value]).union(old[value]))
											# mov into stack/global via disp
											elif dest_op.value.mem.index == 0:
												value = dest_op.value.mem.disp
												#print("*")
												#print(hex(addr))
												#print(insn.mnemonic)
												#print(insn.op_str)
												#print(hex(dest_op.value.mem.disp))
												if src_reg_name not in insn_summary_map[addr]:
													insn_summary_map[addr][src_reg_name] = set([src_reg_name])
												if value not in insn_summary_map[succ]:
													insn_summary_map[succ][value] = set()
												if value not in insn_summary_map[addr]:
													insn_summary_map[addr][value] = set([value])
												if value not in old:
													old[value] = set()
												insn_summary_map[succ][value] = \
													copy.deepcopy((insn_summary_map[succ][value].union(insn_summary_map[addr][src_reg_name]) \
													- insn_summary_map[addr][value]).union(old[value]))
												
										
																
									elif insn.operands[0].type == X86_OP_MEM and insn.operands[1].type == X86_OP_IMM:
										dest_op = insn.operands[0]
										
										# all mov/cmov, no lea, as dest is mem
										
										if dest_op.value.mem.base != 0:
											dest_op_base_reg_name = info.insnsmap[addr].reg_name(dest_op.value.mem.base)
											
											# mov into stack var via base
											if dest_op_base_reg_name == "esp" and dest_op.value.mem.index == 0:
												#print(dest_op.value.mem.disp)
												if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
													value = info.insn_stack_offset_map[addr] + dest_op.value.mem.disp
													#print("*")
													#print(hex(addr))
													#print(value)
													insn_summary_map[succ][value] = set(["CLEAR"])
											
											# mov into global var via disp
											elif dest_op.value.mem.disp >= info.mmin_data_section_addr \
												and dest_op.value.mem.disp <= info.mmax_data_section_addr:
												#print("*")
												#print(hex(addr))
												#print(hex(dest_op.value.mem.disp))
												# clear dest
												value = dest_op.value.mem.disp
												insn_summary_map[succ][value] = set(["CLEAR"])
											
											# mov global/heap var via base, i.e., dereference global/heap var pointer
											elif addr in insn_summary_map and dest_op_base_reg_name in insn_summary_map[addr]:
												for base_reg_value in insn_summary_map[addr][dest_op_base_reg_name]:
													if not isinstance(base_reg_value, int):
														# global pointer dereference
														if base_reg_value.startswith("GLOBAL_POINTER_"):
															gvar_addr_string = base_reg_value[15:]
															gvar_addr = int(gvar_addr_string, 16)
															#print("*")
															#print(hex(addr))
															#print(gvar_addr_string)
															#print(hex(gvar_addr))
															# clear dest op reg
															value = gvar_addr
															insn_summary_map[succ][value] = set(["CLEAR"])
															break
														# heap pointer dereference
														elif base_reg_value.startswith("HEAP_POINTER_"):
															hvar_addr_string = base_reg_value[13:]
															hvar_addr = int(hvar_addr_string, 16)
															#print("*")
															#print(hex(addr))
															#print(hvar_addr_string)
															#print(hex(hvar_addr))
															# clear dest op reg
															value = hvar_addr
															insn_summary_map[succ][value] = set(["CLEAR"])
															break
										else:
											# mov into stack var via index
											if dest_op.value.mem.index != 0 and info.insnsmap[addr].reg_name(dest_op.value.mem.index) == "esp":
												if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
													value = info.insn_stack_offset_map[addr] * dest_op.value.mem.scale + dest_op.value.mem.disp
													#print(info.insn_stack_offset_map[addr])
													#print(op.value.mem.scale)
													#print(op.value.mem.disp)
													#print("*")
													#print(hex(addr))
													#print(value)
													insn_summary_map[succ][value] = set(["CLEAR"])
											
											# mov into stack/global via disp
											elif dest_op.value.mem.index == 0:
												value = dest_op.value.mem.disp
												#print("*")
												#print(hex(addr))
												#print(hex(value))
												insn_summary_map[succ][value] = set(["CLEAR"])
																
								else:
									if insn.operands[0].type == X86_OP_REG:
										dest_reg_name = insn.reg_name(insn.operands[0].value.reg)
										if dest_reg_name in info.gpr:
										
											# reserve the dest if opcode is add/sub and dest reg contains global/heap pointer/var
											if (insn.mnemonic.startswith("add") or insn.mnemonic.startswith("sub")) and addr in insn_summary_map \
												and dest_reg_name in insn_summary_map[addr]:
												#print("*")
												#print(hex(addr))
												#print(dest_reg_name)
												dest_reserve = False
												tmp_set = set()
												for dest_reg_value in insn_summary_map[addr][dest_reg_name]:
													if not isinstance(dest_reg_value, int):
														# global pointer
														if dest_reg_value.startswith("GLOBAL_POINTER_"):
															#print("*")
															#print(hex(addr))
															#print(dest_reg_value)
															tmp_set.add(dest_reg_value)
															dest_reserve = True
															
														# heap pointer and heap var
														elif dest_reg_value.startswith("HEAP_"):
															tmp_set.add(dest_reg_value)
															dest_reserve = True
													else:
														# global var
														if dest_reg_value >= info.mmin_data_section_addr \
															and dest_reg_value <= info.mmax_data_section_addr:
															#print("*")
															#print(hex(addr))
															#print(hex(dest_reg_value))
															tmp_set.add(dest_reg_value)
															dest_reserve = True
												
												if dest_reserve == True:
													insn_summary_map[succ][dest_reg_name] = tmp_set		
												else:
													insn_summary_map[succ][dest_reg_name] = set(["CLEAR"])
											else:
												insn_summary_map[succ][dest_reg_name] = set(["CLEAR"])
									elif insn.operands[0].type == X86_OP_MEM:
										dest_op = insn.operands[0]
										
										value = None
										
										if dest_op.value.mem.base != 0:
											dest_op_base_reg_name = info.insnsmap[addr].reg_name(dest_op.value.mem.base)
											
											# dest mem: stack var via base
											if info.insnsmap[addr].reg_name(dest_op.value.mem.base) == "esp" and dest_op.value.mem.index == 0:
												#print(dest_op.value.mem.disp)
												if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
													value = info.insn_stack_offset_map[addr] + dest_op.value.mem.disp
													#print("*")
													#print(hex(addr))
													#print(value)
													insn_summary_map[succ][value] = set(["CLEAR"])
													
											# dest mem: global var via disp
											elif dest_op.value.mem.disp >= info.mmin_data_section_addr \
												and dest_op.value.mem.disp <= info.mmax_data_section_addr:
												#print("*")
												#print(hex(addr))
												#print(hex(dest_op.value.mem.disp))
												# clear dest
												value = dest_op.value.mem.disp
												insn_summary_map[succ][value] = set(["CLEAR"])
												
											# dest mem: global/heap var via base, i.e., dereference global/heap var pointer
											elif addr in insn_summary_map and dest_op_base_reg_name in insn_summary_map[addr]:
												for base_reg_value in insn_summary_map[addr][dest_op_base_reg_name]:
													if not isinstance(base_reg_value, int):
														# global pointer dereference
														if base_reg_value.startswith("GLOBAL_POINTER_"):
															gvar_addr_string = base_reg_value[15:]
															gvar_addr = int(gvar_addr_string, 16)
															#print("*")
															#print(hex(addr))
															#print(gvar_addr_string)
															#print(hex(gvar_addr))
															# clear dest op reg
															value = gvar_addr
															insn_summary_map[succ][value] = set(["CLEAR"])
															break
														# heap pointer dereference
														elif base_reg_value.startswith("HEAP_POINTER_"):
															hvar_addr_string = base_reg_value[13:]
															hvar_addr = int(hvar_addr_string, 16)
															#print("*")
															#print(hex(addr))
															#print(hvar_addr_string)
															#print(hex(hvar_addr))
															# clear dest op reg
															value = hvar_addr
															insn_summary_map[succ][value] = set(["CLEAR"])
															break
										
										else:
											# dest mem: stack var via index
											if dest_op.value.mem.index != 0 and info.insnsmap[addr].reg_name(dest_op.value.mem.index) == "esp":
												if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
													value = info.insn_stack_offset_map[addr] * dest_op.value.mem.scale + dest_op.value.mem.disp
													#print(info.insn_stack_offset_map[addr])
													#print(op.value.mem.scale)
													#print(op.value.mem.disp)
													#print("*")
													#print(hex(addr))
													#print(value)
													insn_summary_map[succ][value] = set(["CLEAR"])
											# dest mem: stack/global via disp
											elif dest_op.value.mem.index == 0:
												value = dest_op.value.mem.disp
												#print("*")
												#print(hex(addr))
												#print(hex(value))
												insn_summary_map[succ][value] = set(["CLEAR"])
										
										# reserve the dest if opcode is add/sub and dest mem contains global/heap pointer/var
										
										# we solved the dest mem addr
										if value != None:
											if (insn.mnemonic.startswith("add") or insn.mnemonic.startswith("sub")) and addr in insn_summary_map \
												and value in insn_summary_map[addr]:
												#print("*")
												#print(hex(addr))
												#print(value)
												dest_reserve = False
												tmp_set = set()
												for dest_mem_value in insn_summary_map[addr][value]:
													if not isinstance(dest_mem_value, int):
														# global pointer
														if dest_mem_value.startswith("GLOBAL_POINTER_"):
															#print("*")
															#print(hex(addr))
															#print(dest_mem_value)
															tmp_set.add(dest_mem_value)
															dest_reserve = True
															
														# heap pointer and heap var
														elif dest_mem_value.startswith("HEAP_"):
															tmp_set.add(dest_mem_value)
															dest_reserve = True
													else:
														# global var
														if dest_mem_value >= info.mmin_data_section_addr \
															and dest_mem_value <= info.mmax_data_section_addr:
															#print("*")
															#print(hex(addr))
															#print(hex(dest_mem_value))
															tmp_set.add(dest_mem_value)
															dest_reserve = True
												
												if dest_reserve == True:
													insn_summary_map[succ][value] = tmp_set		

					addr = findnextinsaddr(addr)			


			# update func summary
			info.func_summary_map[func_addr] = {}
			for addr in sorted(insn_summary_map):
				#print("*")
				#print(hex(addr))
				#for ab_loc in insn_summary_map[addr]:
				#	print("+" + str(len(insn_summary_map[addr][ab_loc])) + "+")
				#	if isinstance(ab_loc, int):
				#		print(hex(ab_loc))
				#	else:
				#		print(ab_loc)
				#	for ab_loc_1 in insn_summary_map[addr][ab_loc]:
				#		if isinstance(ab_loc_1, int):
				#			print(hex(ab_loc_1))
				#		else:
				#			print(ab_loc_1)
							
				if addr in info.ret_insn_addresses:
					#print("*")
					#print(hex(addr))
					for ab_loc in insn_summary_map[addr]:
						#if isinstance(ab_loc, int):
						#	print(hex(ab_loc))
						#else:
						#	print(ab_loc)
						if ab_loc not in info.func_summary_map[func_addr]:
							info.func_summary_map[func_addr][ab_loc] = set()
						info.func_summary_map[func_addr][ab_loc] = copy.deepcopy(info.func_summary_map[func_addr][ab_loc].union(insn_summary_map[addr][ab_loc]))
						#print(insn_summary_map[addr][ab_loc])
						#print(info.func_summary_map[func_addr][ab_loc])
			
				# update info.insn_summary_map
				#print("*")
				#print(hex(addr))
				for ab_loc in insn_summary_map[addr]:
					#if isinstance(ab_loc, int):
					#	print(hex(ab_loc))
					#else:
					#	print(ab_loc)
					if ab_loc not in info.insn_summary_map[addr]:
						info.insn_summary_map[addr][ab_loc] = set()
					info.insn_summary_map[addr][ab_loc] = copy.deepcopy(info.insn_summary_map[addr][ab_loc].union(insn_summary_map[addr][ab_loc]))
					#print(insn_summary_map[addr][ab_loc])
					#print(info.insn_summary_map[addr][ab_loc])
	

	#for addr in sorted(info.func_summary_map):
	#	print("*")
	#	print(hex(addr))
	#	for ab_loc in info.func_summary_map[addr]:
	#		print("+" + str(len(info.func_summary_map[addr][ab_loc])) + "+")
	#		if isinstance(ab_loc, int):
	#			print(hex(ab_loc))
	#		else:
	#			print(ab_loc)
	#		for ab_loc_1 in info.func_summary_map[addr][ab_loc]:
	#			if isinstance(ab_loc_1, int):
	#				print(hex(ab_loc_1))
	#			else:
	#				print(ab_loc_1)
	
	
	#for addr in sorted(info.insn_summary_map):
	#	print("*")
	#	print(hex(addr))
	#	for ab_loc in info.insn_summary_map[addr]:
	#		print("+" + str(len(info.insn_summary_map[addr][ab_loc])) + "+")
	#		if isinstance(ab_loc, int):
	#			print(hex(ab_loc))
	#		else:
	#			print(ab_loc)
	#		for ab_loc_1 in info.insn_summary_map[addr][ab_loc]:
	#			if isinstance(ab_loc_1, int):
	#				print(hex(ab_loc_1))
	#			else:
	#				print(ab_loc_1)
	

	
	f = open(info.func_summary_map_tmp_file, "w")
	for addr in sorted(info.func_summary_map):
		f.write("*\n")
		f.write(hex(addr) + "\n")
		for ab_loc in info.func_summary_map[addr]:
			f.write("+" + str(len(info.func_summary_map[addr][ab_loc])) + "+\n")
			if isinstance(ab_loc, int):
				f.write(hex(ab_loc) + "\n")
			else:
				f.write(ab_loc + "\n")
			for ab_loc_1 in info.func_summary_map[addr][ab_loc]:
				if isinstance(ab_loc_1, int):
					f.write(hex(ab_loc_1) + "\n")
				else:
					f.write(ab_loc_1 + "\n")
	f.close()

	f = open(info.insn_summary_map_tmp_file, "w")
	for addr in sorted(info.insn_summary_map):
		f.write("*\n")
		f.write(hex(addr) + "\n")
		for ab_loc in info.insn_summary_map[addr]:
			f.write("+" + str(len(info.insn_summary_map[addr][ab_loc])) + "+\n")
			if isinstance(ab_loc, int):
				f.write(hex(ab_loc) + "\n")
			else:
				f.write(ab_loc + "\n")
			for ab_loc_1 in info.insn_summary_map[addr][ab_loc]:
				if isinstance(ab_loc_1, int):
					f.write(hex(ab_loc_1) + "\n")
				else:
					f.write(ab_loc_1 + "\n")
	f.close()


def binary_static_taint_typed():

	# check each function in reversed topological order
	# whether its paras, callees, globals, heaps are tainted and propagate
	# fix-point when info.func_taintedvar_map_typed remains unchanged

	# data structure initialization
	info.func_taintedvar_map_typed = {}
	#info.func_taintedvar_summary_map_typed = {}
	info.tainted_insn_addresses_typed = set()
	
	for func_addr in info.ordered_func_addresses:
		info.func_taintedvar_map_typed[func_addr] = set()
		#info.func_taintedvar_summary_map_typed[func_addr] = set()

	# taint source initialization
	for taintsource in info.args.taintsources:
		if taintsource == "read":
			#print(hex(info.func_name_map["read@plt"][0]))
			info.func_taintedvar_map_typed[info.func_name_map["read@plt"][0]] = set([0x8])
			#info.func_taintedvar_summary_map_typed[info.func_name_map["read@plt"][0]] = set([0x8])
		elif taintsource == "fread":
			#print(hex(info.func_name_map["fread@plt"][0]))
			info.func_taintedvar_map_typed[info.func_name_map["fread@plt"][0]] = set([0x4])
			#info.func_taintedvar_summary_map_typed[info.func_name_map["fread@plt"][0]] = set([0x4])
		elif taintsource == "fgetc":
			#print(hex(info.func_name_map["fgetc@plt"][0]))
			info.func_taintedvar_map_typed[info.func_name_map["fgetc@plt"][0]] = set(["eax"])
			#info.func_taintedvar_summary_map_typed[info.func_name_map["fgetc@plt"][0]] = set(["eax"])
		elif taintsource == "_IO_getc":
			#print(hex(info.func_name_map["fgetc@plt"][0]))
			info.func_taintedvar_map_typed[info.func_name_map["_IO_getc@plt"][0]] = set(["eax"])
		elif taintsource == "fgets":
			#print(hex(info.func_name_map["fgetc@plt"][0]))
			info.func_taintedvar_map_typed[info.func_name_map["fgets@plt"][0]] = set([0x4, "eax"])
		elif taintsource == "__isoc99_fscanf":
			#print(hex(info.func_name_map["fgetc@plt"][0]))
			info.func_taintedvar_map_typed[info.func_name_map["__isoc99_fscanf@plt"][0]] = set([0x8, 0xc, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24])
		elif taintsource == "fscanf":
			#print(hex(info.func_name_map["fgetc@plt"][0]))
			info.func_taintedvar_map_typed[info.func_name_map["fscanf@plt"][0]] = set([0xc, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x28])
		elif taintsource == "_ZNSi4readEPci":
			#print(hex(info.func_name_map["fgetc@plt"][0]))
			info.func_taintedvar_map_typed[info.func_name_map["_ZNSi4readEPci@plt"][0]] = set([0x4])
		elif taintsource == "readv":
			info.func_taintedvar_map_typed[info.func_name_map["readv@plt"][0]] = set([0x8])
		elif taintsource == "readlink":
			info.func_taintedvar_map_typed[info.func_name_map["readlink@plt"][0]] = set([0x8])			
		elif taintsource == "pread64":
			info.func_taintedvar_map_typed[info.func_name_map["pread64@plt"][0]] = set([0x8])	
		elif taintsource == "__fread_chk":
			info.func_taintedvar_map_typed[info.func_name_map["__fread_chk@plt"][0]] = set([0x4])
		elif taintsource == "wgetch":
			info.func_taintedvar_map_typed[info.func_name_map["wgetch@plt"][0]] = set(["eax"])
		elif taintsource == "getline":
			info.func_taintedvar_map_typed[info.func_name_map["getline@plt"][0]] = set([0x4])
		elif taintsource == "__isoc99_scanf":
			info.func_taintedvar_map_typed[info.func_name_map["__isoc99_scanf@plt"][0]] = set([0x8, 0xc, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24])
		elif taintsource == "recv":
			info.func_taintedvar_map_typed[info.func_name_map["recv@plt"][0]] = set([0x8])
		elif taintsource == "gnutls_record_recv":
			info.func_taintedvar_map_typed[info.func_name_map["gnutls_record_recv@plt"][0]] = set([0x8])	
		#jpeg_read_header
		#jpeg_read_raw_data
		#png_read_image




	# iterate
	#for i in range(1):
	while True:
	
		old_tainted_insn_addresses_typed = copy.deepcopy(info.tainted_insn_addresses_typed)
	
		# in reversed topological order
		for func_addr in info.ordered_func_addresses:
			func_name = info.func_addr_map[func_addr][0]
			func_end_addr = info.func_addr_map[func_addr][1]
			#print("binary_static_taint")
			#print("*")
			#print(func_name)
			#print(hex(func_addr))
			#print(hex(func_end_addr))
			
			if func_addr not in info.insnsmap:
				continue
			if func_addr not in info.cfg.kb.functions:
				continue
			if func_addr not in info.func_addr_map:
				continue
			#if func_addr != 0x807e0e0:
			#	continue
			#if func_addr != 0x8049b0e:
			#	continue
			#if func_addr != 0x8049baf:
			#	continue
			#if func_addr != 0x8049c25:
			#	continue
			#if func_addr != 0x8048ed0:
			#	continue
			#if func_addr != 0x804c410:
			#	continue
			#if func_addr != 0x804b271:
			#	continue
			
			#print("*")
			#print(func_name)
			#print(hex(func_addr))
			#print(hex(func_end_addr))



			# analyze each function and propagate
			
			#print(func_name)
			
			
			
			# find all callsites
			callsites = sorted(info.func_callsites_map[func_addr])
			
			#print("*")
			#print(hex(func_addr))
			#for callsite in callsites:
			#	print(hex(callsite))
			
			# find all func paras value
			func_para_values = []

			if func_addr in info.funcaddr_para_access_map:
				func_para_access = info.funcaddr_para_access_map[func_addr]
				func_para_index_set = set(range(func_para_access)).union(set([func_para_access])) - set([0])
				for func_para_index in sorted(func_para_index_set):
					func_para_values.append(int(4 * func_para_index))
			
			#print("**")
			#for func_para_value in func_para_values:
			#	print(hex(func_para_value))

			# find all call site paras value
			callsite_para_values_map = {}
			for callsite in callsites:
				# get esp value
				if callsite in info.insn_stack_offset_map:
					esp_value = info.insn_stack_offset_map[callsite]
					if callsite in info.callsite_para_access_map:
						callsite_para_access = info.callsite_para_access_map[callsite]
						callsite_para_values = []
						for callsite_para_index in range(callsite_para_access):
							callsite_para_values.append(int(4 * callsite_para_index + esp_value))
						callsite_para_values_map[callsite] = copy.deepcopy(callsite_para_values)
			
			#print("***")
			#for callsite in callsites:
			#	print(hex(callsite))
			#	for callsite_para_value in callsite_para_values_map[callsite]:
			#		print(hex(callsite_para_value))
			
			#print("1")
			#print(hex(func_addr))
			#print(info.func_taintedvar_map_typed[func_addr])
			#print(info.func_taintedvar_summary_map_typed[func_addr])
			
			while_true_start = time.time()
			while True:
				old_func_taintedvar_map_typed = copy.deepcopy(info.func_taintedvar_map_typed[func_addr])
				
				#print("2")
				#print(info.func_taintedvar_map_typed[func_addr])
				#print(info.func_taintedvar_summary_map_typed[func_addr])
				
				
				
				if not func_name.endswith("@plt"):
					# for each para
					#if func_addr in info.funcaddr_para_access_map and func_addr in info.func_summary_map:
					#	for func_para_value in func_para_values:
					#		if func_para_value in info.func_summary_map[func_addr]:
					#			if len(info.func_summary_map[func_addr][func_para_value].intersection(info.func_taintedvar_map_typed[func_addr])) != 0:
					#				info.func_taintedvar_map_typed[func_addr].add(func_para_value)
					# for ret
					#if func_addr in info.func_summary_map and "eax" in info.func_summary_map[func_addr]:
					#	if len(info.func_summary_map[func_addr]["eax"].intersection(info.func_taintedvar_map_typed[func_addr])) != 0:
					#		info.func_taintedvar_map_typed[func_addr].add("eax")
					
					# for each call site
					for callsite in callsites:
						#print(hex(callsite))
						if callsite in callsite_para_values_map and callsite in info.insn_summary_map and callsite in info.insn_stack_offset_map:
							#print(hex(callsite))
							esp_value = info.insn_stack_offset_map[callsite]
							
							# for each call site parameter
							for callsite_para_value in callsite_para_values_map[callsite]:
								
								# check how func paras flow to callsites
								# caller -> callee
								if callsite_para_value in info.insn_summary_map[callsite]:
									if len(info.insn_summary_map[callsite][callsite_para_value].intersection(info.func_taintedvar_map_typed[func_addr])) != 0:
										#print("2.1")
										# add CALLSITE_P1(-P10)_0x(callsite) to caller
										callsite_para_index = int((callsite_para_value - esp_value) / 4 + 1)
										value = "CALLSITE_P" + str(callsite_para_index) + "_" + hex(callsite)
										info.func_taintedvar_map_typed[func_addr].add(value)
										#print("2.2")
										# add para offset value to callee
										callee_para_value = int(callsite_para_index * 4)
										if callsite in info.callsite_map:
											for callee in sorted(info.callsite_map[callsite]):
												info.func_taintedvar_map_typed[callee].add(callee_para_value)
												
												# update tainted call site parameter update
												# we do it here since we do not process plt func as non-plt func
												if callee in info.func_addr_map:
													callee_name = info.func_addr_map[callee][0]
													# if plt func
													if callee_name.endswith("@plt"):
														if callee_name == "memmove@plt":
															if 0x8 in info.func_taintedvar_map_typed[callee] \
																and 0x4 not in info.func_taintedvar_map_typed[callee]:
																info.func_taintedvar_map_typed[callee] = copy.deepcopy( \
																	info.func_taintedvar_map_typed[callee].union(set([0x4])))
														elif callee_name == "memcopy@plt":
															if 0x8 in info.func_taintedvar_map_typed[callee] \
																and 0x4 not in info.func_taintedvar_map_typed[callee]:
																info.func_taintedvar_map_typed[callee] = copy.deepcopy( \
																info.func_taintedvar_map_typed[callee].union(set([0x4])))
														elif callee_name == "memset@plt":
															if 0x8 in info.func_taintedvar_map_typed[callee] \
																and 0x4 not in info.func_taintedvar_map_typed[callee]:
																info.func_taintedvar_map_typed[callee] = copy.deepcopy( \
																info.func_taintedvar_map_typed[callee].union(set([0x4])))
														elif callee_name == "strcpy@plt":
															if 0x8 in info.func_taintedvar_map_typed[callee] \
																and 0x4 not in info.func_taintedvar_map_typed[callee]:
																info.func_taintedvar_map_typed[callee] = copy.deepcopy( \
																info.func_taintedvar_map_typed[callee].union(set([0x4])))
														elif callee_name == "strncpy@plt":
															if 0x8 in info.func_taintedvar_map_typed[callee] \
																and 0x4 not in info.func_taintedvar_map_typed[callee]:
																info.func_taintedvar_map_typed[callee] = copy.deepcopy( \
																info.func_taintedvar_map_typed[callee].union(set([0x4])))
														elif callee_name == "strtol@plt":
															if 0x4 in info.func_taintedvar_map_typed[callee] \
																and (0x8 not in info.func_taintedvar_map_typed[callee] \
																or "eax" not in info.func_taintedvar_map_typed[callee]):
																info.func_taintedvar_map_typed[callee] = copy.deepcopy( \
																info.func_taintedvar_map_typed[callee].union(set([0x8, "eax"])))
														elif callee_name == "gcvt@plt":
															if 0x4 in info.func_taintedvar_map_typed[callee] \
																and 0xc not in info.func_taintedvar_map_typed[callee]:
																info.func_taintedvar_map_typed[callee] = copy.deepcopy( \
																info.func_taintedvar_map_typed[callee].union(set([0xc])))
												
										#print("2.3")		
										# add ret offset value to callee
										#if callsite in info.callsite_map:
										#	for callee in sorted(info.callsite_map[callsite]):
										#		if callee in info.func_summary_map and "eax" in info.func_summary_map[callee] \
										#			and callee_para_value in info.func_summary_map[callee]["eax"]:
										#			info.func_taintedvar_map_typed[callee].add("eax")
													
								# check how callsites paras and rets flow to caller
								# callee -> caller
								callsite_para_index = int((callsite_para_value - esp_value) / 4 + 1)
								para_value = "CALLSITE_P" + str(callsite_para_index) + "_" + hex(callsite)
								# CALLSITE_EAX_0x(callsite)
								ret_value = "CALLSITE_EAX_" + hex(callsite)
								callee_para_value = int(callsite_para_index * 4)
								#print(hex(callsite))
								if callsite in info.callsite_map:
									for callee in sorted(info.callsite_map[callsite]):
										# if callee paras are tainted, add it to caller
										if callee_para_value in info.func_taintedvar_map_typed[callee]:
											#print("2.4")
											#if isinstance(callee_para_value, int):
											#	print(hex(callee_para_value))
										
											# do not add to taintedvar if para is not a pointer
											nonpointer = False
											
											# the index starts from 0
											callsite_para_index_1 = int((callsite_para_value - esp_value) / 4)
											if callsite in info.bbendaddr_bbstartaddr_map:
												call_insn_bb_addr = info.bbendaddr_bbstartaddr_map[callsite]
												from_bb = info.cfg.model.get_any_node(call_insn_bb_addr)
												if from_bb != None:
													to_bbs = from_bb.successors
													if len(to_bbs) >= 1 and to_bbs[0].name != "UnresolvableCallTarget":
														#print(to_bbs[0])
														#print(dir(to_bbs[0]))
														callee_func_addr = to_bbs[0].addr
														#print(hex(callee_func_addr))
														if callee_func_addr in info.funcaddr_para_details_map \
															and callsite in info.callsite_para_details_map:
															
															if len(info.funcaddr_para_details_map[callee_func_addr]) <= callsite_para_index_1:
																if info.callsite_para_details_map[callsite][callsite_para_index_1] == 0:
																	nonpointer = True
															elif info.funcaddr_para_details_map[callee_func_addr][callsite_para_index_1] == 0 \
																and info.callsite_para_details_map[callsite][callsite_para_index_1] == 0:
																	nonpointer = True
															if nonpointer == True:
																#print("*")
																#print(hex(callsite_para_index_1))
																#print(hex(callsite))
																#print(info.callsite_para_details_map[callsite])
																#print(hex(callee_func_addr))
																#print(info.funcaddr_para_details_map[callee_func_addr])
																pass
															else:
																#print("*")
																#print(hex(callsite_para_index_1))
																#print(hex(callsite))
																#print(info.callsite_para_details_map[callsite])
																#print(hex(callee_func_addr))
																#print(info.funcaddr_para_details_map[callee_func_addr])
																pass
																
																# do not update this parameter
																
												
											# only add when para is a pointer
											#if nonpointer == False:
										
											#	# add CALLSITE_P1(-P10)_0x(callsite)
											#	info.func_taintedvar_map_typed[func_addr].add(para_value)
											#	# add callsite_para_value
											#	info.func_taintedvar_map_typed[func_addr].add(callsite_para_value)
											#	# add values inside callsite_para_value
											#	if callsite_para_value in info.insn_summary_map[callsite]:
											#		for stack_contained_value in info.insn_summary_map[callsite][callsite_para_value]:
											#			if stack_contained_value != "eax":
											#				info.func_taintedvar_map_typed[func_addr].add(stack_contained_value)
											#			#if isinstance(stack_contained_value, int):
											#			#	print(hex(stack_contained_value))
														
											# add CALLSITE_P1(-P10)_0x(callsite)
											info.func_taintedvar_map_typed[func_addr].add(para_value)
											# add callsite_para_value
											info.func_taintedvar_map_typed[func_addr].add(callsite_para_value)
											# add values inside callsite_para_value
											if callsite_para_value in info.insn_summary_map[callsite]:
												for stack_contained_value in info.insn_summary_map[callsite][callsite_para_value]:
													if stack_contained_value != "eax":
														info.func_taintedvar_map_typed[func_addr].add(stack_contained_value)
													#if isinstance(stack_contained_value, int):
													#	print(hex(stack_contained_value))
														
										# if callee return value is tainted, add it to caller
										if "eax" in info.func_taintedvar_map_typed[callee]:
											#print("2.5")
											# add CALLSITE_EAX_0x(callsite)
											info.func_taintedvar_map_typed[func_addr].add(ret_value)
							
							# if callsite has no para
							if len(callsite_para_values_map[callsite]) == 0:
								#print(hex(callsite))
								ret_value = "CALLSITE_EAX_" + hex(callsite)
								if callsite in info.callsite_map:
									for callee in sorted(info.callsite_map[callsite]):
										# if callee return value is tainted, add it to caller
										if "eax" in info.func_taintedvar_map_typed[callee]:
											#print("2.5")
											# add CALLSITE_EAX_0x(callsite)
											info.func_taintedvar_map_typed[func_addr].add(ret_value)
							
							
						# after analyzing each call site, clear plt func taints except taint source func
						if callsite in info.callsite_map:
							for callee in sorted(info.callsite_map[callsite]):
								if callee in info.func_addr_map:
									callee_name = info.func_addr_map[callee][0]
									if callee_name.endswith("@plt"):
										callee_short_name = callee_name[:callee_name.index("@plt")]
										if callee_short_name not in info.args.taintsources:
											info.func_taintedvar_map_typed[callee] = set()
				
				#print("3")
				#print(info.func_taintedvar_map_typed[func_addr])
				#print(info.func_taintedvar_summary_map_typed[func_addr])
				
				# add var containing tainted var to tainted vars
				func_gvars = set()
				addr = func_addr
				while addr <= func_end_addr and addr != -1:
					#print(hex(addr))
					if addr in info.insn_summary_map:
						for ab_loc in info.insn_summary_map[addr]:
							for ab_loc_1 in info.insn_summary_map[addr][ab_loc]:
								if ab_loc_1 in info.func_taintedvar_map_typed[func_addr]:
									info.func_taintedvar_map_typed[func_addr].add(ab_loc)
									
									#if ab_loc in info.gpr:
									#	#if ab_loc in info.insn_summary_map[addr][ab_loc]:
									#	#	info.func_taintedvar_map_typed[func_addr].add(ab_loc)
									#	info.func_taintedvar_map_typed[func_addr].add(ab_loc)
									#else:
									#	info.func_taintedvar_map_typed[func_addr].add(ab_loc)
									
									#print("*")
									#if isinstance(ab_loc, int):
									#	print(hex(ab_loc))
									#else:
									#	print(ab_loc)
									#if isinstance(ab_loc_1, int):
									#	print(hex(ab_loc_1))
									#else:
									#	print(ab_loc_1)
									#break
						
							# collect gvars
							if isinstance(ab_loc, int) and ab_loc >= info.mmin_data_section_addr and ab_loc <= info.mmax_data_section_addr:
								func_gvars.add(ab_loc)
								#print("*")
								#print(hex(addr))
								#print(hex(ab_loc))
					addr = findnextinsaddr(addr)
				
				#print("4")
				#print(info.func_taintedvar_map_typed[func_addr])
				
				# if global in tainted var, add global+0x100 to tainted var
				to_addr_gvars = set()
				for tainted_var in info.func_taintedvar_map_typed[func_addr]:
					if isinstance(tainted_var, int):
						#print(hex(tainted_var))
						if tainted_var >= info.mmin_data_section_addr and tainted_var <= info.mmax_data_section_addr:
							for func_gvar in func_gvars:
								if isinstance(func_gvar, int):
									if func_gvar > tainted_var and func_gvar <= tainted_var + 0x100:
										to_addr_gvars.add(func_gvar)
				
				#for to_add_gvar in sorted(to_addr_gvars):
				#	print(hex(to_add_gvar))
					
				info.func_taintedvar_map_typed[func_addr] = info.func_taintedvar_map_typed[func_addr].union(to_addr_gvars)
				
				#print("5")
				#print(info.func_taintedvar_map_typed[func_addr])
				
				#print("*")
				#for tainted_var in info.func_taintedvar_map_typed[func_addr]:
				#	if isinstance(tainted_var, int):
				#		print(hex(tainted_var))
				#	else:
				#		print(tainted_var)
				
				if info.func_taintedvar_map_typed[func_addr] == old_func_taintedvar_map_typed:
						break
				# if time-out, also break
				while_true_end = time.time()
				while_true_time = while_true_end - while_true_start
				if while_true_time > 60:
					break
			
			#print("6")
			#print(info.func_taintedvar_map_typed[func_addr])
			
			# update other functions using global variables
			tainted_gvars = set()
			for tainted_var in info.func_taintedvar_map_typed[func_addr]:
				if isinstance(tainted_var, int):
					#print(hex(tainted_var))
					if tainted_var >= info.mmin_data_section_addr and tainted_var <= info.mmax_data_section_addr:
						tainted_gvars.add(tainted_var)
			
			for func_addr_1 in info.ordered_func_addresses:
				#func_name_1 = info.func_addr_map[func_addr_1][0]
				#func_end_addr_1 = info.func_addr_map[func_addr_1][1]
				#print("*")
				#print(func_name_1)
				#print(hex(func_addr_1))
				#print(hex(func_end_addr_1))
				if func_addr_1 not in info.insnsmap:
					continue
				if func_addr_1 not in info.cfg.kb.functions:
					continue
				if func_addr_1 not in info.func_addr_map:
					continue
				info.func_taintedvar_map_typed[func_addr_1] = info.func_taintedvar_map_typed[func_addr_1].union(tainted_gvars)
			
			
			
			# identify tainted insn based on tainted values for this function
			finish_to_next_insn_addr = False
			addr = func_addr
			while addr <= func_end_addr and addr != -1:
				
				ab_locs_containing_tainted_value = set()
				
				for ab_loc in info.insn_summary_map[addr]:
					# some ab loc contains tainted values
					if len(info.func_taintedvar_map_typed[func_addr].intersection(info.insn_summary_map[addr][ab_loc])) != 0 and addr in info.insnsmap:
						ab_locs_containing_tainted_value.add(ab_loc)
						
						
				# check whether the tainted value is actually read/written in this insn
				# check ab_loc is register, stack, or glbal/heap
				
				# find all values used in insn
				values_used_set = set()
			
				if len(ab_locs_containing_tainted_value) != 0 and addr in info.insnsmap:
					insn = info.insnsmap[addr]
					# insn has one operand
					if len(insn.operands) == 1 and insn.operands[0].type == X86_OP_REG:
						#print("*")
						#print(hex(addr))
						#print(insn.mnemonic)
						#print(insn.op_str)
						#print(insn.reg_name(insn.operands[0].value.reg))
						reg_name = insn.reg_name(insn.operands[0].value.reg)
						if reg_name in info.gpr:
							#print(reg_name)
							values_used_set.add(reg_name)
					elif len(insn.operands) == 2:
						#print("*")
						#print(hex(addr))
						#print(insn.mnemonic)
						#print(insn.op_str)
						#print(insn.operands[0].type)
						#print(insn.operands[1].type)
						if insn.mnemonic.startswith("test") or insn.mnemonic.startswith("cmp"):
							pass
						elif insn.mnemonic.startswith("mov") or insn.mnemonic.startswith("cmove") or insn.mnemonic.startswith("lea"):
							#print("*")
							#print(hex(addr))
							#print(insn.mnemonic)
							#print(insn.op_str)
							#print(insn.operands[0].type)
							#print(insn.operands[1].type)
							if insn.operands[0].type == X86_OP_REG and insn.operands[1].type == X86_OP_REG:
								dest_reg_name = insn.reg_name(insn.operands[0].value.reg)
								src_reg_name = insn.reg_name(insn.operands[1].value.reg)
								values_used_set.add(dest_reg_name)
								values_used_set.add(src_reg_name)
										
							elif insn.operands[0].type == X86_OP_REG and insn.operands[1].type == X86_OP_MEM:
								dest_reg_name = insn.reg_name(insn.operands[0].value.reg)
								src_op = insn.operands[1]
								#print("*")
								#print(hex(addr))
								#print(insn.mnemonic)
								#print(insn.op_str)
								#print(insn.operands[0].type)
								#print(insn.operands[1].type)
								
								# lea insn
								if insn.mnemonic.startswith("lea") and dest_reg_name in info.gpr:
									# lea insn: check whether lea global var addr and generate global var pointer
									if src_op.value.mem.disp >= info.mmin_data_section_addr \
									and src_op.value.mem.disp <= info.mmax_data_section_addr:
										#print("*")
										#print(hex(addr))
										#print(hex(src_op.value.mem.disp))
										values_used_set.add(dest_reg_name)
										values_used_set.add(value)
										# add global var pointer to dest op reg
										value = "GLOBAL_POINTER_" + hex(src_op.value.mem.disp)
										values_used_set.add(dest_reg_name)
										values_used_set.add(value)
									else:
										values_used_set.add(dest_reg_name)
								
								# mov/cmov insn
								if (insn.mnemonic.startswith("mov") or insn.mnemonic.startswith("cmove")) and dest_reg_name in info.gpr:
									
									if src_op.value.mem.base != 0:
										src_op_base_reg_name = info.insnsmap[addr].reg_name(src_op.value.mem.base)
										
										# mov stack var via base
										if src_op_base_reg_name == "esp" and src_op.value.mem.index == 0:
											#print(src_op.value.mem.disp)
											if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
												value = info.insn_stack_offset_map[addr] + src_op.value.mem.disp
												#print("*")
												#print(hex(addr))
												#print(value)
												values_used_set.add(dest_reg_name)
												values_used_set.add(value)
											else:
												values_used_set.add(dest_reg_name)
										
										# mov global var via disp
										elif src_op.value.mem.disp >= info.mmin_data_section_addr \
											and src_op.value.mem.disp <= info.mmax_data_section_addr:
											#print("*")
											#print(hex(addr))
											#print(hex(src_op.value.mem.disp))
											# add global var to dest op reg
											value = src_op.value.mem.disp
											values_used_set.add(dest_reg_name)
											values_used_set.add(value)
										
										# mov global/heap var via base, i.e., dereference global/heap var pointer
										elif addr in info.insn_summary_map and src_op_base_reg_name in info.insn_summary_map[addr]:
											dereference = False
											for base_reg_value in info.insn_summary_map[addr][src_op_base_reg_name]:
												if not isinstance(base_reg_value, int):
													# global pointer dereference
													if base_reg_value.startswith("GLOBAL_POINTER_"):
														gvar_addr_string = base_reg_value[15:]
														gvar_addr = int(gvar_addr_string, 16)
														#print("*")
														#print(hex(addr))
														#print(gvar_addr_string)
														#print(hex(gvar_addr))
														
														# add global var to dest op reg
														value = gvar_addr
														values_used_set.add(dest_reg_name)
														values_used_set.add(value)
														dereference = True
														break
														
													# heap pointer dereference
													elif base_reg_value.startswith("HEAP_POINTER_"):
														hvar_addr_string = base_reg_value[13:]
														hvar_addr = int(hvar_addr_string, 16)
														#print("*")
														#print(hex(addr))
														#print(hvar_addr_string)
														#print(hex(hvar_addr))
														
														# add global var to dest op reg
														value = "HEAP_" + hex(hvar_addr)
														values_used_set.add(dest_reg_name)
														values_used_set.add(value)
														dereference = True
														break
											if dereference == False:
												values_used_set.add(dest_reg_name)
										else:
											values_used_set.add(dest_reg_name)

									elif src_op.value.mem.base == 0:
										# mov stack var via index
										if src_op.value.mem.index != 0 and info.insnsmap[addr].reg_name(src_op.value.mem.index) == "esp":
											if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
												value = info.insn_stack_offset_map[addr] * src_op.value.mem.scale + src_op.value.mem.disp
												#print(info.insn_stack_offset_map[addr])
												#print(op.value.mem.scale)
												#print(op.value.mem.disp)
												#print("*")
												#print(hex(addr))
												#print(value)
												values_used_set.add(dest_reg_name)
												values_used_set.add(value)
										# mov stack/global via disp
										elif src_op.value.mem.index == 0:
											#print("*")
											#print(hex(addr))
											#print(insn.mnemonic)
											#print(insn.op_str)
											#print(hex(src_op.value.mem.disp))
											
											# stack or global var dereference
											value = src_op.value.mem.disp
											values_used_set.add(dest_reg_name)
											values_used_set.add(value)
										else:
											values_used_set.add(dest_reg_name)
									else:
										values_used_set.add(dest_reg_name)
							elif insn.operands[0].type == X86_OP_REG and insn.operands[1].type == X86_OP_IMM:
								dest_reg_name = insn.reg_name(insn.operands[0].value.reg)
								if dest_reg_name in info.gpr:
									values_used_set.add(dest_reg_name)
							elif insn.operands[0].type == X86_OP_MEM and insn.operands[1].type == X86_OP_REG:
								src_reg_name = insn.reg_name(insn.operands[1].value.reg)
								dest_op = insn.operands[0]
								
								# all mov/cmov, no lea, as dest is mem
								
								if dest_op.value.mem.base != 0 and src_reg_name in info.gpr:
								
									dest_op_base_reg_name = info.insnsmap[addr].reg_name(dest_op.value.mem.base)
								
									# mov into stack var via base
									if dest_op_base_reg_name == "esp" and dest_op.value.mem.index == 0:
										#print(dest_op.value.mem.disp)
										if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
											value = info.insn_stack_offset_map[addr] + dest_op.value.mem.disp
											#print("*")
											#print(hex(addr))
											#print(value)
											values_used_set.add(src_reg_name)
											values_used_set.add(value)
												
									# mov into global var via disp
									elif dest_op.value.mem.disp >= info.mmin_data_section_addr \
										and dest_op.value.mem.disp <= info.mmax_data_section_addr:
										#print("*")
										#print(hex(addr))
										#print(hex(dest_op.value.mem.disp))
										# add global var to dest
										value = dest_op.value.mem.disp
										values_used_set.add(src_reg_name)
										values_used_set.add(value)
									
									# mov global/heap var via base, i.e., dereference global/heap var pointer
									elif addr in info.insn_summary_map and dest_op_base_reg_name in info.insn_summary_map[addr]:
										for base_reg_value in info.insn_summary_map[addr][dest_op_base_reg_name]:
											if not isinstance(base_reg_value, int):
												# global pointer dereference
												if base_reg_value.startswith("GLOBAL_POINTER_"):
													gvar_addr_string = base_reg_value[15:]
													gvar_addr = int(gvar_addr_string, 16)
													#print("*")
													#print(hex(addr))
													#print(gvar_addr_string)
													#print(hex(gvar_addr))
													
													# add global var to dest op reg
													value = gvar_addr
													#print("*")
													#print(hex(addr))
													#print(insn.mnemonic)
													#print(insn.op_str)
													#print(hex(dest_op.value.mem.disp))
													values_used_set.add(src_reg_name)
													values_used_set.add(value)
													break
													
												# heap pointer dereference
												elif base_reg_value.startswith("HEAP_POINTER_"):
													hvar_addr_string = base_reg_value[13:]
													hvar_addr = int(hvar_addr_string, 16)
													#print("*")
													#print(hex(addr))
													#print(hvar_addr_string)
													#print(hex(hvar_addr))
													
													# add global var to dest op reg
													value = hvar_addr
													#print("*")
													#print(hex(addr))
													#print(insn.mnemonic)
													#print(insn.op_str)
													#print(hex(dest_op.value.mem.disp))
													values_used_set.add(src_reg_name)
													values_used_set.add(value)
													break	
									
									
								elif dest_op.value.mem.base == 0 and src_reg_name in info.gpr:

									# mov into stack var via index
									if dest_op.value.mem.index != 0 and info.insnsmap[addr].reg_name(dest_op.value.mem.index) == "esp":
										if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
											value = info.insn_stack_offset_map[addr] * dest_op.value.mem.scale + dest_op.value.mem.disp
											#print(info.insn_stack_offset_map[addr])
											#print(op.value.mem.scale)
											#print(op.value.mem.disp)
											#print("*")
											#print(hex(addr))
											#print(value)
											values_used_set.add(src_reg_name)
											values_used_set.add(value)
									# mov into stack/global via disp
									elif dest_op.value.mem.index == 0:
										value = dest_op.value.mem.disp
										#print("*")
										#print(hex(addr))
										#print(insn.mnemonic)
										#print(insn.op_str)
										#print(hex(dest_op.value.mem.disp))
										values_used_set.add(src_reg_name)
										values_used_set.add(value)
														
							elif insn.operands[0].type == X86_OP_MEM and insn.operands[1].type == X86_OP_IMM:
								dest_op = insn.operands[0]
								
								# all mov/cmov, no lea, as dest is mem
								
								if dest_op.value.mem.base != 0:
									dest_op_base_reg_name = info.insnsmap[addr].reg_name(dest_op.value.mem.base)
									
									# mov into stack var via base
									if dest_op_base_reg_name == "esp" and dest_op.value.mem.index == 0:
										#print(dest_op.value.mem.disp)
										if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
											value = info.insn_stack_offset_map[addr] + dest_op.value.mem.disp
											#print("*")
											#print(hex(addr))
											#print(value)
											values_used_set.add(value)
									
									# mov into global var via disp
									elif dest_op.value.mem.disp >= info.mmin_data_section_addr \
										and dest_op.value.mem.disp <= info.mmax_data_section_addr:
										#print("*")
										#print(hex(addr))
										#print(hex(dest_op.value.mem.disp))
										# clear dest
										value = dest_op.value.mem.disp
										values_used_set.add(value)
									
									# mov global/heap var via base, i.e., dereference global/heap var pointer
									elif addr in info.insn_summary_map and dest_op_base_reg_name in info.insn_summary_map[addr]:
										for base_reg_value in info.insn_summary_map[addr][dest_op_base_reg_name]:
											if not isinstance(base_reg_value, int):
												# global pointer dereference
												if base_reg_value.startswith("GLOBAL_POINTER_"):
													gvar_addr_string = base_reg_value[15:]
													gvar_addr = int(gvar_addr_string, 16)
													#print("*")
													#print(hex(addr))
													#print(gvar_addr_string)
													#print(hex(gvar_addr))
													# clear dest op reg
													value = gvar_addr
													values_used_set.add(value)
													break
												# heap pointer dereference
												elif base_reg_value.startswith("HEAP_POINTER_"):
													hvar_addr_string = base_reg_value[13:]
													hvar_addr = int(hvar_addr_string, 16)
													#print("*")
													#print(hex(addr))
													#print(hvar_addr_string)
													#print(hex(hvar_addr))
													# clear dest op reg
													value = hvar_addr
													values_used_set.add(value)
													break
								else:
									# mov into stack var via index
									if dest_op.value.mem.index != 0 and info.insnsmap[addr].reg_name(dest_op.value.mem.index) == "esp":
										if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
											value = info.insn_stack_offset_map[addr] * dest_op.value.mem.scale + dest_op.value.mem.disp
											#print(info.insn_stack_offset_map[addr])
											#print(op.value.mem.scale)
											#print(op.value.mem.disp)
											#print("*")
											#print(hex(addr))
											#print(value)
											values_used_set.add(value)
									
									# mov into stack/global via disp
									elif dest_op.value.mem.index == 0:
										value = dest_op.value.mem.disp
										#print("*")
										#print(hex(addr))
										#print(hex(value))
										values_used_set.add(value)
														
						else:
							if insn.operands[0].type == X86_OP_REG:
								dest_reg_name = insn.reg_name(insn.operands[0].value.reg)
								if dest_reg_name in info.gpr:
									values_used_set.add(dest_reg_name)
							elif insn.operands[0].type == X86_OP_MEM:
								dest_op = insn.operands[0]
								
								value = None
								
								if dest_op.value.mem.base != 0:
									dest_op_base_reg_name = info.insnsmap[addr].reg_name(dest_op.value.mem.base)
									
									# dest mem: stack var via base
									if info.insnsmap[addr].reg_name(dest_op.value.mem.base) == "esp" and dest_op.value.mem.index == 0:
										#print(dest_op.value.mem.disp)
										if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
											value = info.insn_stack_offset_map[addr] + dest_op.value.mem.disp
											#print("*")
											#print(hex(addr))
											#print(value)
											values_used_set.add(value)
											
									# dest mem: global var via disp
									elif dest_op.value.mem.disp >= info.mmin_data_section_addr \
										and dest_op.value.mem.disp <= info.mmax_data_section_addr:
										#print("*")
										#print(hex(addr))
										#print(hex(dest_op.value.mem.disp))
										# clear dest
										value = dest_op.value.mem.disp
										values_used_set.add(value)
										
									# dest mem: global/heap var via base, i.e., dereference global/heap var pointer
									elif addr in info.insn_summary_map and dest_op_base_reg_name in info.insn_summary_map[addr]:
										for base_reg_value in info.insn_summary_map[addr][dest_op_base_reg_name]:
											if not isinstance(base_reg_value, int):
												# global pointer dereference
												if base_reg_value.startswith("GLOBAL_POINTER_"):
													gvar_addr_string = base_reg_value[15:]
													gvar_addr = int(gvar_addr_string, 16)
													#print("*")
													#print(hex(addr))
													#print(gvar_addr_string)
													#print(hex(gvar_addr))
													# clear dest op reg
													value = gvar_addr
													values_used_set.add(value)
													break
												# heap pointer dereference
												elif base_reg_value.startswith("HEAP_POINTER_"):
													hvar_addr_string = base_reg_value[13:]
													hvar_addr = int(hvar_addr_string, 16)
													#print("*")
													#print(hex(addr))
													#print(hvar_addr_string)
													#print(hex(hvar_addr))
													# clear dest op reg
													value = hvar_addr
													values_used_set.add(value)
													break
								
								else:
									# dest mem: stack var via index
									if dest_op.value.mem.index != 0 and info.insnsmap[addr].reg_name(dest_op.value.mem.index) == "esp":
										if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
											value = info.insn_stack_offset_map[addr] * dest_op.value.mem.scale + dest_op.value.mem.disp
											#print(info.insn_stack_offset_map[addr])
											#print(op.value.mem.scale)
											#print(op.value.mem.disp)
											#print("*")
											#print(hex(addr))
											#print(value)
											values_used_set.add(value)
									# dest mem: stack/global via disp
									elif dest_op.value.mem.index == 0:
										value = dest_op.value.mem.disp
										#print("*")
										#print(hex(addr))
										#print(hex(value))
										values_used_set.add(value)
								
				if len(values_used_set.intersection(ab_locs_containing_tainted_value)) != 0:
					info.tainted_insn_addresses_typed.add(addr)
					#print("*")
					#print(hex(addr))
					#print(values_used_set)
					#print(ab_locs_containing_tainted_value)

				
				# add original taint sources to tainted insn addresses
				if addr in info.callsite_map and len(info.callsite_map[addr]) >= 1:
					callee_addr = list(info.callsite_map[addr])[0]
					if callee_addr in info.func_addr_map:
						callee_name = list(info.func_addr_map[callee_addr])[0]
						if callee_name.endswith("@plt"):
							callee_short_name = callee_name[:callee_name.index("@plt")]
							if callee_short_name in info.args.taintsources:
								info.tainted_insn_addresses_typed.add(addr)
				
				addr = findnextinsaddr(addr)
				
			
			#for tainted_insn_addr in sorted(info.tainted_insn_addresses_typed):
			#	print(hex(tainted_insn_addr))
				

				
		if info.tainted_insn_addresses_typed == old_tainted_insn_addresses_typed:
			break
			
		
	#for func_addr in info.func_taintedvar_map_typed:
	#	print("*")
	#	print(hex(func_addr))
	#	for ab_loc in info.func_taintedvar_map_typed[func_addr]:
	#		if isinstance(ab_loc, int):
	#			print(hex(ab_loc))
	#		else:
	#			print(ab_loc)
				

	for csinsn in info.insns:
		if csinsn.id in [6,7,8,25,48,49,56,71,72,73,74,77,79,80,81,82, \
                        85,87,88,90,91,92,94,147,322,323,332,333,334, \
                        449,477,481,566,588,621]:
			info.tainted_insn_addresses_typed.add(csinsn.address)
	#		print(hex(csinsn.address))
			

	#print("+++++")
	#for tainted_insn_addr in sorted(info.tainted_insn_addresses_typed):
	#	print(hex(tainted_insn_addr))





	info.tainted_insn_typed_output_file = info.binaryfile + "_tainted_insn_typed_output_file"
	f = open(info.tainted_insn_typed_output_file, "w")
	for tainted_insn_addr in sorted(info.tainted_insn_addresses_typed):
		f.write(hex(tainted_insn_addr) + "\n")
	f.close()

def generate_function_summary_typed():


	info.func_summary_map_typed_tmp_file = info.binaryfile + "_func_summary_map_typed_tmp_file"
	info.insn_summary_map_typed_tmp_file = info.binaryfile + "_insn_summary_map_typed_tmp_file"

	if os.path.exists(info.func_summary_map_typed_tmp_file) and os.path.exists(info.insn_summary_map_typed_tmp_file):
	
		info.func_summary_map_typed = {}
		for func_addr in sorted(info.func_addr_map):
			info.func_summary_map_typed[func_addr] = {}

		f = open(info.func_summary_map_typed_tmp_file, "r")
		lines = f.readlines()

		func_addr = None
		key = None
		value = set()
		
		line_num = 0
		
		parse_func_addr = False
		parse_key = False
		parse_value = False
		
		key_count = 0
		value_count = None


		for line in lines:
			#print(line)
			l = line.strip()
			#print(l)
			if "*" in line:
				if func_addr:
					if key_count != 0:
						info.func_summary_map_typed[func_addr][key] = copy.deepcopy(value)
					func_addr = None
					key = None
					value = set()
					key_count = 0
					parse_value = False
				parse_func_addr = True
			elif parse_func_addr == True:
				func_addr = int(l, 16)
				parse_func_addr = False
			elif line.startswith("+"):
				value_count = int(l[1:-1], 10)
				parse_value = False
				parse_key = True
				if key_count != 0:
					info.func_summary_map_typed[func_addr][key] = copy.deepcopy(value)
				key_count = key_count + 1
			elif parse_key == True:
				try:
					key = int(l, 16)
				except:
					key = l
				value = set()
				parse_key = False
				parse_value = True
			elif parse_value == True:
				try:
					value.add(int(l, 16))
				except:
					value.add(l)
			if line_num == len(lines) - 1:
				if key_count != 0:
					info.func_summary_map_typed[func_addr][key] = copy.deepcopy(value)
				func_addr = None
				key = None
				value = set()
				key_count = 0
				parse_value = False

			line_num = line_num + 1

		f.close()
		
		#for addr in sorted(info.func_summary_map_typed):
		#	print("*")
		#	print(hex(addr))
		#	for ab_loc in info.func_summary_map_typed[addr]:
		#		print("+" + str(len(info.func_summary_map_typed[addr][ab_loc])) + "+")
		#		if isinstance(ab_loc, int):
		#			print(hex(ab_loc))
		#		else:
		#			print(ab_loc)
		#		for ab_loc_1 in info.func_summary_map_typed[addr][ab_loc]:
		#			if isinstance(ab_loc_1, int):
		#				print(hex(ab_loc_1))
		#			else:
		#				print(ab_loc_1)


		info.insn_summary_map_typed = {}
		
		for func_addr in info.ordered_func_addresses:
			func_name = info.func_addr_map[func_addr][0]
			func_end_addr = info.func_addr_map[func_addr][1]
			#print("*")
			#print(func_name)
			#print(hex(func_addr))
			#print(hex(func_end_addr))
			
			if func_addr not in info.insnsmap:
				continue
			if func_addr not in info.cfg.kb.functions:
				continue
			if func_addr not in info.func_addr_map:
				continue
			
			#print("*")
			#print(func_name)
			#print(hex(func_addr))
			#print(hex(func_end_addr))
			
			addr = func_addr
			while addr <= func_end_addr and addr != -1:
				info.insn_summary_map_typed[addr] = {}
				addr = findnextinsaddr(addr)
		
		f = open(info.insn_summary_map_typed_tmp_file, "r")
		lines = f.readlines()

		addr = None
		key = None
		value = set()
		
		line_num = 0
		
		parse_addr = False
		parse_key = False
		parse_value = False
		
		key_count = 0
		value_count = None


		for line in lines:
			#print(line)
			l = line.strip()
			#print(l)
			if "*" in line:
				if addr:
					if key_count != 0:
						info.insn_summary_map_typed[addr][key] = copy.deepcopy(value)
					addr = None
					key = None
					value = set()
					key_count = 0
					parse_value = False
				parse_addr = True
			elif parse_addr == True:
				addr = int(l, 16)
				parse_addr = False
			elif line.startswith("+"):
				value_count = int(l[1:-1], 10)
				parse_value = False
				parse_key = True
				if key_count != 0:
					info.insn_summary_map_typed[addr][key] = copy.deepcopy(value)
				key_count = key_count + 1
			elif parse_key == True:
				try:
					key = int(l, 16)
				except:
					key = l
				value = set()
				parse_key = False
				parse_value = True
			elif parse_value == True:
				try:
					value.add(int(l, 16))
				except:
					value.add(l)
			if line_num == len(lines) - 1:
				if key_count != 0:
					info.insn_summary_map_typed[addr][key] = copy.deepcopy(value)
				addr = None
				key = None
				value = set()
				key_count = 0
				parse_value = False

			line_num = line_num + 1

		f.close()
		
		#for addr in sorted(info.insn_summary_map_typed):
		#	print("*")
		#	print(hex(addr))
		#	for ab_loc in info.insn_summary_map_typed[addr]:
		#		print("+" + str(len(info.insn_summary_map_typed[addr][ab_loc])) + "+")
		#		if isinstance(ab_loc, int):
		#			print(hex(ab_loc))
		#		else:
		#			print(ab_loc)
		#		for ab_loc_1 in info.insn_summary_map_typed[addr][ab_loc]:
		#			if isinstance(ab_loc_1, int):
		#				print(hex(ab_loc_1))
		#			else:
		#				print(ab_loc_1)

		return


	for func_addr in sorted(info.func_addr_map):
		info.func_summary_map_typed[func_addr] = {}


	# generate func summary for all functions first

	# iterate
	for i in range(1):
		# in reversed topological order
		for func_addr in info.ordered_func_addresses:
			func_name = info.func_addr_map[func_addr][0]
			func_end_addr = info.func_addr_map[func_addr][1]
			#print("*")
			#print(func_name)
			#print(hex(func_addr))
			#print(hex(func_end_addr))
			
			if func_addr not in info.insnsmap:
				continue
			if func_addr not in info.cfg.kb.functions:
				continue
			if func_addr not in info.func_addr_map:
				continue
			#if func_addr != 0x807e0e0:
			#	continue
			#if func_addr != 0x8049b0e:
			#	continue
			#if func_addr != 0x8049baf:
			#	continue
			#if func_addr != 0x8049c25:
			#	continue
			#if func_addr != 0x8048ed0:
			#	continue
			#if func_addr != 0x804d7c0:
			#	continue
			
			#print("*")
			#print(func_name)
			#print(hex(func_addr))
			#print(hex(func_end_addr))
			
			# run liveness analysis on each function
			
			# local bookkeeping
			# insn addr to insn summary map
			# insn summary:
			# reg, stack (including paras), global or heap to a set of regs, stack(including paras), globals, or heaps
			# register is eax, ebx, ecx, edx, edi, esi, esp, ebp
			# stack is a number relative to esp at the function beginning state
			# note paras are stack variables, 0x4, 0x8, 0xc, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x28
			# global is address (0xyyyyyyyy or speical values GLOBAL_POINTER_0xyyyyyyyy)
			# heap is malloc insn addr (speical values HEAP_POINTER_0xyyyyyyyy and speical values HEAP_0xyyyyyyyy)
			# a special CLEAR for overwritten by some intermediate results
			# special values for called function side effects: CALLSITE_P1(-P10)_0x(callsite) and CALLSITE_EAX_0x(callsite)
			# the first is after the instructions up to and excluding current insn
			# the second is the function beginning state
			insn_summary_map_typed = {}
			
			addr = func_addr
			while addr <= func_end_addr and addr != -1:
				insn_summary_map_typed[addr] = {}
				info.insn_summary_map_typed[addr] = {}
				addr = findnextinsaddr(addr)
			
			insn_summary_map_typed[func_addr] = {}
			
			# traverse the CFG
			for j in range(1):
				addr = func_addr
				while addr <= func_end_addr and addr != -1:
					#print("*")
					#print(hex(addr))
					# update which successor
					succs = []
					is_call_insn = False
					callsite_para_ab_locs = []
					
					if addr not in info.bbendaddr_bbstartaddr_map:
						if findnextinsaddr(addr) != -1:
							nextaddr = findnextinsaddr(addr)
							if nextaddr >= func_addr and nextaddr <= func_end_addr:
								succs.append(nextaddr)
					else:
						if addr in info.insnsmap:
							insn = info.insnsmap[addr]
							# skip the call for now
							if insn.mnemonic.startswith("call"):
								# find out fall through address
								if findnextinsaddr(addr) != -1:
									nextaddr = findnextinsaddr(addr)
									if nextaddr >= func_addr and nextaddr <= func_end_addr:
										succs.append(nextaddr)
										
								#print("*")
								#print(hex(func_addr))
								#print(hex(addr))
								#print(str(info.callsite_para_access_map[addr]))
								#print(info.insn_stack_offset_map[addr])
								#print("+")
								is_call_insn = True
								if addr in info.callsite_para_access_map and addr in info.insn_stack_offset_map:
									call_insn_para_access = info.callsite_para_access_map[addr]
									call_insn_esp_value = info.insn_stack_offset_map[addr]
									for index in range(call_insn_para_access):
										ab_loc = call_insn_esp_value + index * 4
										#print(str(ab_loc))
										callsite_para_ab_locs.append([int(ab_loc), int(index + 1)])
									#print(callsite_para_ab_locs)
							else:
								if func_addr in info.cfg.kb.functions:
									#print(hex(addr))
									if info.cfg.model.get_any_node(info.bbendaddr_bbstartaddr_map[addr]) != None:
										for succ in info.cfg.model.get_any_node(info.bbendaddr_bbstartaddr_map[addr]).successors:
											if succ.addr >= func_addr and succ.addr <= func_end_addr:
												succs.append(succ.addr)
					
					#print(hex(findnextinsaddr(addr)))
					#print("succs:")
					#for succ in succs:
					#	print(hex(succ))
					#print("*")
					

					# update each successor insn
					for succ in succs:
					
						# deadcode do not flow to non-dead code
						#if info.deadcode[addr] == True and info.deadcode[succ] == False:
						#	continue
							
						#print("*")
						#print(hex(addr))
						#print(info.deadcode[addr])
						#print(hex(succ))
						#print(info.deadcode[succ])
					
						# old insn summary, this might come from other incoming edges
						old = copy.deepcopy(insn_summary_map_typed[succ])
						
						# copy whole thing first, we'll remove some copied values later
						for ab_loc in insn_summary_map_typed[addr]:
							if ab_loc not in insn_summary_map_typed[succ]:
								insn_summary_map_typed[succ][ab_loc] = set()
							insn_summary_map_typed[succ][ab_loc] = insn_summary_map_typed[succ][ab_loc].union(copy.deepcopy(insn_summary_map_typed[addr][ab_loc]))
						
						#if addr == 0x807e13f and succ == 0x807e118:
						#	print("*")
						#	print(insn_summary_map_typed[addr])
						#	print(insn_summary_map_typed[succ])
						
						# if addr is call insn, add special function parameters and return values to succ
						if is_call_insn == True:
						
							# check the callees' summary, see whether they affect the parameters and return values (whether they return)
							#para_count = len(callsite_para_ab_locs)
							#para_affected = set()
							#func_return = False
							#to_bbs = []
							
							#if addr in info.unsolved_call_site_addrs:
							#	para_affected = copy.deepcopy((para_affected.union(set(range(para_count))) - set([0])).union(set([para_count])))
							#	func_return = True
							#else:
							#	call_insn_bb_addr = info.bbendaddr_bbstartaddr_map[addr]
							#	from_bb = info.cfg.model.get_any_node(call_insn_bb_addr)
							#	to_bbs = []
							#	if from_bb != None:
							#		to_bbs = from_bb.successors
								
							#	if len(to_bbs) == 0:
							#		para_affected = copy.deepcopy((para_affected.union(set(range(para_count))) - set([0])).union(set([para_count])))
							#		func_return = True
							#	else:
									
							#		for to_bb in to_bbs:
							#			to_func_addr = to_bb.addr
							#			for para in range(para_count):
							#				if (para + 1) * 4 in info.func_summary_map_typed[to_func_addr]:
							#					para_affected.add(para + 1)
							#			if "eax" in info.func_summary_map_typed[to_func_addr]:
							#				func_return = True
							
							
							#print("*")
							#print(hex(addr))
							#print(hex(succ))
							#print(para_affected)
							#print(func_return)
							#print(info.insn_stack_offset_map[addr])
							#print(callsite_para_ab_locs)
							#if len(to_bbs) != 0:
							#	print("+")
							#	for to_bb in sorted(to_bbs):
							#		print(hex(to_bb.addr))
								
							# update value in callsite paras ab locs
							for callsite_para_ab_loc in callsite_para_ab_locs:
							
								# do not update if parameter is not pointer
								callsite_para_index = callsite_para_ab_loc[1] - 1
								if addr in info.bbendaddr_bbstartaddr_map:
									call_insn_bb_addr = info.bbendaddr_bbstartaddr_map[addr]
									from_bb = info.cfg.model.get_any_node(call_insn_bb_addr)
									if from_bb != None:
										to_bbs = from_bb.successors
										if len(to_bbs) >= 1 and to_bbs[0].name != "UnresolvableCallTarget":
											#print(to_bbs[0])
											#print(dir(to_bbs[0]))
											callee_func_addr = to_bbs[0].addr
											if callee_func_addr in info.funcaddr_para_details_map and addr in info.callsite_para_details_map:
												#print(hex(addr))
												#print(hex(callee_func_addr))
												#print(info.funcaddr_para_details_map[callee_func_addr])
												nonpointer = False
												if len(info.funcaddr_para_details_map[callee_func_addr]) <= callsite_para_index:
													if info.callsite_para_details_map[addr][callsite_para_index] == 0:
														nonpointer = True
												elif info.funcaddr_para_details_map[callee_func_addr][callsite_para_index] == 0 \
													and info.callsite_para_details_map[addr][callsite_para_index] == 0:
														nonpointer = True
												if nonpointer == True:
													#print("*")
													#print(hex(callsite_para_index))
													#print(hex(addr))
													#print(info.callsite_para_details_map[addr])
													#print(hex(callee_func_addr))
													#print(info.funcaddr_para_details_map[callee_func_addr])
													
													# do not update this parameter
													continue
							
								#if callsite_para_ab_loc[1] in para_affected:
								#print(callsite_para_ab_loc)
								added_value = "CALLSITE_P" + str(callsite_para_ab_loc[1]) + "_" + hex(addr)
								added_value_set = set()
								added_value_set.add(added_value)
								
								
								ab_loc = callsite_para_ab_loc[0]
								if ab_loc not in insn_summary_map_typed[succ]:
									insn_summary_map_typed[succ][ab_loc] = set()
								if ab_loc not in insn_summary_map_typed[addr]:
									insn_summary_map_typed[addr][ab_loc] = set([ab_loc])
								if ab_loc not in old:
									old[ab_loc] = set()
								#insn_summary_map_typed[succ][ab_loc] = \
								#	copy.deepcopy((insn_summary_map_typed[succ][ab_loc].union(added_value_set) - \
								#	insn_summary_map_typed[addr][ab_loc]).union(old[ab_loc]))
									
								insn_summary_map_typed[succ][ab_loc] = \
									copy.deepcopy(insn_summary_map_typed[succ][ab_loc].union(added_value_set))
									
								#print("*")
								#print(hex(succ))
								#print(hex(ab_loc))
								#print(insn_summary_map_typed[succ][ab_loc])
								
								# also update value in ab locs contained in callsite paras ab locs
								ab_loc_copy = ab_loc
								for ab_loc in insn_summary_map_typed[addr][ab_loc_copy]:
									# update every ab loc except "CLEAR"
									if ab_loc != "CLEAR":
										if ab_loc not in insn_summary_map_typed[succ]:
											insn_summary_map_typed[succ][ab_loc] = set()
										if ab_loc not in insn_summary_map_typed[addr]:
											insn_summary_map_typed[addr][ab_loc] = set([ab_loc])
										if ab_loc not in old:
											old[ab_loc] = set()
										#insn_summary_map_typed[succ][ab_loc] = \
										#	copy.deepcopy((insn_summary_map_typed[succ][ab_loc].union(added_value_set) - \
										#	insn_summary_map_typed[addr][ab_loc]).union(old[ab_loc]))
											
										insn_summary_map_typed[succ][ab_loc] = \
											copy.deepcopy(insn_summary_map_typed[succ][ab_loc].union(added_value_set))
											
										#print("*")
										#print(hex(succ))
										#if isinstance(ab_loc, int):
										#	print(hex(ab_loc))
										#else:
										#	print(ab_loc)
										#print(insn_summary_map_typed[succ][ab_loc])	
								
							# update return value eax in call fall through insn
							#if func_return == True:
							added_value = ""
							
							# malloc, calloc, realloc returns a heap var pointer in eax, this is a special value
							if addr in info.insnstringsmap and "malloc@plt" in info.insnstringsmap[addr] or \
								"calloc@plt" in info.insnstringsmap[addr] or "realloc@plt" in info.insnstringsmap[addr]:
								#print("*")
								#print(hex(addr))
								#print(info.insnstringsmap[addr])
								added_value = "HEAP_POINTER_" + hex(addr)
							# normal call insn		
							else:
								added_value = "CALLSITE_EAX_" + hex(addr)
							
							added_value_set = set([added_value])
							ab_loc = "eax"
							if ab_loc not in insn_summary_map_typed[succ]:
								insn_summary_map_typed[succ][ab_loc] = set()
							if ab_loc not in insn_summary_map_typed[addr]:
								#print("*")
								#print(hex(addr))
								#print(insn_summary_map_typed[addr])
								insn_summary_map_typed[addr][ab_loc] = set([ab_loc])
							if ab_loc not in old:
								old[ab_loc] = set()
							insn_summary_map_typed[succ][ab_loc] = \
								copy.deepcopy((insn_summary_map_typed[succ][ab_loc].union(added_value_set) - \
								insn_summary_map_typed[addr][ab_loc]).union(old[ab_loc]))
							#print("*")
							#print(hex(succ))
							#print(ab_loc)
							#print(insn_summary_map_typed[succ][ab_loc])
						
						
						# update value sets	
						if addr in info.insnsmap:
							insn = info.insnsmap[addr]
							if len(insn.operands) == 1 and insn.operands[0].type == X86_OP_REG:
								#print("*")
								#print(hex(addr))
								#print(insn.mnemonic)
								#print(insn.op_str)
								#print(insn.reg_name(insn.operands[0].value.reg))
								reg_name = insn.reg_name(insn.operands[0].value.reg)
								if reg_name in info.gpr:
									#print(reg_name)

									if insn.mnemonic.startswith("push"):
										if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
											write_to_stack_addr = info.insn_stack_offset_map[addr] - 4
											if reg_name not in insn_summary_map_typed[addr]:
												insn_summary_map_typed[addr][reg_name] = set([reg_name])
											if write_to_stack_addr not in insn_summary_map_typed[succ]:
												insn_summary_map_typed[succ][write_to_stack_addr] = set()
											if write_to_stack_addr not in insn_summary_map_typed[addr]:
												insn_summary_map_typed[addr][write_to_stack_addr] = set([write_to_stack_addr])
											if write_to_stack_addr not in old:
												old[write_to_stack_addr] = set()
											insn_summary_map_typed[succ][write_to_stack_addr] = \
												copy.deepcopy((insn_summary_map_typed[succ][write_to_stack_addr].union(insn_summary_map_typed[addr][reg_name]) \
												- insn_summary_map_typed[addr][write_to_stack_addr]).union(old[write_to_stack_addr]))
								
									elif insn.mnemonic.startswith("pop"):
										if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
											read_from_stack_addr = info.insn_stack_offset_map[addr]
											if read_from_stack_addr not in insn_summary_map_typed[addr]:
												insn_summary_map_typed[addr][read_from_stack_addr] = set([read_from_stack_addr])
											if reg_name not in insn_summary_map_typed[succ]:
												insn_summary_map_typed[succ][reg_name] = set()
											if reg_name not in insn_summary_map_typed[addr]:
												insn_summary_map_typed[addr][reg_name] = set([reg_name])
											if reg_name not in old:
												old[reg_name] = set()
											insn_summary_map_typed[succ][reg_name] = \
												copy.deepcopy((insn_summary_map_typed[succ][reg_name].union(insn_summary_map_typed[addr][read_from_stack_addr]) \
												- insn_summary_map_typed[addr][reg_name]).union(old[reg_name]))
									elif insn.mnemonic.startswith("inc") or insn.mnemonic.startswith("neg"):
										insn_summary_map_typed[succ][reg_name] = set(["CLEAR"])
									
												
							elif len(insn.operands) == 2:
								#print("*")
								#print(hex(addr))
								#print(insn.mnemonic)
								#print(insn.op_str)
								#print(insn.operands[0].type)
								#print(insn.operands[1].type)
								if insn.mnemonic.startswith("test") or insn.mnemonic.startswith("cmp"):
									pass
								elif insn.mnemonic.startswith("mov") or insn.mnemonic.startswith("cmove") or insn.mnemonic.startswith("lea"):
									#print("*")
									#print(hex(addr))
									#print(insn.mnemonic)
									#print(insn.op_str)
									#print(insn.operands[0].type)
									#print(insn.operands[1].type)
									if insn.operands[0].type == X86_OP_REG and insn.operands[1].type == X86_OP_REG:
										dest_reg_name = insn.reg_name(insn.operands[0].value.reg)
										src_reg_name = insn.reg_name(insn.operands[1].value.reg)
										if dest_reg_name in info.gpr and src_reg_name in info.gpr:
											if src_reg_name not in insn_summary_map_typed[addr]:
												insn_summary_map_typed[addr][src_reg_name] = set([src_reg_name])
											if dest_reg_name not in insn_summary_map_typed[succ]:
												insn_summary_map_typed[succ][dest_reg_name] = set()
											if dest_reg_name not in insn_summary_map_typed[addr]:
												insn_summary_map_typed[addr][dest_reg_name] = set([dest_reg_name])
											if dest_reg_name not in old:
												old[dest_reg_name] = set()
											insn_summary_map_typed[succ][dest_reg_name] = \
												copy.deepcopy((insn_summary_map_typed[succ][dest_reg_name].union(insn_summary_map_typed[addr][src_reg_name]) \
												- insn_summary_map_typed[addr][dest_reg_name]).union(old[dest_reg_name]))
												
									elif insn.operands[0].type == X86_OP_REG and insn.operands[1].type == X86_OP_MEM:
										dest_reg_name = insn.reg_name(insn.operands[0].value.reg)
										src_op = insn.operands[1]
										#print("*")
										#print(hex(addr))
										#print(insn.mnemonic)
										#print(insn.op_str)
										#print(insn.operands[0].type)
										#print(insn.operands[1].type)
										
										# lea insn
										if insn.mnemonic.startswith("lea") and dest_reg_name in info.gpr:
											# lea insn: check whether lea global var addr and generate global var pointer
											if src_op.value.mem.disp >= info.mmin_data_section_addr \
											and src_op.value.mem.disp <= info.mmax_data_section_addr:
												#print("*")
												#print(hex(addr))
												#print(hex(src_op.value.mem.disp))
												
												# add global var pointer to dest op reg
												value = "GLOBAL_POINTER_" + hex(src_op.value.mem.disp)
												if dest_reg_name not in insn_summary_map_typed[succ]:
													insn_summary_map_typed[succ][dest_reg_name] = set()
												if dest_reg_name not in insn_summary_map_typed[addr]:
													insn_summary_map_typed[addr][dest_reg_name] = set([dest_reg_name])
												if dest_reg_name not in old:
													old[dest_reg_name] = set()
												insn_summary_map_typed[succ][dest_reg_name] = \
													copy.deepcopy((insn_summary_map_typed[succ][dest_reg_name].union(set([value])) \
													- insn_summary_map_typed[addr][dest_reg_name]).union(old[dest_reg_name]))
											else:
												insn_summary_map_typed[succ][dest_reg_name] = set(["CLEAR"])
										
										# mov/cmov insn
										if (insn.mnemonic.startswith("mov") or insn.mnemonic.startswith("cmove")) and dest_reg_name in info.gpr:
											
											if src_op.value.mem.base != 0:
												src_op_base_reg_name = info.insnsmap[addr].reg_name(src_op.value.mem.base)
												
												# mov stack var via base
												if src_op_base_reg_name == "esp" and src_op.value.mem.index == 0:
													#print(src_op.value.mem.disp)
													if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
														value = info.insn_stack_offset_map[addr] + src_op.value.mem.disp
														#print("*")
														#print(hex(addr))
														#print(value)
														if value not in insn_summary_map_typed[addr]:
															insn_summary_map_typed[addr][value] = set([value])
														if dest_reg_name not in insn_summary_map_typed[succ]:
															insn_summary_map_typed[succ][dest_reg_name] = set()
														if dest_reg_name not in insn_summary_map_typed[addr]:
															insn_summary_map_typed[addr][dest_reg_name] = set([dest_reg_name])
														if dest_reg_name not in old:
															old[dest_reg_name] = set()
														insn_summary_map_typed[succ][dest_reg_name] = \
															copy.deepcopy((insn_summary_map_typed[succ][dest_reg_name].union( \
															insn_summary_map_typed[addr][value]) \
															- insn_summary_map_typed[addr][dest_reg_name]).union(old[dest_reg_name]))
													else:
														insn_summary_map_typed[succ][dest_reg_name] = set(["CLEAR"])
												
												# mov global var via disp
												elif src_op.value.mem.disp >= info.mmin_data_section_addr \
													and src_op.value.mem.disp <= info.mmax_data_section_addr:
													#print("*")
													#print(hex(addr))
													#print(hex(src_op.value.mem.disp))
													# add global var to dest op reg
													value = src_op.value.mem.disp
													if dest_reg_name not in insn_summary_map_typed[succ]:
														insn_summary_map_typed[succ][dest_reg_name] = set()
													if dest_reg_name not in insn_summary_map_typed[addr]:
														insn_summary_map_typed[addr][dest_reg_name] = set([dest_reg_name])
													if dest_reg_name not in old:
														old[dest_reg_name] = set()
													insn_summary_map_typed[succ][dest_reg_name] = \
														copy.deepcopy((insn_summary_map_typed[succ][dest_reg_name].union( \
														set([value])) \
														- insn_summary_map_typed[addr][dest_reg_name]).union(old[dest_reg_name]))
												
												# mov global/heap var via base, i.e., dereference global/heap var pointer
												elif addr in insn_summary_map_typed and src_op_base_reg_name in insn_summary_map_typed[addr]:
													dereference = False
													for base_reg_value in insn_summary_map_typed[addr][src_op_base_reg_name]:
														if not isinstance(base_reg_value, int):
															# global pointer dereference
															if base_reg_value.startswith("GLOBAL_POINTER_"):
																gvar_addr_string = base_reg_value[15:]
																gvar_addr = int(gvar_addr_string, 16)
																#print("*")
																#print(hex(addr))
																#print(gvar_addr_string)
																#print(hex(gvar_addr))
																
																# add global var to dest op reg
																value = gvar_addr
																if dest_reg_name not in insn_summary_map_typed[succ]:
																	insn_summary_map_typed[succ][dest_reg_name] = set()
																if dest_reg_name not in insn_summary_map_typed[addr]:
																	insn_summary_map_typed[addr][dest_reg_name] = set([dest_reg_name])
																if dest_reg_name not in old:
																	old[dest_reg_name] = set()
																insn_summary_map_typed[succ][dest_reg_name] = \
																	copy.deepcopy((insn_summary_map_typed[succ][dest_reg_name].union( \
																	set([value])) \
																	- insn_summary_map_typed[addr][dest_reg_name]).union(old[dest_reg_name]))
																dereference = True
																break
																
															# heap pointer dereference
															elif base_reg_value.startswith("HEAP_POINTER_"):
																hvar_addr_string = base_reg_value[13:]
																hvar_addr = int(hvar_addr_string, 16)
																#print("*")
																#print(hex(addr))
																#print(hvar_addr_string)
																#print(hex(hvar_addr))
																
																# add global var to dest op reg
																value = "HEAP_" + hex(hvar_addr)
																if dest_reg_name not in insn_summary_map_typed[succ]:
																	insn_summary_map_typed[succ][dest_reg_name] = set()
																if dest_reg_name not in insn_summary_map_typed[addr]:
																	insn_summary_map_typed[addr][dest_reg_name] = set([dest_reg_name])
																if dest_reg_name not in old:
																	old[dest_reg_name] = set()
																insn_summary_map_typed[succ][dest_reg_name] = \
																	copy.deepcopy((insn_summary_map_typed[succ][dest_reg_name].union( \
																	set([value])) \
																	- insn_summary_map_typed[addr][dest_reg_name]).union(old[dest_reg_name]))
																dereference = True
																break
													if dereference == False:
														insn_summary_map_typed[succ][dest_reg_name] = set(["CLEAR"])
												else:
													insn_summary_map_typed[succ][dest_reg_name] = set(["CLEAR"])

											elif src_op.value.mem.base == 0:
												# mov stack var via index
												if src_op.value.mem.index != 0 and info.insnsmap[addr].reg_name(src_op.value.mem.index) == "esp":
													if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
														value = info.insn_stack_offset_map[addr] * src_op.value.mem.scale + src_op.value.mem.disp
														#print(info.insn_stack_offset_map[addr])
														#print(op.value.mem.scale)
														#print(op.value.mem.disp)
														#print("*")
														#print(hex(addr))
														#print(value)
														if value not in insn_summary_map_typed[addr]:
															insn_summary_map_typed[addr][value] = set([value])
														if dest_reg_name not in insn_summary_map_typed[succ]:
															insn_summary_map_typed[succ][dest_reg_name] = set()
														if dest_reg_name not in insn_summary_map_typed[addr]:
															insn_summary_map_typed[addr][dest_reg_name] = set([dest_reg_name])
														if dest_reg_name not in old:
															old[dest_reg_name] = set()
														insn_summary_map_typed[succ][dest_reg_name] = \
															copy.deepcopy((insn_summary_map_typed[succ][dest_reg_name].union( \
															insn_summary_map_typed[addr][value]) \
															- insn_summary_map_typed[addr][dest_reg_name]).union(old[dest_reg_name]))
												# mov stack/global via disp
												elif src_op.value.mem.index == 0:
													#print("*")
													#print(hex(addr))
													#print(insn.mnemonic)
													#print(insn.op_str)
													#print(hex(src_op.value.mem.disp))
													
													# stack or global var dereference
													value = src_op.value.mem.disp
													if value not in insn_summary_map_typed[addr]:
														insn_summary_map_typed[addr][value] = set([value])
													if dest_reg_name not in insn_summary_map_typed[succ]:
														insn_summary_map_typed[succ][dest_reg_name] = set()
													if dest_reg_name not in insn_summary_map_typed[addr]:
														insn_summary_map_typed[addr][dest_reg_name] = set([dest_reg_name])
													if dest_reg_name not in old:
														old[dest_reg_name] = set()
													insn_summary_map_typed[succ][dest_reg_name] = \
														copy.deepcopy((insn_summary_map_typed[succ][dest_reg_name].union( \
														insn_summary_map_typed[addr][value]) \
														- insn_summary_map_typed[addr][dest_reg_name]).union(old[dest_reg_name]))
												else:
													insn_summary_map_typed[succ][dest_reg_name] = set(["CLEAR"])	
											else:
												insn_summary_map_typed[succ][dest_reg_name] = set(["CLEAR"])
									elif insn.operands[0].type == X86_OP_REG and insn.operands[1].type == X86_OP_IMM:
										dest_reg_name = insn.reg_name(insn.operands[0].value.reg)
										if dest_reg_name in info.gpr:
											insn_summary_map_typed[succ][dest_reg_name] = set(["CLEAR"])
									elif insn.operands[0].type == X86_OP_MEM and insn.operands[1].type == X86_OP_REG:
										src_reg_name = insn.reg_name(insn.operands[1].value.reg)
										dest_op = insn.operands[0]
										
										# all mov/cmov, no lea, as dest is mem
										
										if dest_op.value.mem.base != 0 and src_reg_name in info.gpr:
										
											dest_op_base_reg_name = info.insnsmap[addr].reg_name(dest_op.value.mem.base)
										
											# mov into stack var via base
											if dest_op_base_reg_name == "esp" and dest_op.value.mem.index == 0:
												#print(dest_op.value.mem.disp)
												if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
													value = info.insn_stack_offset_map[addr] + dest_op.value.mem.disp
													#print("*")
													#print(hex(addr))
													#print(value)
													if src_reg_name not in insn_summary_map_typed[addr]:
														insn_summary_map_typed[addr][src_reg_name] = set([src_reg_name])
													if value not in insn_summary_map_typed[succ]:
														insn_summary_map_typed[succ][value] = set()
													if value not in insn_summary_map_typed[addr]:
														insn_summary_map_typed[addr][value] = set([value])
													if value not in old:
														old[value] = set()
													insn_summary_map_typed[succ][value] = \
														copy.deepcopy((insn_summary_map_typed[succ][value].union(insn_summary_map_typed[addr][src_reg_name]) \
														- insn_summary_map_typed[addr][value]).union(old[value]))
														
											# mov into global var via disp
											elif dest_op.value.mem.disp >= info.mmin_data_section_addr \
												and dest_op.value.mem.disp <= info.mmax_data_section_addr:
												#print("*")
												#print(hex(addr))
												#print(hex(dest_op.value.mem.disp))
												# add global var to dest
												value = dest_op.value.mem.disp
												if src_reg_name not in insn_summary_map_typed[addr]:
													insn_summary_map_typed[addr][src_reg_name] = set([src_reg_name])
												if value not in insn_summary_map_typed[succ]:
													insn_summary_map_typed[succ][value] = set()
												if value not in insn_summary_map_typed[addr]:
													insn_summary_map_typed[addr][value] = set([value])
												if value not in old:
													old[value] = set()
												insn_summary_map_typed[succ][value] = \
													copy.deepcopy((insn_summary_map_typed[succ][value].union(insn_summary_map_typed[addr][src_reg_name]) \
													- insn_summary_map_typed[addr][value]).union(old[value]))
											
											# mov global/heap var via base, i.e., dereference global/heap var pointer
											elif addr in insn_summary_map_typed and dest_op_base_reg_name in insn_summary_map_typed[addr]:
												for base_reg_value in insn_summary_map_typed[addr][dest_op_base_reg_name]:
													if not isinstance(base_reg_value, int):
														# global pointer dereference
														if base_reg_value.startswith("GLOBAL_POINTER_"):
															gvar_addr_string = base_reg_value[15:]
															gvar_addr = int(gvar_addr_string, 16)
															#print("*")
															#print(hex(addr))
															#print(gvar_addr_string)
															#print(hex(gvar_addr))
															
															# add global var to dest op reg
															value = gvar_addr
															#print("*")
															#print(hex(addr))
															#print(insn.mnemonic)
															#print(insn.op_str)
															#print(hex(dest_op.value.mem.disp))
															if src_reg_name not in insn_summary_map_typed[addr]:
																insn_summary_map_typed[addr][src_reg_name] = set([src_reg_name])
															if value not in insn_summary_map_typed[succ]:
																insn_summary_map_typed[succ][value] = set()
															if value not in insn_summary_map_typed[addr]:
																insn_summary_map_typed[addr][value] = set([value])
															if value not in old:
																old[value] = set()
															insn_summary_map_typed[succ][value] = \
																copy.deepcopy((insn_summary_map_typed[succ][value].union( \
																insn_summary_map_typed[addr][src_reg_name]) \
																- insn_summary_map_typed[addr][value]).union(old[value]))
															break
															
														# heap pointer dereference
														elif base_reg_value.startswith("HEAP_POINTER_"):
															hvar_addr_string = base_reg_value[13:]
															hvar_addr = int(hvar_addr_string, 16)
															#print("*")
															#print(hex(addr))
															#print(hvar_addr_string)
															#print(hex(hvar_addr))
															
															# add global var to dest op reg
															value = hvar_addr
															#print("*")
															#print(hex(addr))
															#print(insn.mnemonic)
															#print(insn.op_str)
															#print(hex(dest_op.value.mem.disp))
															if src_reg_name not in insn_summary_map_typed[addr]:
																insn_summary_map_typed[addr][src_reg_name] = set([src_reg_name])
															if value not in insn_summary_map_typed[succ]:
																insn_summary_map_typed[succ][value] = set()
															if value not in insn_summary_map_typed[addr]:
																insn_summary_map_typed[addr][value] = set([value])
															if value not in old:
																old[value] = set()
															insn_summary_map_typed[succ][value] = \
																copy.deepcopy((insn_summary_map_typed[succ][value].union( \
																insn_summary_map_typed[addr][src_reg_name]) \
																- insn_summary_map_typed[addr][value]).union(old[value]))
															break	
											
											
										elif dest_op.value.mem.base == 0 and src_reg_name in info.gpr:

											# mov into stack var via index
											if dest_op.value.mem.index != 0 and info.insnsmap[addr].reg_name(dest_op.value.mem.index) == "esp":
												if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
													value = info.insn_stack_offset_map[addr] * dest_op.value.mem.scale + dest_op.value.mem.disp
													#print(info.insn_stack_offset_map[addr])
													#print(op.value.mem.scale)
													#print(op.value.mem.disp)
													#print("*")
													#print(hex(addr))
													#print(value)
													if src_reg_name not in insn_summary_map_typed[addr]:
														insn_summary_map_typed[addr][src_reg_name] = set([src_reg_name])
													if value not in insn_summary_map_typed[succ]:
														insn_summary_map_typed[succ][value] = set()
													if value not in insn_summary_map_typed[addr]:
														insn_summary_map_typed[addr][value] = set([value])
													if value not in old:
														old[value] = set()
													insn_summary_map_typed[succ][value] = \
														copy.deepcopy((insn_summary_map_typed[succ][value].union(insn_summary_map_typed[addr][src_reg_name]) \
														- insn_summary_map_typed[addr][value]).union(old[value]))
											# mov into stack/global via disp
											elif dest_op.value.mem.index == 0:
												value = dest_op.value.mem.disp
												#print("*")
												#print(hex(addr))
												#print(insn.mnemonic)
												#print(insn.op_str)
												#print(hex(dest_op.value.mem.disp))
												if src_reg_name not in insn_summary_map_typed[addr]:
													insn_summary_map_typed[addr][src_reg_name] = set([src_reg_name])
												if value not in insn_summary_map_typed[succ]:
													insn_summary_map_typed[succ][value] = set()
												if value not in insn_summary_map_typed[addr]:
													insn_summary_map_typed[addr][value] = set([value])
												if value not in old:
													old[value] = set()
												insn_summary_map_typed[succ][value] = \
													copy.deepcopy((insn_summary_map_typed[succ][value].union(insn_summary_map_typed[addr][src_reg_name]) \
													- insn_summary_map_typed[addr][value]).union(old[value]))
												
										
																
									elif insn.operands[0].type == X86_OP_MEM and insn.operands[1].type == X86_OP_IMM:
										dest_op = insn.operands[0]
										
										# all mov/cmov, no lea, as dest is mem
										
										if dest_op.value.mem.base != 0:
											dest_op_base_reg_name = info.insnsmap[addr].reg_name(dest_op.value.mem.base)
											
											# mov into stack var via base
											if dest_op_base_reg_name == "esp" and dest_op.value.mem.index == 0:
												#print(dest_op.value.mem.disp)
												if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
													value = info.insn_stack_offset_map[addr] + dest_op.value.mem.disp
													#print("*")
													#print(hex(addr))
													#print(value)
													insn_summary_map_typed[succ][value] = set(["CLEAR"])
											
											# mov into global var via disp
											elif dest_op.value.mem.disp >= info.mmin_data_section_addr \
												and dest_op.value.mem.disp <= info.mmax_data_section_addr:
												#print("*")
												#print(hex(addr))
												#print(hex(dest_op.value.mem.disp))
												# clear dest
												value = dest_op.value.mem.disp
												insn_summary_map_typed[succ][value] = set(["CLEAR"])
											
											# mov global/heap var via base, i.e., dereference global/heap var pointer
											elif addr in insn_summary_map_typed and dest_op_base_reg_name in insn_summary_map_typed[addr]:
												for base_reg_value in insn_summary_map_typed[addr][dest_op_base_reg_name]:
													if not isinstance(base_reg_value, int):
														# global pointer dereference
														if base_reg_value.startswith("GLOBAL_POINTER_"):
															gvar_addr_string = base_reg_value[15:]
															gvar_addr = int(gvar_addr_string, 16)
															#print("*")
															#print(hex(addr))
															#print(gvar_addr_string)
															#print(hex(gvar_addr))
															# clear dest op reg
															value = gvar_addr
															insn_summary_map_typed[succ][value] = set(["CLEAR"])
															break
														# heap pointer dereference
														elif base_reg_value.startswith("HEAP_POINTER_"):
															hvar_addr_string = base_reg_value[13:]
															hvar_addr = int(hvar_addr_string, 16)
															#print("*")
															#print(hex(addr))
															#print(hvar_addr_string)
															#print(hex(hvar_addr))
															# clear dest op reg
															value = hvar_addr
															insn_summary_map_typed[succ][value] = set(["CLEAR"])
															break
										else:
											# mov into stack var via index
											if dest_op.value.mem.index != 0 and info.insnsmap[addr].reg_name(dest_op.value.mem.index) == "esp":
												if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
													value = info.insn_stack_offset_map[addr] * dest_op.value.mem.scale + dest_op.value.mem.disp
													#print(info.insn_stack_offset_map[addr])
													#print(op.value.mem.scale)
													#print(op.value.mem.disp)
													#print("*")
													#print(hex(addr))
													#print(value)
													insn_summary_map_typed[succ][value] = set(["CLEAR"])
											
											# mov into stack/global via disp
											elif dest_op.value.mem.index == 0:
												value = dest_op.value.mem.disp
												#print("*")
												#print(hex(addr))
												#print(hex(value))
												insn_summary_map_typed[succ][value] = set(["CLEAR"])
																
								else:
									if insn.operands[0].type == X86_OP_REG:
										dest_reg_name = insn.reg_name(insn.operands[0].value.reg)
										if dest_reg_name in info.gpr:
										
											# reserve the dest if opcode is add/sub and dest reg contains global/heap pointer/var
											if (insn.mnemonic.startswith("add") or insn.mnemonic.startswith("sub")) and addr in insn_summary_map_typed \
												and dest_reg_name in insn_summary_map_typed[addr]:
												#print("*")
												#print(hex(addr))
												#print(dest_reg_name)
												dest_reserve = False
												tmp_set = set()
												for dest_reg_value in insn_summary_map_typed[addr][dest_reg_name]:
													if not isinstance(dest_reg_value, int):
														# global pointer
														if dest_reg_value.startswith("GLOBAL_POINTER_"):
															#print("*")
															#print(hex(addr))
															#print(dest_reg_value)
															tmp_set.add(dest_reg_value)
															dest_reserve = True
															
														# heap pointer and heap var
														elif dest_reg_value.startswith("HEAP_"):
															tmp_set.add(dest_reg_value)
															dest_reserve = True
													else:
														# global var
														if dest_reg_value >= info.mmin_data_section_addr \
															and dest_reg_value <= info.mmax_data_section_addr:
															#print("*")
															#print(hex(addr))
															#print(hex(dest_reg_value))
															tmp_set.add(dest_reg_value)
															dest_reserve = True
												
												if dest_reserve == True:
													insn_summary_map_typed[succ][dest_reg_name] = tmp_set		
												else:
													insn_summary_map_typed[succ][dest_reg_name] = set(["CLEAR"])
											else:
												insn_summary_map_typed[succ][dest_reg_name] = set(["CLEAR"])
									elif insn.operands[0].type == X86_OP_MEM:
										dest_op = insn.operands[0]
										
										value = None
										
										if dest_op.value.mem.base != 0:
											dest_op_base_reg_name = info.insnsmap[addr].reg_name(dest_op.value.mem.base)
											
											# dest mem: stack var via base
											if info.insnsmap[addr].reg_name(dest_op.value.mem.base) == "esp" and dest_op.value.mem.index == 0:
												#print(dest_op.value.mem.disp)
												if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
													value = info.insn_stack_offset_map[addr] + dest_op.value.mem.disp
													#print("*")
													#print(hex(addr))
													#print(value)
													insn_summary_map_typed[succ][value] = set(["CLEAR"])
													
											# dest mem: global var via disp
											elif dest_op.value.mem.disp >= info.mmin_data_section_addr \
												and dest_op.value.mem.disp <= info.mmax_data_section_addr:
												#print("*")
												#print(hex(addr))
												#print(hex(dest_op.value.mem.disp))
												# clear dest
												value = dest_op.value.mem.disp
												insn_summary_map_typed[succ][value] = set(["CLEAR"])
												
											# dest mem: global/heap var via base, i.e., dereference global/heap var pointer
											elif addr in insn_summary_map_typed and dest_op_base_reg_name in insn_summary_map_typed[addr]:
												for base_reg_value in insn_summary_map_typed[addr][dest_op_base_reg_name]:
													if not isinstance(base_reg_value, int):
														# global pointer dereference
														if base_reg_value.startswith("GLOBAL_POINTER_"):
															gvar_addr_string = base_reg_value[15:]
															gvar_addr = int(gvar_addr_string, 16)
															#print("*")
															#print(hex(addr))
															#print(gvar_addr_string)
															#print(hex(gvar_addr))
															# clear dest op reg
															value = gvar_addr
															insn_summary_map_typed[succ][value] = set(["CLEAR"])
															break
														# heap pointer dereference
														elif base_reg_value.startswith("HEAP_POINTER_"):
															hvar_addr_string = base_reg_value[13:]
															hvar_addr = int(hvar_addr_string, 16)
															#print("*")
															#print(hex(addr))
															#print(hvar_addr_string)
															#print(hex(hvar_addr))
															# clear dest op reg
															value = hvar_addr
															insn_summary_map_typed[succ][value] = set(["CLEAR"])
															break
										
										else:
											# dest mem: stack var via index
											if dest_op.value.mem.index != 0 and info.insnsmap[addr].reg_name(dest_op.value.mem.index) == "esp":
												if addr in info.insn_stack_offset_map and info.insn_stack_offset_map[addr] != None:
													value = info.insn_stack_offset_map[addr] * dest_op.value.mem.scale + dest_op.value.mem.disp
													#print(info.insn_stack_offset_map[addr])
													#print(op.value.mem.scale)
													#print(op.value.mem.disp)
													#print("*")
													#print(hex(addr))
													#print(value)
													insn_summary_map_typed[succ][value] = set(["CLEAR"])
											# dest mem: stack/global via disp
											elif dest_op.value.mem.index == 0:
												value = dest_op.value.mem.disp
												#print("*")
												#print(hex(addr))
												#print(hex(value))
												insn_summary_map_typed[succ][value] = set(["CLEAR"])
										
										# reserve the dest if opcode is add/sub and dest mem contains global/heap pointer/var
										
										# we solved the dest mem addr
										if value != None:
											if (insn.mnemonic.startswith("add") or insn.mnemonic.startswith("sub")) and addr in insn_summary_map_typed \
												and value in insn_summary_map_typed[addr]:
												#print("*")
												#print(hex(addr))
												#print(value)
												dest_reserve = False
												tmp_set = set()
												for dest_mem_value in insn_summary_map_typed[addr][value]:
													if not isinstance(dest_mem_value, int):
														# global pointer
														if dest_mem_value.startswith("GLOBAL_POINTER_"):
															#print("*")
															#print(hex(addr))
															#print(dest_mem_value)
															tmp_set.add(dest_mem_value)
															dest_reserve = True
															
														# heap pointer and heap var
														elif dest_mem_value.startswith("HEAP_"):
															tmp_set.add(dest_mem_value)
															dest_reserve = True
													else:
														# global var
														if dest_mem_value >= info.mmin_data_section_addr \
															and dest_mem_value <= info.mmax_data_section_addr:
															#print("*")
															#print(hex(addr))
															#print(hex(dest_mem_value))
															tmp_set.add(dest_mem_value)
															dest_reserve = True
												
												if dest_reserve == True:
													insn_summary_map_typed[succ][value] = tmp_set		

					addr = findnextinsaddr(addr)			


			# update func summary
			info.func_summary_map_typed[func_addr] = {}
			for addr in sorted(insn_summary_map_typed):
				#print("*")
				#print(hex(addr))
				#for ab_loc in insn_summary_map_typed[addr]:
				#	print("+" + str(len(insn_summary_map_typed[addr][ab_loc])) + "+")
				#	if isinstance(ab_loc, int):
				#		print(hex(ab_loc))
				#	else:
				#		print(ab_loc)
				#	for ab_loc_1 in insn_summary_map_typed[addr][ab_loc]:
				#		if isinstance(ab_loc_1, int):
				#			print(hex(ab_loc_1))
				#		else:
				#			print(ab_loc_1)
							
				if addr in info.ret_insn_addresses:
					#print("*")
					#print(hex(addr))
					for ab_loc in insn_summary_map_typed[addr]:
						#if isinstance(ab_loc, int):
						#	print(hex(ab_loc))
						#else:
						#	print(ab_loc)
						if ab_loc not in info.func_summary_map_typed[func_addr]:
							info.func_summary_map_typed[func_addr][ab_loc] = set()
						info.func_summary_map_typed[func_addr][ab_loc] = copy.deepcopy(info.func_summary_map_typed[func_addr][ab_loc].union(insn_summary_map_typed[addr][ab_loc]))
						#print(insn_summary_map_typed[addr][ab_loc])
						#print(info.func_summary_map_typed[func_addr][ab_loc])
			
				# update info.insn_summary_map_typed
				#print("*")
				#print(hex(addr))
				for ab_loc in insn_summary_map_typed[addr]:
					#if isinstance(ab_loc, int):
					#	print(hex(ab_loc))
					#else:
					#	print(ab_loc)
					if ab_loc not in info.insn_summary_map_typed[addr]:
						info.insn_summary_map_typed[addr][ab_loc] = set()
					info.insn_summary_map_typed[addr][ab_loc] = copy.deepcopy(info.insn_summary_map_typed[addr][ab_loc].union(insn_summary_map_typed[addr][ab_loc]))
					#print(insn_summary_map_typed[addr][ab_loc])
					#print(info.insn_summary_map_typed[addr][ab_loc])
	

	#for addr in sorted(info.func_summary_map_typed):
	#	print("*")
	#	print(hex(addr))
	#	for ab_loc in info.func_summary_map_typed[addr]:
	#		print("+" + str(len(info.func_summary_map_typed[addr][ab_loc])) + "+")
	#		if isinstance(ab_loc, int):
	#			print(hex(ab_loc))
	#		else:
	#			print(ab_loc)
	#		for ab_loc_1 in info.func_summary_map_typed[addr][ab_loc]:
	#			if isinstance(ab_loc_1, int):
	#				print(hex(ab_loc_1))
	#			else:
	#				print(ab_loc_1)
	
	
	#for addr in sorted(info.insn_summary_map_typed):
	#	print("*")
	#	print(hex(addr))
	#	for ab_loc in info.insn_summary_map_typed[addr]:
	#		print("+" + str(len(info.insn_summary_map_typed[addr][ab_loc])) + "+")
	#		if isinstance(ab_loc, int):
	#			print(hex(ab_loc))
	#		else:
	#			print(ab_loc)
	#		for ab_loc_1 in info.insn_summary_map_typed[addr][ab_loc]:
	#			if isinstance(ab_loc_1, int):
	#				print(hex(ab_loc_1))
	#			else:
	#				print(ab_loc_1)
	

	
	f = open(info.func_summary_map_typed_tmp_file, "w")
	for addr in sorted(info.func_summary_map_typed):
		f.write("*\n")
		f.write(hex(addr) + "\n")
		for ab_loc in info.func_summary_map_typed[addr]:
			f.write("+" + str(len(info.func_summary_map_typed[addr][ab_loc])) + "+\n")
			if isinstance(ab_loc, int):
				f.write(hex(ab_loc) + "\n")
			else:
				f.write(ab_loc + "\n")
			for ab_loc_1 in info.func_summary_map_typed[addr][ab_loc]:
				if isinstance(ab_loc_1, int):
					f.write(hex(ab_loc_1) + "\n")
				else:
					f.write(ab_loc_1 + "\n")
	f.close()

	f = open(info.insn_summary_map_typed_tmp_file, "w")
	for addr in sorted(info.insn_summary_map_typed):
		f.write("*\n")
		f.write(hex(addr) + "\n")
		for ab_loc in info.insn_summary_map_typed[addr]:
			f.write("+" + str(len(info.insn_summary_map_typed[addr][ab_loc])) + "+\n")
			if isinstance(ab_loc, int):
				f.write(hex(ab_loc) + "\n")
			else:
				f.write(ab_loc + "\n")
			for ab_loc_1 in info.insn_summary_map_typed[addr][ab_loc]:
				if isinstance(ab_loc_1, int):
					f.write(hex(ab_loc_1) + "\n")
				else:
					f.write(ab_loc_1 + "\n")
	f.close()




def update_CFG():
	#print("update_CFG")
	#index = 0
	#print(len(info.callsite_para_access_map))
	max_total = 250000
	if len(info.callsite_para_access_map) > 50000:
		max_total = 10000
	total_index = 0
	for callsite_insn_addr in sorted(info.callsite_para_access_map):
		#print("*")
		#print("add edge")
		##print(str(index))
		#print("callsite_insn_addr")
		#print(hex(callsite_insn_addr))
		index = 0
		#print(str(total_index))
		if total_index > max_total:
			break
		# first connect newly resolved jmp insn to its targets
		if callsite_insn_addr in info.jmp_insn_addresses:
			if callsite_insn_addr in info.bbendaddr_bbstartaddr_map:
				jmp_insn_bb_addr = info.bbendaddr_bbstartaddr_map[callsite_insn_addr]
				from_bb = info.cfg.model.get_any_node(jmp_insn_bb_addr)
				old_to_bbs = []
				if from_bb != None:
					old_to_bbs = from_bb.successors
				# remove edge if the target is fake
				for old_to_bb in old_to_bbs:
					if old_to_bb.name == "UnresolvableJumpTarget":
						info.cfg.graph.remove_edge(from_bb, old_to_bb)
						#print("*")
						#print(hex(from_bb.addr))
						#print(hex(old_to_bb.addr))
				# add edge
				for func_addr in sorted(info.funcaddr_para_access_map):
					if info.funcaddr_para_access_map[func_addr] == info.callsite_para_access_map[callsite_insn_addr]:
						index = index + 1
						total_index = total_index + 1
						if index > 500:
							break
						if total_index > max_total:
							break
						to_bb = info.cfg.model.get_any_node(func_addr)
						data = {}
						data["jumpkind"] = "Ijk_Boring"
						info.cfg.graph.add_edge(from_bb, to_bb, **data)
						#print("*")
						#print(hex(from_bb.addr))
						#print(hex(to_bb.addr))
						
		# connect newly resolved call insn to its targets
		if callsite_insn_addr in info.call_insn_addresses:
			#print(hex(callsite_insn_addr))
			if callsite_insn_addr in info.bbendaddr_bbstartaddr_map:
				call_insn_bb_addr = info.bbendaddr_bbstartaddr_map[callsite_insn_addr]
				from_bb = info.cfg.model.get_any_node(call_insn_bb_addr)
				old_to_bbs = []
				if from_bb != None:
					old_to_bbs = from_bb.successors
				unsolved = False
				# remove edge if the target is fake
				for old_to_bb in old_to_bbs:
					if old_to_bb.name == "UnresolvableCallTarget":
						info.cfg.graph.remove_edge(from_bb, old_to_bb)
						#print("*")
						#print(hex(from_bb.addr))
						#print(hex(old_to_bb.addr))
						unsolved = True
				if unsolved == True:
					# add edge
					for func_addr in sorted(info.funcaddr_para_access_map):
						if info.funcaddr_para_access_map[func_addr] == info.callsite_para_access_map[callsite_insn_addr]:
							index = index + 1
							total_index = total_index + 1
							if index > 500:
								break
							if total_index > max_total:
								break
							to_bb = info.cfg.model.get_any_node(func_addr)
							data = {}
							data["jumpkind"] = "Ijk_Call"
							info.cfg.graph.add_edge(from_bb, to_bb, **data)
							#print("*")
							#print(hex(from_bb.addr))
							#print(hex(to_bb.addr))
							
							for ret_insn_addr in info.func_rets_map[func_addr]:
								index = index + 1
								total_index = total_index + 1
								if index > 500:
									break
								if total_index > max_total:
									break
								ret_insn_bb_addr = info.bbendaddr_bbstartaddr_map[ret_insn_addr]
								ret_bb = info.cfg.model.get_any_node(ret_insn_bb_addr)
								data = {}
								data["jumpkind"] = "Ijk_Ret"
								info.cfg.graph.add_edge(ret_bb, from_bb, **data)
								#print("*")
								#print(hex(ret_bb.addr))
								#print(hex(from_bb.addr))
						
	# on the updated CFG, generate our concise callgraph
	#print("generate callgraph")
	for func_addr in sorted(info.func_addr_map):
		info.concise_callgraph.add_node(func_addr)
		info.concise_callgraph_acyclic.add_node(func_addr)
	
	for callsite_insn_addr in info.call_insn_addresses:
		#print(hex(callsite_insn_addr))
		if callsite_insn_addr in info.bbendaddr_bbstartaddr_map:
			#print("*")
			#print(hex(callsite_insn_addr))
			info.callsite_map[callsite_insn_addr] = set()
			call_insn_bb_addr = info.bbendaddr_bbstartaddr_map[callsite_insn_addr]
			from_bb = info.cfg.model.get_any_node(call_insn_bb_addr)
			to_bbs = []
			if from_bb != None:
				to_bbs = from_bb.successors
			for to_bb in to_bbs:
				#print("*")
				#print(hex(callsite_insn_addr))
				#print(hex(to_bb.addr))
				if callsite_insn_addr in info.insn_func_map:
					caller_func_addr = info.insn_func_map[callsite_insn_addr]
					callee_func_addr = to_bb.addr
					if to_bb.addr in info.func_addr_map:
						info.concise_callgraph.add_edge(caller_func_addr, callee_func_addr)
						info.concise_callgraph_acyclic.add_edge(caller_func_addr, callee_func_addr)
						info.callsite_map[callsite_insn_addr].add(callee_func_addr)
						
	# prune to be acyclic for sorting orders
	#print(list(nx.simple_cycles(info.concise_callgraph)))


	#pruned = []

	#print(len(info.concise_callgraph_acyclic.edges()))
	
	#index = 1
	
	try:
		#while_true_start = time.time()
		while True:
			edge = list(nx.find_cycle(info.concise_callgraph_acyclic, orientation='original'))[-1]
			#print("*")
			#print("remove edge")
			##print(str(index))
			##print(list(nx.find_cycle(info.concise_callgraph_acyclic, orientation='original')))
			#print(edge)
			info.concise_callgraph_acyclic.remove_edge(edge[0], edge[1])
			#print(info.concise_callgraph_acyclic.has_edge(edge[0], edge[1]))
			#pruned.append(edge[0], edge[1])
			#list(nx.find_cycle(info.concise_callgraph, orientation='original'))[-1]
			#print("*")
			#print(list(nx.find_cycle(info.concise_callgraph, orientation='original')))
			#print(list(nx.find_cycle(info.concise_callgraph, orientation='original'))[-1])
			#print(hex(edge[0]))
			#print(hex(edge[1]))
			#index = index + 1
			
			
			# if time-out, also break
			#while_true_end = time.time()
			#while_true_time = while_true_end - while_true_start
			#if while_true_time > 300:
			#	break
			
	except:
		pass

	#for p in pruned:
	#	print("*")
	#	print(hex(p[0]))
	#	print(hex(p[1]))
	
	#print(len(info.concise_callgraph_acyclic.edges()))

	#print(len(info.func_addr_map))
	#print(len(info.concise_callgraph_acyclic.nodes()))
	#print(len(list(reversed(list(nx.topological_sort(info.concise_callgraph_acyclic))))))
	info.ordered_func_addresses = list(reversed(list(nx.topological_sort(info.concise_callgraph_acyclic))))

	#print("*")
	#for ordered_func_addr in info.ordered_func_addresses:
	#	print(hex(ordered_func_addr))
	

	#for callsite in sorted(info.callsite_map):
	#	print("*")
	#	print(hex(callsite))
	#	for callee in sorted(info.callsite_map[callsite]):
	#		print(hex(callee))
	
	#print("update_CFG finishes")
	


# generate call site signatures for call sites and unsolved jmp sites
def generate_callsite_signature():

	info.callsite_para_access_map_tmp_file = info.binaryfile + "_callsite_para_access_map_tmp_file"
	
	if os.path.exists(info.callsite_para_access_map_tmp_file):
	
		info.callsite_para_access_map = {}

		f = open(info.callsite_para_access_map_tmp_file, "r")
		lines = f.readlines()

		key = None
		value = None
		index = 0
		line_num = 0


		for line in lines:
			#print(line)
			if "*" in line:
				if key:
					info.callsite_para_access_map[key] = value
					key = None
					value = None
					index = 0
			else:
				if index == 0:
					key = int(line, 16)
				else:
					value = int(line, 10)
					
				index = index + 1

			if line_num == len(lines) - 1:
				if key:
					info.callsite_para_access_map[key] = value
					key = None
					value = None
					index = 0

			line_num = line_num + 1

		f.close()
		
		#for addr in sorted(info.callsite_para_access_map):
		#	print("*")
		#	print(hex(addr))
		#	print(info.callsite_para_access_map[addr])
		
		return


	# two kinds: call sites and jump sites
	
	# call sites
	# check local bb and its fall through bb
	# find all call sites
	unsolved_call_site_addrs = set()
	call_site_addrs = set()
	for func_addr in sorted(info.func_addr_map):
		func_name = info.func_addr_map[func_addr][0]
		func_end_addr = info.func_addr_map[func_addr][1]
		
		#print("*")
		#print(func_name)
		#print(hex(func_addr))
		#print(hex(func_end_addr))
		
		if func_addr not in info.insnsmap:
			continue
		if func_addr not in info.cfg.kb.functions:
			continue
		if func_addr not in info.func_addr_map:
			continue
		
		func = info.cfg.kb.functions[func_addr]
		
		#print("*")
		#print(func_name)
		#for callsite_bb_addr in func.get_call_sites():
		#	#print(hex(callsite_bb_addr))
		#	calltarget = func.get_call_target(callsite_bb_addr)
		#	call_site_addrs.add(info.bbstartaddr_bbendaddr_map[callsite_bb_addr])
		#	if calltarget < info.first_insn_addr or calltarget > info.last_insn_addr:
		#		unsolved_call_site_addrs.add(info.bbstartaddr_bbendaddr_map[callsite_bb_addr])
		
		if func_addr in info.func_call_insn_addresses_map:
			for call_insn_addr in info.func_call_insn_addresses_map[func_addr]:
				if call_insn_addr in info.bbendaddr_bbstartaddr_map:
					callsite_bb_addr = info.bbendaddr_bbstartaddr_map[call_insn_addr]
					if callsite_bb_addr not in func.get_call_sites():
						#print(hex(call_insn_addr))
						if call_insn_addr in info.callsite_explicit_call_targets_map:
							calltarget = info.callsite_explicit_call_targets_map[call_insn_addr]
							call_site_addrs.add(call_insn_addr)
						else:
							unsolved_call_site_addrs.add(call_insn_addr)
					else:
						calltarget = func.get_call_target(callsite_bb_addr)
						call_site_addrs.add(info.bbstartaddr_bbendaddr_map[callsite_bb_addr])
						if calltarget < info.first_insn_addr or calltarget > info.last_insn_addr:
							unsolved_call_site_addrs.add(info.bbstartaddr_bbendaddr_map[callsite_bb_addr])


	
	info.unsolved_call_site_addrs = sorted(unsolved_call_site_addrs)
	
	for addr in info.unsolved_call_site_addrs:
		info.unsolved_call_site_bb_addrs.append(info.bbendaddr_bbstartaddr_map[addr])
		
	info.call_site_addrs = sorted(call_site_addrs)
	
	for addr in info.call_site_addrs:
		info.call_site_bb_addrs.append(info.bbendaddr_bbstartaddr_map[addr])
	
	callsite_para_access_map = {}
	for call_insn_addr in info.call_insn_addresses:
	
		if call_insn_addr not in info.bbendaddr_bbstartaddr_map:
			continue
	
		callsite_bb_addr = info.bbendaddr_bbstartaddr_map[call_insn_addr]
		#print("*")
		#print(hex(call_insn_addr))
		#print(hex(callsite_bb_addr))
		#print("*")
		nextinsnaddr = findnextinsaddr(info.bbstartaddr_bbendaddr_map[callsite_bb_addr])
		#print(nextinsnaddr)

		bb1addr = callsite_bb_addr
		bb1endaddr = info.bbstartaddr_bbendaddr_map[bb1addr]
		#print("*")
		#print(hex(bb1addr))
		
		# check esp in bb1
		# each insn to esp value (first relative to bb1 start esp value, then esp at bb1 end addr) map
		esp_value_map = {}
		# insn to esp write access map
		# insn not in map if esp is not written
		# call_esp -> 1, ..., for ten parameters
		esp_access_map = {}
		
		# list all accesses before call insn
		esp_accesses_before = set()
		
		esp_value_map[bb1addr] = 0
		#print("*")
		addr = bb1addr
		while addr < bb1endaddr and addr != -1:
				
			succ = findnextinsaddr(addr)
			#print(hex(addr))
			#print(hex(succ))
			if succ != -1:
				if addr in info.insnsmap:
					insn = info.insnsmap[addr]
					if insn.mnemonic.startswith("sub") \
						and len(insn.operands) == 2 and insn.operands[1].type == X86_OP_IMM \
						and insn.operands[0].type == X86_OP_REG \
						and "esp" == insn.reg_name(insn.operands[0].value.reg):
							#print(insn.reg_name(insn.operands[0].value.reg))
							esp_value_map[succ] = esp_value_map[addr] - insn.operands[1].value.imm
					elif insn.mnemonic.startswith("add") \
						and len(insn.operands) == 2 and insn.operands[1].type == X86_OP_IMM \
						and insn.operands[0].type == X86_OP_REG \
						and "esp" == insn.reg_name(insn.operands[0].value.reg):
							#print(insn.reg_name(insn.operands[0].value.reg))
							esp_value_map[succ] = esp_value_map[addr] + insn.operands[1].value.imm
					elif insn.mnemonic.startswith("push"):
						#print(insn.op_str)
						esp_value_map[succ] = esp_value_map[addr] - 4
					elif insn.mnemonic.startswith("pop"):
						#print(insn.op_str)
						esp_value_map[succ] = esp_value_map[addr] + 4
					else:
						esp_value_map[succ] = esp_value_map[addr]
				else:
					esp_value_map[succ] = esp_value_map[addr]
					
			addr = findnextinsaddr(addr)

		addr = bb1addr
		while addr <= bb1endaddr and addr != -1:
			#print("*")
			#print(hex(addr))
			#print(hex(bb1endaddr))
			#print(esp_value_map[addr])
			esp_value_map[addr] = esp_value_map[addr] - esp_value_map[bb1endaddr]
			#print(esp_value_map[addr])
			addr = findnextinsaddr(addr)
		
		for addr in sorted(esp_value_map):
			if addr in info.insnsmap:
				insn = info.insnsmap[addr]
				if len(insn.operands) == 2:
					op = insn.operands[0]
					if op.type == X86_OP_MEM:
						#print("*")
						#print(hex(insn.address))
						#print(insn.mnemonic)
						#print(insn.op_str)
						if (op.value.mem.base != 0 and "esp" == info.insnsmap[addr].reg_name(op.value.mem.base)) \
							and (op.value.mem.index == 0):
							#print(op.value.mem.disp)
							value = esp_value_map[addr] + op.value.mem.disp
							#print("*")
							#print(hex(addr))
							#print(value)
							if value in [0x0, 0x4, 0x8, 0xc, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24]:#[0x0, 0x4, 0x8, 0xc, 0x10, 0x14]:
								esp_access_map[addr] = int((value + 0x4) / 0x4)

						if (op.value.mem.index != 0 and "esp" == info.insnsmap[addr].reg_name(op.value.mem.index)) \
							and (op.value.mem.base == 0):
							value = esp_value_map[addr] * op.value.mem.scale + op.value.mem.disp
							#print(esp_value_map[addr])
							#print(op.value.mem.scale)
							#print(op.value.mem.disp)
							#print("*")
							#print(hex(addr))
							#print(value)
							if value in [0x0, 0x4, 0x8, 0xc, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24]:#[0x0, 0x4, 0x8, 0xc, 0x10, 0x14]:
								esp_access_map[addr] = int((value + 0x4) / 0x4)
		mmax = -1
		for addr in sorted(esp_access_map):
			if esp_access_map[addr] > mmax:
				mmax = esp_access_map[addr]
			esp_accesses_before.add(esp_access_map[addr])
				
		if mmax != -1:
			callsite_para_access_map[bb1endaddr] = mmax
		else:
			callsite_para_access_map[bb1endaddr] = 0
			
			
			
			
			
		# check esp in bb2
		# each insn to esp value (relative to bb2 start esp value) map
		
		mmin = 0x10000
		
		if nextinsnaddr != -1 and info.insn_func_map[callsite_bb_addr] == info.insn_func_map[nextinsnaddr]:
			bb2addr = nextinsnaddr
			if bb2addr in info.bbstartaddr_bbendaddr_map:
				bb2endaddr = info.bbstartaddr_bbendaddr_map[bb2addr]
				#print("*")
				#print(hex(bb1addr))
				#print(hex(bb2addr))
				esp_value_map = {}
				# insn to esp read access map
				# insn not in map if esp is not read
				# call_esp -> 1, ..., for ten parameters
				esp_access_map = {}
				
				esp_value_map[bb2addr] = 0
				
				addr = bb2addr
				while addr < bb2endaddr and addr != -1:
						
					succ = findnextinsaddr(addr)
					
					if succ != -1:
						if addr in info.insnsmap:
							insn = info.insnsmap[addr]
							if insn.mnemonic.startswith("sub") \
								and len(insn.operands) == 2 and insn.operands[1].type == X86_OP_IMM \
								and insn.operands[0].type == X86_OP_REG \
								and "esp" == insn.reg_name(insn.operands[0].value.reg):
									#print(insn.reg_name(insn.operands[0].value.reg))
									esp_value_map[succ] = esp_value_map[addr] - insn.operands[1].value.imm
							elif insn.mnemonic.startswith("add") \
								and len(insn.operands) == 2 and insn.operands[1].type == X86_OP_IMM \
								and insn.operands[0].type == X86_OP_REG \
								and "esp" == insn.reg_name(insn.operands[0].value.reg):
									#print(insn.reg_name(insn.operands[0].value.reg))
									esp_value_map[succ] = esp_value_map[addr] + insn.operands[1].value.imm
							elif insn.mnemonic.startswith("push"):
								#print(insn.op_str)
								esp_value_map[succ] = esp_value_map[addr] - 4
							elif insn.mnemonic.startswith("pop"):
								#print(insn.op_str)
								esp_value_map[succ] = esp_value_map[addr] + 4
							else:
								esp_value_map[succ] = esp_value_map[addr]
						else:
							esp_value_map[succ] = esp_value_map[addr]
							
					addr = findnextinsaddr(addr)

				#addr = bb2addr
				#while addr <= bb2endaddr and addr != -1:
				#	print("*")
				#	print(hex(addr))
				#	print(esp_value_map[addr])
				#	addr = findnextinsaddr(addr)
				
				for addr in sorted(esp_value_map):
					if addr in info.insnsmap:
						insn = info.insnsmap[addr]
						if len(insn.operands) == 2:
							op = insn.operands[1]
							if op.type == X86_OP_MEM:
								#print("*")
								#print(hex(insn.address))
								#print(insn.mnemonic)
								#print(insn.op_str)
								
								if insn.mnemonic.startswith("lea") == False:
									if (op.value.mem.base != 0 and "esp" == info.insnsmap[addr].reg_name(op.value.mem.base)) \
										and (op.value.mem.index == 0):
										#print(op.value.mem.disp)
										value = esp_value_map[addr] + op.value.mem.disp
										#print("*")
										#print(hex(addr))
										#print(value)
										if value in [0x0, 0x4, 0x8, 0xc, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24]:#[0x0, 0x4, 0x8, 0xc, 0x10, 0x14]:
											esp_access_map[addr] = int((value + 0x4) / 0x4)

									if (op.value.mem.index != 0 and "esp" == info.insnsmap[addr].reg_name(op.value.mem.index)) \
										and (op.value.mem.base == 0):
										value = esp_value_map[addr] * op.value.mem.scale + op.value.mem.disp
										#print(esp_value_map[addr])
										#print(op.value.mem.scale)
										#print(op.value.mem.disp)
										#print("*")
										#print(hex(addr))
										#print(value)
										if value in [0x0, 0x4, 0x8, 0xc, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24]:#[0x0, 0x4, 0x8, 0xc, 0x10, 0x14]:
											esp_access_map[addr] = int((value + 0x4) / 0x4)

				for addr in sorted(esp_access_map):
					if esp_access_map[addr] < mmin:
						mmin = esp_access_map[addr]
				
		if mmin != 0x10000 and callsite_para_access_map[bb1endaddr] != 0:
			if callsite_para_access_map[bb1endaddr] >= mmin:
				if (mmin - 1) in esp_accesses_before:
					callsite_para_access_map[bb1endaddr] = mmin - 1
				else:
					mmax = -1
					for e in esp_accesses_before:
						if e < mmin and e > mmax:
							mmax = e
					if mmax == -1:
						callsite_para_access_map[bb1endaddr] = 0
					else:
						callsite_para_access_map[bb1endaddr] = mmax
						
		info.callsite_para_access_map[bb1endaddr] = callsite_para_access_map[bb1endaddr]
			
		#print("*")
		#print("hex(bb1endaddr): " + hex(bb1endaddr))
		#print("mmin: " + str(mmin))
		#print("callsite_para_access_map[bb1endaddr]: " + str(callsite_para_access_map[bb1endaddr]))
		#print(info.project.factory.block(bb2addr).pp())
	
	# jmp sites
	
	# first check prototype is generated
	if len(info.funcaddr_para_access_map) == 0:
		generate_func_prototype()
	
	# find all unsolved jmp sites
	for jmp_insn_addr in info.jmp_insn_addresses:
		if jmp_insn_addr in info.bbendaddr_bbstartaddr_map:
			jmp_insn_bb_addr = info.bbendaddr_bbstartaddr_map[jmp_insn_addr]
			bbnode = info.cfg.model.get_any_node(jmp_insn_bb_addr)
			if bbnode != None:
				if len(bbnode.successors) == 1:
					jmp_target_addr = bbnode.successors[0].addr
					if jmp_target_addr < info.first_insn_addr or jmp_target_addr > info.last_insn_addr:
						#print("*")
						#print(hex(jmp_insn_addr))
						#print(hex(info.insn_func_map[jmp_insn_addr]))
						#print(info.func_addr_map[info.insn_func_map[jmp_insn_addr]][0])
						func_addr = info.insn_func_map[jmp_insn_addr]
						func_name = info.func_addr_map[func_addr][0]
						#print(info.insnstringsmap[jmp_insn_addr])
						#print(info.insnsmap[jmp_insn_addr].op_str)
						
						if not func_name.endswith("@plt"):
							if func_addr in info.funcaddr_para_access_map:
								info.callsite_para_access_map[jmp_insn_addr] = info.funcaddr_para_access_map[func_addr]
								#print("*")
								#print(hex(jmp_insn_addr))
								#print(str(info.callsite_para_access_map[jmp_insn_addr]))
						
						
						
				#if len(bbnode.successors) == 0:
				#	print("*")
				#	print(hex(jmp_insn_addr))
				#	print(info.insnstringsmap[jmp_insn_addr])
				#	print(info.insnsmap[jmp_insn_addr].op_str)
	
			
			
	#for addr in sorted(info.callsite_para_access_map):
	#	print("*")
	#	print(hex(addr))
	#	print(info.callsite_para_access_map[addr])
					
	f = open(info.callsite_para_access_map_tmp_file, "w")
	for addr in sorted(info.callsite_para_access_map):
		f.write("*\n")
		f.write(hex(addr) + "\n")
		f.write(str(info.callsite_para_access_map[addr]) + "\n")
	f.close()



def generate_func_prototype():

	info.funcaddr_para_access_map_tmp_file = info.binaryfile + "_funcaddr_para_access_map_tmp_file"
	info.insn_para_access_map_tmp_file = info.binaryfile + "_insn_para_access_map_tmp_file"
	info.insn_stack_offset_map_tmp_file = info.binaryfile + "_insn_stack_offset_map_tmp_file"
	info.deadcode_tmp_file = info.binaryfile + "_deadcode_tmp_file"
	
	
	#print(os.path.exists(info.funcaddr_para_access_map_tmp_file))
	#print(os.path.exists(info.insn_para_access_map_tmp_file))
	#print(os.path.exists(info.insn_stack_offset_map_tmp_file))
	#print(os.path.exists(info.deadcode_tmp_file))

	
	if os.path.exists(info.funcaddr_para_access_map_tmp_file) and os.path.exists(info.insn_para_access_map_tmp_file) and os.path.exists(info.insn_stack_offset_map_tmp_file) \
		and os.path.exists(info.deadcode_tmp_file):
	
		info.funcaddr_para_access_map = {}

		f = open(info.funcaddr_para_access_map_tmp_file, "r")
		lines = f.readlines()

		key = None
		value = None
		index = 0
		line_num = 0


		for line in lines:
			#print(line)
			if "*" in line:
				if key:
					info.funcaddr_para_access_map[key] = value
					key = None
					value = None
					index = 0
			else:
				if index == 0:
					key = int(line, 16)
				else:
					value = int(line, 10)
					
				index = index + 1

			if line_num == len(lines) - 1:
				if key:
					info.funcaddr_para_access_map[key] = value
					key = None
					value = None
					index = 0

			line_num = line_num + 1

		f.close()
		
		#for addr in sorted(info.funcaddr_para_access_map):
		#	print("*")
		#	print(hex(addr))
		#	print(info.funcaddr_para_access_map[addr])


		info.insn_para_access_map = {}

		f = open(info.insn_para_access_map_tmp_file, "r")
		lines = f.readlines()

		key = None
		value = None
		index = 0
		line_num = 0


		for line in lines:
			#print(line)
			if "*" in line:
				if key:
					info.insn_para_access_map[key] = value
					key = None
					value = None
					index = 0
			else:
				if index == 0:
					key = int(line, 16)
				else:
					value = int(line, 10)
					
				index = index + 1

			if line_num == len(lines) - 1:
				if key:
					info.insn_para_access_map[key] = value
					key = None
					value = None
					index = 0

			line_num = line_num + 1

		f.close()
		
		#for addr in sorted(info.insn_para_access_map):
		#	print("*")
		#	print(hex(addr))
		#	print(info.insn_para_access_map[addr])
		
		
		
		info.insn_stack_offset_map = {}

		f = open(info.insn_stack_offset_map_tmp_file, "r")
		lines = f.readlines()

		key = None
		value = None
		index = 0
		line_num = 0


		for line in lines:
			#print(line)
			if "*" in line:
				if key:
					info.insn_stack_offset_map[key] = value
					key = None
					value = None
					index = 0
			else:
				if index == 0:
					#print(line)
					key = int(line, 16)
				else:
					#print(line)
					value = int(line, 10)
					
				index = index + 1

			if line_num == len(lines) - 1:
				if key:
					info.insn_stack_offset_map[key] = value
					key = None
					value = None
					index = 0

			line_num = line_num + 1

		f.close()
		
		#for addr in sorted(info.insn_stack_offset_map):
		#	print("*")
		#	print(hex(addr))
		#	print(info.insn_stack_offset_map[addr])


		
		info.deadcode = {}

		f = open(info.deadcode_tmp_file, "r")
		lines = f.readlines()

		key = None
		value = None
		index = 0
		line_num = 0


		for line in lines:
			#print(line)
			if "*" in line:
				if key:
					info.deadcode[key] = value
					key = None
					value = None
					index = 0
			else:
				if index == 0:
					key = int(line, 16)
				else:
					value = int(line, 10)
					if value == 1:
						value = True
					elif value == 0:
						value = False
				index = index + 1

			if line_num == len(lines) - 1:
				if key:
					info.deadcode[key] = value
					key = None
					value = None
					index = 0

			line_num = line_num + 1

		f.close()
		
		#for addr in sorted(info.deadcode):
		#	print("*")
		#	print(hex(addr))
		#	print(info.deadcode[addr])
		
		#for addr in sorted(info.deadcode):
		#	print("*")
		#	print(hex(addr))
		#	if info.deadcode[addr] == True:
		#		print("1")
		#	elif info.deadcode[addr] == False:
		#		print("0")

		return


	for func_addr in sorted(info.func_addr_map):
		func_name = info.func_addr_map[func_addr][0]
		func_end_addr = info.func_addr_map[func_addr][1]
		#print("generate_func_prototype")
		#print("*")
		#print(func_name)
		#print(hex(func_addr))
		#print(hex(func_end_addr))
		
		if func_addr not in info.insnsmap:
			continue
		if func_addr not in info.cfg.kb.functions:
			continue
		if func_addr not in info.func_addr_map:
			continue
		#if func_addr != 0x8059400:
		#	continue
		#if func_addr != 0x807e0e0:
		#	continue
		
		#print("*")
		#print(func_name)
		#print(hex(func_addr))
		#print(hex(func_end_addr))
		
		# run liveness analysis on each function
		
		# check six parameters at most
		# they should be rsp + 0x4, rsp + 0x8, rsp + 0xc, rsp + 0x10, rsp + 0x14, rsp + 0x18
		
		
		# check which instruction read or write which parameters
		# look for sub, add, push, pop instructions
		
		insn_stack_offset_map = {}
		insn_para_access_map = {}
		
		addr = func_addr
		while addr <= func_end_addr and addr != -1:
			insn_stack_offset_map[addr] = None
			info.deadcode[addr] = False
			addr = findnextinsaddr(addr)
		
		# Perl_pad_push
		
		# traverse the CFG
		# handle function entry insn
		insn_stack_offset_map[func_addr] = 0
		
		
		while_true_start = time.time()
		while True:
		
			old_insn_stack_offset_map = copy.deepcopy(insn_stack_offset_map)
			
			addr = func_addr
			while addr <= func_end_addr and addr != -1:
				#print("*")
				#print(hex(addr))
				# update which successor
				succs = []
				
				if addr not in info.bbendaddr_bbstartaddr_map:
					if findnextinsaddr(addr) != -1:
						nextaddr = findnextinsaddr(addr)
						if nextaddr >= func_addr and nextaddr <= func_end_addr:
							succs.append(nextaddr)
				else:
					if addr in info.insnsmap:
						insn = info.insnsmap[addr]
						if insn.mnemonic.startswith("call"):
							if findnextinsaddr(addr) != -1:
								nextaddr = findnextinsaddr(addr)
								if nextaddr >= func_addr and nextaddr <= func_end_addr:
									succs.append(nextaddr)
						else:
							if func_addr in info.cfg.kb.functions:
								if info.cfg.model.get_any_node(info.bbendaddr_bbstartaddr_map[addr]) != None:
									for succ in info.cfg.model.get_any_node(info.bbendaddr_bbstartaddr_map[addr]).successors:
										if succ.addr >= func_addr and succ.addr <= func_end_addr:
											succs.append(succ.addr)
				
				#print("*")
				#print(hex(findnextinsaddr(addr)))
				#print("succs:")
				#for succ in succs:
				#	print(hex(succ))
				#print("*")
				
				# update each successor insn
				if insn_stack_offset_map[addr] != None:
					for succ in succs:
						if addr in info.insnsmap:
							insn = info.insnsmap[addr]
							if insn.mnemonic.startswith("sub") \
								and len(insn.operands) == 2 and insn.operands[1].type == X86_OP_IMM \
								and insn.operands[0].type == X86_OP_REG \
								and "esp" == insn.reg_name(insn.operands[0].value.reg):
									#print(insn.reg_name(insn.operands[0].value.reg))
									insn_stack_offset_map[succ] = insn_stack_offset_map[addr] - insn.operands[1].value.imm
							elif insn.mnemonic.startswith("add") \
								and len(insn.operands) == 2 and insn.operands[1].type == X86_OP_IMM \
								and insn.operands[0].type == X86_OP_REG \
								and "esp" == insn.reg_name(insn.operands[0].value.reg):
									#print(insn.reg_name(insn.operands[0].value.reg))
									insn_stack_offset_map[succ] = insn_stack_offset_map[addr] + insn.operands[1].value.imm
							elif insn.mnemonic.startswith("push"):
								#print(insn.op_str)
								insn_stack_offset_map[succ] = insn_stack_offset_map[addr] - 4
							elif insn.mnemonic.startswith("pop"):
								#print(insn.op_str)
								insn_stack_offset_map[succ] = insn_stack_offset_map[addr] + 4
							else:
								insn_stack_offset_map[succ] = insn_stack_offset_map[addr]
						else:
							insn_stack_offset_map[succ] = insn_stack_offset_map[addr]
						#print("++")
						#print(info.insnsmap[addr].mnemonic)
						#print(insn_stack_offset_map[addr])
						#print(insn_stack_offset_map[succ])
						#print("++")						
								
				addr = findnextinsaddr(addr)
						
			changed = False
			addr = func_addr
			while addr <= func_end_addr and addr != -1:
				if insn_stack_offset_map[addr] != old_insn_stack_offset_map[addr]:
					changed = True
					break
				addr = findnextinsaddr(addr)
			
			'''
			# fix unreachable insn due to unsolved jmp insn (or just dead code)
			# here for convinience we will give an insn_stack_offset_map value to every insn in function
			if None in insn_stack_offset_map.values():
				# we need to propagate to dead code and further more iterations
				changed = True
			
				dead_code_snippet_begin_addresses = []
				default_insn_stack_offset = None
				
				# find dead_code_snippet_begin_addresses and default_insn_stack_offset
				addr = func_addr
				while addr <= func_end_addr and addr != -1:
					if insn_stack_offset_map[addr] == None:
						
						pre_insn_addr = findpreviousinsaddr(addr)
						if pre_insn_addr != -1 and insn_stack_offset_map[pre_insn_addr] != None:
							dead_code_snippet_begin_addresses.append(addr)
					
					# try to set default_insn_stack_offset via unsolved jmp
					elif addr in info.jmp_insn_addresses:
						jmp_insn_bb_addr = info.bbendaddr_bbstartaddr_map[addr]
						from_bb = info.cfg.model.get_any_node(jmp_insn_bb_addr)
						to_bbs = []
						if from_bb != None:
							to_bbs = from_bb.successors
						#print("*")
						#print(hex(addr))
						#print(len(to_bbs))
						# remove edge if the target is fake
						if len(to_bbs) == 0 or (len(to_bbs) == 1 and to_bbs[0].name == "UnresolvableJumpTarget"):
							default_insn_stack_offset = insn_stack_offset_map[addr]
							#print("*")
							#print(hex(addr))
							#print(hex(default_insn_stack_offset))
					addr = findnextinsaddr(addr)
				
				# set stack offsets for dead_code_snippet_begin_addresses
				for dead_code_snippet_begin_addr in dead_code_snippet_begin_addresses:
					if default_insn_stack_offset != None:
						insn_stack_offset_map[dead_code_snippet_begin_addr] = default_insn_stack_offset
					# if no unsolved jmp is found, use first bb end insn stack offset for each dead code snippet begin addr
					else:
						first_bb_end_addr = info.bbstartaddr_bbendaddr_map[func_addr]
						insn_stack_offset_map[dead_code_snippet_begin_addr] = insn_stack_offset_map[first_bb_end_addr]
					#print("*")
					#print(hex(dead_code_snippet_begin_addr))
					#print(hex(insn_stack_offset_map[dead_code_snippet_begin_addr]))
			'''
							
			if changed == False:
				break
				
			# if time-out, also break
			while_true_end = time.time()
			while_true_time = while_true_end - while_true_start
			if while_true_time > 60:
				break

		# fix unreachable insn due to unsolved jmp insn (or just dead code)
		# here for convinience we will give an insn_stack_offset_map value to every insn in function
		if None in insn_stack_offset_map.values():
		
			default_insn_stack_offset = None
			
			# find default_insn_stack_offset
			addr = func_addr
			while addr <= func_end_addr and addr != -1:
				# try to set default_insn_stack_offset via unsolved jmp
				if addr in info.jmp_insn_addresses and addr in info.bbendaddr_bbstartaddr_map:
					jmp_insn_bb_addr = info.bbendaddr_bbstartaddr_map[addr]
					from_bb = info.cfg.model.get_any_node(jmp_insn_bb_addr)
					to_bbs = []
					if from_bb != None:
						to_bbs = from_bb.successors
					#print("*")
					#print(hex(addr))
					#print(len(to_bbs))
					# remove edge if the target is fake
					if len(to_bbs) == 0 or (len(to_bbs) == 1 and to_bbs[0].name == "UnresolvableJumpTarget"):
						default_insn_stack_offset = insn_stack_offset_map[addr]
						#print("*")
						#print(hex(addr))
						#print(hex(default_insn_stack_offset))
				addr = findnextinsaddr(addr)
			
			# set stack offsets for dead code
			addr = func_addr
			while addr <= func_end_addr and addr != -1:
				if insn_stack_offset_map[addr] == None:
					#print(hex(addr))
				
					# found a dead code insn, record it.
					info.deadcode[addr] = True
				
					if default_insn_stack_offset != None:
						insn_stack_offset_map[addr] = default_insn_stack_offset
					# if no unsolved jmp is found, use first bb end insn stack offset for each dead code snippet begin addr
					else:
						first_bb_end_addr = info.bbstartaddr_bbendaddr_map[func_addr]
						insn_stack_offset_map[addr] = insn_stack_offset_map[first_bb_end_addr]
						
						if insn_stack_offset_map[addr] == None:
							insn_stack_offset_map[addr] = 0
						
					#print("*")
					#print(hex(addr))
					#print(hex(insn_stack_offset_map[addr]))
				addr = findnextinsaddr(addr)



		
		for addr in sorted(insn_stack_offset_map):
			if addr in info.insnsmap:
				for op in info.insnsmap[addr].operands:
					if op.type == X86_OP_MEM:
						if (op.value.mem.base != 0 and "esp" == info.insnsmap[addr].reg_name(op.value.mem.base)) \
							and (op.value.mem.index == 0):
							#print(insn_stack_offset_map[addr])
							#print(op.value.mem.disp)
							if insn_stack_offset_map[addr] != None:
								value = insn_stack_offset_map[addr] + op.value.mem.disp
								#print("*")
								#print(hex(addr))
								#print(value)
								if value in [0x4, 0x8, 0xc, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x28]:
									insn_para_access_map[addr] = int(value / 0x4)

						if (op.value.mem.index != 0 and "esp" == info.insnsmap[addr].reg_name(op.value.mem.index)) \
							and (op.value.mem.base == 0):
							if insn_stack_offset_map[addr] != None:
								value = insn_stack_offset_map[addr] * op.value.mem.scale + op.value.mem.disp
								#print(insn_stack_offset_map[addr])
								#print(op.value.mem.scale)
								#print(op.value.mem.disp)
								#print("*")
								#print(hex(addr))
								#print(value)
								if value in [0x4, 0x8, 0xc, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x28]:
									insn_para_access_map[addr] = int(value / 0x4)
		esp_accesses = set()
		mmax = -1
		for addr in sorted(insn_para_access_map):
			if insn_para_access_map[addr] > mmax:
				mmax = insn_para_access_map[addr]
			esp_accesses.add(insn_para_access_map[addr])
		
		if mmax != -1:
			#serialmax = 0
			#for access in sorted(esp_accesses):
			#	serialmax = access
			#	if access + 1 not in esp_accesses:
			#		if access + 2 not in esp_accesses:
			#			break
			info.funcaddr_para_access_map[func_addr] = mmax
		else:
			info.funcaddr_para_access_map[func_addr] = 0

		#print("*")
		#print(hex(func_addr))
		#print(str(info.funcaddr_para_access_map[func_addr]))
		
		
		for addr in sorted(insn_para_access_map):
			info.insn_para_access_map[addr] = insn_para_access_map[addr]

		for addr in sorted(insn_stack_offset_map):
			info.insn_stack_offset_map[addr] = insn_stack_offset_map[addr]

	#for addr in sorted(info.funcaddr_para_access_map):
	#	print("*")
	#	print(hex(addr))
	#	print(info.funcaddr_para_access_map[addr])
	#for addr in sorted(info.deadcode):
	#	print("*")
	#	print(hex(addr))
	#	if info.deadcode[addr] == True:
	#		print("1")
	#	elif info.deadcode[addr] == False:
	#		print("0")

	f = open(info.funcaddr_para_access_map_tmp_file, "w")
	for addr in sorted(info.funcaddr_para_access_map):
		f.write("*\n")
		f.write(hex(addr) + "\n")
		f.write(str(info.funcaddr_para_access_map[addr]) + "\n")
	f.close()
	
	f = open(info.insn_para_access_map_tmp_file, "w")
	for addr in sorted(info.insn_para_access_map):
		f.write("*\n")
		f.write(hex(addr) + "\n")
		f.write(str(info.insn_para_access_map[addr]) + "\n")
	f.close()

	f = open(info.insn_stack_offset_map_tmp_file, "w")
	for addr in sorted(info.insn_stack_offset_map):
		f.write("*\n")
		f.write(hex(addr) + "\n")
		f.write(str(info.insn_stack_offset_map[addr]) + "\n")
	f.close()	

	f = open(info.deadcode_tmp_file, "w")
	for addr in sorted(info.deadcode):
		f.write("*\n")
		f.write(hex(addr) + "\n")
		if info.deadcode[addr] == True:
			f.write("1\n")
		elif info.deadcode[addr] == False:
			f.write("0\n")
	f.close()




def find_deadcode():
	return
	'''
	info.deadcode_tmp_file = info.binaryfile + "_deadcode_tmp_file"
	
	if os.path.exists(info.deadcode_tmp_file):
	
		info.deadcode = {}

		f = open(info.deadcode_tmp_file, "r")
		lines = f.readlines()

		key = None
		value = None
		index = 0
		line_num = 0


		for line in lines:
			#print(line)
			if "*" in line:
				if key:
					info.deadcode[key] = value
					key = None
					value = None
					index = 0
			else:
				if index == 0:
					key = int(line, 16)
				else:
					value = int(line, 10)
					if value == 1:
						value = True
					elif value == 0:
						value = False
				index = index + 1

			if line_num == len(lines) - 1:
				if key:
					info.deadcode[key] = value
					key = None
					value = None
					index = 0

			line_num = line_num + 1

		f.close()
		
		#for addr in sorted(info.deadcode):
		#	print("*")
		#	print(hex(addr))
		#	print(info.deadcode[addr])
		
		return
		
		
	
	start = time.time()
	for func_addr in sorted(info.func_addr_map):
		func_name = info.func_addr_map[func_addr][0]
		func_end_addr = info.func_addr_map[func_addr][1]
		#print("*")
		#print(func_name)
		#print(hex(func_addr))
		#print(hex(func_end_addr))
		
		if func_addr not in info.insnsmap:
			continue
		if func_addr not in info.cfg.kb.functions:
			continue
		if func_addr not in info.func_addr_map:
			continue
		#if func_addr != 0x8059400:
		#	continue
		#if func_addr != 0x807e0e0:
		#	continue
		
		#print("*")
		#print(func_name)
		#print(hex(func_addr))
		#print(hex(func_end_addr))
		
		deadcode = {}
		
		addr = func_addr
		while addr <= func_end_addr and addr != -1:
			deadcode[addr] = True
			addr = findnextinsaddr(addr)
			
		deadcode[func_addr] = False
		
		while True:
			old_deadcode = copy.deepcopy(deadcode)
			
			addr = func_addr
			while addr <= func_end_addr and addr != -1:
				#print("*")
				#print(hex(addr))
				# update which successor
				succs = []
				
				if addr not in info.bbendaddr_bbstartaddr_map:
					if findnextinsaddr(addr) != -1:
						nextaddr = findnextinsaddr(addr)
						if nextaddr >= func_addr and nextaddr <= func_end_addr:
							succs.append(nextaddr)
				else:
					if addr in info.insnsmap:
						insn = info.insnsmap[addr]
						if insn.mnemonic.startswith("call"):
							if findnextinsaddr(addr) != -1:
								nextaddr = findnextinsaddr(addr)
								if nextaddr >= func_addr and nextaddr <= func_end_addr:
									succs.append(nextaddr)
						else:
							if func_addr in info.cfg.kb.functions:
								if info.cfg.model.get_any_node(info.bbendaddr_bbstartaddr_map[addr]) != None:
									for succ in info.cfg.model.get_any_node(info.bbendaddr_bbstartaddr_map[addr]).successors:
										if succ.addr >= func_addr and succ.addr <= func_end_addr:
											succs.append(succ.addr)

				#print(hex(findnextinsaddr(addr)))
				#print("succs:")
				#for succ in succs:
				#	print(hex(succ))
				#print("*")
				
				# update each successor insn
				if deadcode[addr] != True:
					for succ in succs:
						deadcode[succ] = False
						#print("++")
						#print(info.insnsmap[addr].mnemonic)
						#print(deadcode[addr])
						#print(deadcode[succ])
						#print("++")						
								
				addr = findnextinsaddr(addr)
						
			changed = False
			addr = func_addr
			while addr <= func_end_addr and addr != -1:
				if deadcode[addr] != old_deadcode[addr]:
					changed = True
					break
				addr = findnextinsaddr(addr)
				
			if changed == False:
				break
		
		for addr in deadcode:
			info.deadcode[addr] = deadcode[addr]
	
	end = time.time()
	
	print(end - start)
	
	for addr in info.deadcode:
		print("*")
		print(hex(addr))
		print(info.deadcode[addr])

	f = open(info.deadcode_tmp_file, "w")
	for addr in sorted(info.deadcode):
		f.write("*\n")
		f.write(hex(addr) + "\n")
		if info.deadcode[addr] == True:
			f.write("1\n")
		elif info.deadcode[addr] == False:
			f.write("0\n")
	f.close()	
	'''
	
	

def find_functions():
	
	templist = []

	f1 = open(info.asmfile,'r')
	lines1 = f1.readlines()
	#print("find_functions() loop 1")
	for line1 in lines1:
		if "<" in line1 and ">:" in line1:
			func_name = line1[line1.index("<") + 1:line1.index(">")]
			#print(str(line1.index("<")))
			#print(str(line1.index(">")))
			#print(func_name)
			func_addr = int(line1[:line1.index("<")], 16)
			
			templist.append([func_addr, func_name])


	f1.close()

	count = len(templist)
	index = 1
	func_rets = []

	#print("find_functions() loop 2")
	for addr in info.insnaddrs:
		if index == count:
			break

		if addr >= templist[index][0]:
			func_end_addr = info.insnaddrs[info.insnaddrs.index(addr) - 1]
			info.func_list.append([templist[index - 1][0], templist[index - 1][1], func_end_addr])
			index = index + 1

	info.func_list.append([templist[count - 1][0], templist[count - 1][1], info.insnaddrs[-1]])

	# to handle name duplicates
	#func_name_set = set()
	#dup_name_set = set()
	#for f in info.func_list:
	#	if f[1] in func_name_set:
	#		dup_name_set.add(f[1])
	#	func_name_set.add(f[1])

	#print("find_functions() loop 3")
	for f in info.func_list:
		#if f[1] in dup_name_set:
		#	info.func_name_map[f[1] + "_FUNCADDR_" + hex(f[0])] = [f[0], f[2]]
		#else:
		#	info.func_name_map[f[1]] = [f[0], f[2]]
		info.func_name_map[f[1]] = [f[0], f[2]]
		info.func_addr_map[f[0]] = [f[1], f[2]]
		info.func_addrs.append(f[0])
	
		
	first_func_addr = info.func_addrs[0]
	last_func_addr = info.func_addrs[-1]
	
	#for addr in info.func_addrs:
	#	print(hex(addr))
	
	#print(hex(first_func_addr))
	#print(hex(last_func_addr))
	
	info.first_insn_addr = first_func_addr
	info.last_insn_addr = info.func_addr_map[last_func_addr][1]
	
	#print(hex(info.first_insn_addr))
	#print(hex(info.last_insn_addr))
	

	#print("find_functions() loop 4")
	func_addr = None
	for addr in info.insnaddrs:
		#print(hex(addr))
		if addr in info.func_addr_map:
			func_addr = addr
			info.func_rets_map[func_addr] = []
			info.func_callsites_map[func_addr] = []
		
		info.insn_func_map[addr] = func_addr
		
		if addr in info.ret_insn_addresses:
			info.func_rets_map[func_addr].append(addr)
		if addr in info.call_insn_addresses:
			info.func_callsites_map[func_addr].append(addr)
	
	#for addr in info.func_addr_map:
	#	print("*")
	#	print(hex(addr))
	#	print(info.func_addr_map[addr][0])
	#	print(hex(info.func_addr_map[addr][1]))
	
	#for f in info.func_list:
	#	print("*")
	#	print(f[1])
	#	print(hex(f[0]))
	#	print(hex(f[2]))

	#for name in info.func_name_map:
	#	print("*")
	#	print(name)
	#	print(hex(info.func_name_map[name][0]))
	#	print(hex(info.func_name_map[name][1]))
	
	#for addr in sorted(info.func_rets_map):
	#	print("*")
	#	print(hex(addr))
	#	for ret_addr in sorted(info.func_rets_map[addr]):
	#		print(hex(ret_addr))
	
	#for addr in sorted(info.insn_func_map):
	#	print("*")
	#	print(hex(addr))
	#	print(hex(info.insn_func_map[addr]))
	
	#for addr in info.func_callsites_map:
	#	print("*")
	#	print(hex(addr))
	#	for callsite in info.func_callsites_map[addr]:
	#		print(hex(callsite))
	
	print("Table 2 Column 3: # Func.: " + str(len(info.func_list)))


def findnextinsaddr(addr):
	if addr >= info.insnaddrs[-1] or addr < info.insnaddrs[0]:
		return -1
	try:
		return info.insnaddrs[info.insnaddrs.index(addr) + 1]
	except:
		return -1


def findpreviousinsaddr(addr):
	if addr > info.insnaddrs[-1] or addr <= info.insnaddrs[0]:
		return -1
	try:
		return info.insnaddrs[info.insnaddrs.index(addr) - 1]
	except:
		return -1

# convert variable dynamic address used by angr (for symbolic execution use)
# to static variable address (address defined in the binary) by just minus
# 0x400000 (for shared object)
def v_dyn_addr_to_static_addr(v_addr):
	if info.picflag == 1:
		return v_addr - 0x400000
	else:
		return v_addr


def static_addr_to_v_dyn_addr(s_addr):
	if info.picflag == 1:
		return s_addr + 0x400000
	else:
		return s_addr
		
# convert variable dynamic address used by angr (for symbolic execution use)
# to offset in the binary. if the variable address is not defined in the
# binary, return -1
def v_dyn_addr_to_binary_offset(v_addr):
	# convert v_addr to v_static_addr
	v_static_addr = v_dyn_addr_to_static_addr(v_addr)

	for sectioninfo in info.sectionsinfo:
		if sectioninfo[2] != 0:
			# find it.
			if v_static_addr >= sectioninfo[2] and v_static_addr <= sectioninfo[2] + sectioninfo[4] - 1:
				return v_static_addr - (sectioninfo[2] - sectioninfo[3])
	return -1


def capstone_parse():
	start = info.insnaddrs[0]
	while True:
		if start == info.insnaddrs[0]:
			addr = start
		else:
			while start <= info.insnaddrs[-1]:
				addr = findnextinsaddr(start)
				if addr >= info.insnaddrs[0] and addr <= info.insnaddrs[-1]:
					break
				else:
					start = start + 1

		if start < info.insnaddrs[0] or start > info.insnaddrs[-1]:
			break

		#print("capstone disassembly starts: " + hex(addr))
		with open(info.args.input, 'rb') as f:
			seekstart = v_dyn_addr_to_binary_offset(addr)

			f.seek(seekstart, 1)
			info.code = f.read()
			insns = info.project.arch.capstone.disasm(info.code, addr)
			insnlist = list(insns)

			# disassemble as many instructions as objdump
			templist = list(insnlist)
			for csinsn in templist:
				if csinsn.address > info.insnaddrs[-1]:
					insnlist.remove(csinsn)

			info.insns.extend(insnlist)
			for ins in insnlist:
				info.insnsmap[ins.address] = ins

		f.close()

		if insnlist:
			start = insnlist[-1].address
		else:
			start = addr
		#print("start: " + hex(start))

	all_insn_addrs = set(info.insnaddrs)
	all_capstone_insn_addrs = set()

	for csinsn in info.insns:
		all_capstone_insn_addrs.add(csinsn.address)
	#	print("*")
	#	print(hex(csinsn.address))
	#	print(csinsn.mnemonic)
	#	print(csinsn.op_str)
	#	print(csinsn.size)


	capstone_not_insn_addrs = all_insn_addrs - all_capstone_insn_addrs
	new_all_insn_addrs = all_capstone_insn_addrs.union(capstone_not_insn_addrs)

	#print("--------")
	#for addr in sorted(new_all_insn_addrs):
	#	print(hex(addr))
	#print("--------")

	add_insn_addrs = set()

	#for csinsn in info.insns:
		#if csinsn.id in [6,7,8,25,48,49,56,57,58,71,72,73,74,77,79,80,81,82, \
		#	85,87,88,90,91,92,94,100,128,129,147,322,323,332,333,334,335,336,338, \
		#	347,449,470,471,476,477,481,566,567,568,588,589,590,621,675,676, \
		#	678,1301,1309]:

		#if csinsn.id in [6,7,8,25,48,49,56,57,58,71,72,73,74,77,79,80,81,82, \
		#	85,87,88,90,91,92,94,100,128,129,147,322,323,332,333,334, \
		#	449,477,481,566,588,621]:

	#	if csinsn.id in [6,7,8,25,48,49,56,71,72,73,74,77,79,80,81,82, \
        #                85,87,88,90,91,92,94,147,322,323,332,333,334, \
        #                449,477,481,566,588,621]:
	#		print(hex(csinsn.address))
		


	'''	
	case X86_INS_ADC:
	case X86_INS_ADD:
	case X86_INS_AND:
	case X86_INS_OR:
	case X86_INS_XOR:
	case X86_INS_SBB:
	case X86_INS_SUB:

	case X86_INS_BSF:
	case X86_INS_BSR:
	case X86_INS_MOV:

	case X86_INS_CMOVA:
	case X86_INS_CMOVAE:
	case X86_INS_CMOVB:
	case X86_INS_CMOVBE:
	case X86_INS_CMOVE:
	case X86_INS_CMOVG:
	case X86_INS_CMOVGE:
	case X86_INS_CMOVL:
	case X86_INS_CMOVLE:
	case X86_INS_CMOVNE:
	case X86_INS_CMOVNO:
	case X86_INS_CMOVNP:
	case X86_INS_CMOVNS:
	case X86_INS_CMOVO:
	case X86_INS_CMOVP:
	case X86_INS_CMOVS:

	case X86_INS_CBW:

	case X86_INS_CWD:

	case X86_INS_CWDE:

	case X86_INS_CDQ:

	case X86_INS_MOVSX:

	case X86_INS_MOVZX:

	case X86_INS_CMPXCHG:

	case X86_INS_XCHG:

	case X86_INS_XADD:

	case X86_INS_XLATB:
	case X86_INS_LODSB:

	case X86_INS_LODSW:

	case X86_INS_LODSD:

	case X86_INS_STOSB:

	case X86_INS_STOSW:

	case X86_INS_STOSD:

	case X86_INS_MOVSD:

	case X86_INS_MOVSW:

	case X86_INS_MOVSB:

	case X86_INS_POP:

	case X86_INS_PUSH:

	case X86_INS_POPAW:

	case X86_INS_POPAL:

	case X86_INS_PUSHAW:

	case X86_INS_PUSHAL:

	case X86_INS_CALL:

	case X86_INS_RET:

	case X86_INS_LEAVE:

	case X86_INS_LEA:


	'''





def find_ins_addr():
	#sset = set()
	func_addr = -1
	f1 = open(info.asmfile,'r')
	lines1 = f1.readlines()
	for line1 in lines1:
		if len(line1.strip().split()) != 0:
			l1 = line1.strip().split()[0]
			
			if "<" in line1 and ">:" in line1:
				func_addr = int(line1[:line1.index("<")], 16)
				#print(hex(func_addr))
			
			if ":" in l1 and len(l1) >= 2:
				#print(l1)
				addr = -1
				ll1 = l1[:-1]
				try:
					addr = int(ll1, 16)
				except:
					continue
					
				#print("*")
				#print(hex(addr))
				info.insnaddrs.append(addr)
				info.insnlinesmap[addr] = line1
				s = line1.strip().split("\t")
				#print(s)
				if len(s) >= 3:
					info.insnstringsmap[addr] = s[-1]
					#print(s[-1])
				else:
					info.insnstringsmap[addr] = ""
					#print(s)
					#print(hex(addr))
					continue
				#print(line1)
				#print("*")
				#print(hex(addr))
				#print(info.insnstringsmap[addr])
				s = info.insnstringsmap[addr].strip().split()[0]
				#print(s)
				#if s.startswith("j"):
				#	sset.add(s)
				if info.insnstringsmap[addr].startswith("ret") or info.insnstringsmap[addr].startswith("repz ret"):
					info.ret_insn_addresses.append(addr)
					if func_addr not in info.func_ret_insn_addresses_map:
						info.func_ret_insn_addresses_map[func_addr] = []
					info.func_ret_insn_addresses_map[func_addr].append(addr)
				if info.insnstringsmap[addr].startswith("jmp"):
					info.jmp_insn_addresses.append(addr)
					if func_addr not in info.func_jmp_insn_addresses_map:
						info.func_jmp_insn_addresses_map[func_addr] = []
					info.func_jmp_insn_addresses_map[func_addr].append(addr)
				if info.insnstringsmap[addr].startswith("call"):
					info.call_insn_addresses.append(addr)
					if func_addr not in info.func_call_insn_addresses_map:
						info.func_call_insn_addresses_map[func_addr] = []
					info.func_call_insn_addresses_map[func_addr].append(addr)
					s1 = info.insnstringsmap[addr].strip().split()[1]
					#print(s)
					target_addr = -1
					try:
						target_addr = int(s1, 16)
						#print(hex(target_addr))
					except:
						#print(s1)
						continue
					#print(hex(target_addr))
					info.callsite_explicit_call_targets_map[addr] = target_addr
					
				if s in info.cond_uncond_jump_insn_oprands:
					info.cond_uncond_jump_insn_addresses.append(addr)
					if func_addr not in info.func_cond_uncond_jump_insn_addresses_map:
						info.func_cond_uncond_jump_insn_addresses_map[func_addr] = []
					info.func_cond_uncond_jump_insn_addresses_map[func_addr].append(addr)
					if s in info.uncond_jump_insn_oprands:
						info.uncond_jump_insn_addresses.append(addr)
						if func_addr not in info.func_uncond_jump_insn_addresses_map:
							info.func_uncond_jump_insn_addresses_map[func_addr] = []
						info.func_uncond_jump_insn_addresses_map[func_addr].append(addr)
					if s in info.cond_jump_insn_oprands:
						info.cond_jump_insn_addresses.append(addr)
						if func_addr not in info.func_cond_jump_insn_addresses_map:
							info.func_cond_jump_insn_addresses_map[func_addr] = []
						info.func_cond_jump_insn_addresses_map[func_addr].append(addr)
						
					s1 = info.insnstringsmap[addr].strip().split()[1]
					#print(s)
					target_addr = -1
					try:
						target_addr = int(s1, 16)
						#print(hex(target_addr))
					except:
						#print(s1)
						continue
					#print(hex(target_addr))
					if func_addr not in info.func_explicit_non_fall_through_control_flow_targets_map:
						info.func_explicit_non_fall_through_control_flow_targets_map[func_addr] = set()
					info.func_explicit_non_fall_through_control_flow_targets_map[func_addr] = \
						info.func_explicit_non_fall_through_control_flow_targets_map[func_addr].union(set([target_addr]))
						
	f1.close()

	#for s in sset:
	#	print(s)

	#print("--------")
	#for ad in info.insnaddrs:
	#	print(hex(ad))
	#print("--------")


	#for addr in sorted(info.insnlinesmap):
	#	print("*")
	#	print(hex(addr))
	#	print(info.insnlinesmap[addr])
	
	#for addr in sorted(info.ret_insn_addresses):
	#	print(hex(addr))

	#for addr in sorted(info.jmp_insn_addresses):
	#	print(hex(addr))
		
	#for addr in sorted(info.call_insn_addresses):
	#	print(hex(addr))
	
	#for addr in sorted(info.cond_uncond_jump_insn_addresses):
	#	print(hex(addr))
	
	#for func_addr in sorted(info.func_cond_uncond_jump_insn_addresses_map):
	#	print("*")
	#	print(hex(func_addr))
	#	for addr in info.func_cond_uncond_jump_insn_addresses_map[func_addr]:
	#		print(hex(addr))
	
	#for func_addr in sorted(info.func_explicit_non_fall_through_control_flow_targets_map):
	#	print("*")
	#	print(hex(func_addr))
	#	for target in sorted(info.func_explicit_non_fall_through_control_flow_targets_map[func_addr]):
	#		print(hex(target))
	
	#for callsite in info.callsite_explicit_call_targets_map:
	#	print("*")
	#	print(hex(callsite))
	#	print(hex(info.callsite_explicit_call_targets_map[callsite]))
	
	print("Table 2 Column 4: # Inst.: " + str(len(info.insnaddrs)))


def readelf_sections_info():
	f1 = open(info.readelffile,'r')
	lines1 = f1.readlines()
	for line1 in lines1:
		if "[" in line1 and "]" in line1:
			#print(line1[line1.index("[") + 1:line1.index("]")])
			s = line1[line1.index("[") + 1:line1.index("]")].strip()
			#print(s)
			if s.isnumeric():
				#print(s)
				#print(str(int(s, 10)))
				#print(line1)
				restline1 = line1[line1.index("]") + 1:].strip().split()
				#print(restline1)

				if int(s, 10) != 0:
					#print(line1)
					#print(restline1[0])
					#print(restline1[3])
					#print(nextline1split[0])

					info.sectionsinfo.append([restline1[0], restline1[1], int(restline1[2], 16), int(restline1[3], 16), int(restline1[4], 16)])
					info.sectionsinfo_name_map[restline1[0]] = [restline1[0], restline1[1], int(restline1[2], 16), int(restline1[3], 16), int(restline1[4], 16)]
	f1.close()

	info.mmin_data_section_addr = 0xffffffffffffffff
	info.mmax_data_section_addr = -0x1

	for sectioninfo_name in sorted(info.sectionsinfo_name_map):
	#	print("*")
	#	print(info.sectionsinfo_name_map[sectioninfo_name][0])
	#	print(info.sectionsinfo_name_map[sectioninfo_name][1])
	#	print(hex(info.sectionsinfo_name_map[sectioninfo_name][2]))
	#	print(hex(info.sectionsinfo_name_map[sectioninfo_name][3]))
	#	print(hex(info.sectionsinfo_name_map[sectioninfo_name][4]))
		if info.sectionsinfo_name_map[sectioninfo_name][0] in info.data_section_names:
			start = info.sectionsinfo_name_map[sectioninfo_name][2]
			end = info.sectionsinfo_name_map[sectioninfo_name][2] + info.sectionsinfo_name_map[sectioninfo_name][4] - 0x1
			#print("*")
			#print(hex(start))
			#print(hex(end))
			if start < info.mmin_data_section_addr:
				info.mmin_data_section_addr = start
			if end > info.mmax_data_section_addr:
				info.mmax_data_section_addr = end
				
				
	#print(hex(info.mmin_data_section_addr))
	#print(hex(info.mmax_data_section_addr))



#
# the objdump generated diassembly file is named with original_file_name_asm in the same directory
# the hexdump generated file and readelf generated section info are also in the same directory
#
def disassemble():
	info.binaryfile = os.path.realpath(info.args.input)

	# generate objdump file
	info.asmfile = info.binaryfile + "_asm"
	#print(info.asmfile)
	tmpfile = "/tmp/" + os.path.basename(info.asmfile)
	#print(tmpfile)
	comm = "objdump -d " + info.binaryfile + " > " + tmpfile
	os.system(comm)
	if os.path.exists(tmpfile):
		if (os.path.exists(info.asmfile) and not filecmp.cmp(tmpfile, info.asmfile)) or not os.path.exists(info.asmfile):
			comm = "objdump -d " + info.binaryfile + " > " + info.asmfile
			os.system(comm)

	# generate hexdump file
	info.hexdumpfile = info.binaryfile + "_hexdump"
	#print(info.hexdumpfile)
	tmpfile = "/tmp/" + os.path.basename(info.hexdumpfile)
	#print(tmpfile)
	comm = "hexdump -C " + info.binaryfile + " > " + tmpfile
	os.system(comm)
	if os.path.exists(tmpfile):
		if (os.path.exists(info.hexdumpfile) and not filecmp.cmp(tmpfile, info.hexdumpfile)) or not os.path.exists(info.hexdumpfile):
			comm = "hexdump -C " + info.binaryfile + " > " + info.hexdumpfile
			os.system(comm)

	# generate readelf section info file
	info.readelffile = info.binaryfile + "_readelf"
	#print(info.readelffile)
	tmpfile = "/tmp/" + os.path.basename(info.readelffile)
	#print(tmpfile)
	comm = "readelf -S " + info.binaryfile + " > " + tmpfile
	os.system(comm)
	if os.path.exists(tmpfile):
		if (os.path.exists(info.readelffile) and not filecmp.cmp(tmpfile, info.readelffile)) or not os.path.exists(info.readelffile):
			comm = "readelf -S " + info.binaryfile + " > " + info.readelffile
			os.system(comm)



def reset_update_CFG_typed():
	
	# initialize
	for func_addr in sorted(info.func_addr_map):
		func_name = info.func_addr_map[func_addr][0]
		func_end_addr = info.func_addr_map[func_addr][1]
		#print("generate_func_prototype")
		#print("*")
		#print(func_name)
		#print(hex(func_addr))
		##print(hex(func_end_addr))
		
		if func_addr not in info.insnsmap:
			continue
		if func_addr not in info.cfg.kb.functions:
			continue
		if func_addr not in info.func_addr_map:
			continue
		
		func_para_count = info.funcaddr_para_access_map[func_addr]
		info.funcaddr_para_details_map[func_addr] = []
		for i in range(func_para_count):
			info.funcaddr_para_details_map[func_addr].append(0)
		
		addr = func_addr
		while addr <= func_end_addr and addr != -1:
			if addr in info.callsite_para_access_map:
				info.callsite_para_details_map[addr] = []
				callsite_para_count = info.callsite_para_access_map[addr]
				for i in range(callsite_para_count):
					info.callsite_para_details_map[addr].append(0)
				#print("*")
				#print(hex(addr))
				#print(info.callsite_para_details_map[addr])
			addr = findnextinsaddr(addr)
		
		
	#print("first pass")
	# first pass	
	for func_addr in sorted(info.func_addr_map):
		func_name = info.func_addr_map[func_addr][0]
		func_end_addr = info.func_addr_map[func_addr][1]
		#print("generate_func_prototype")
		#print("*")
		#print(func_name)
		#print(hex(func_addr))
		##print(hex(func_end_addr))
		
		if func_addr not in info.insnsmap:
			continue
		if func_addr not in info.cfg.kb.functions:
			continue
		if func_addr not in info.func_addr_map:
			continue
			
		func_para_count = info.funcaddr_para_access_map[func_addr]
			
		# generate typed function prototype
		addr = func_addr
		while addr <= func_end_addr and addr != -1:
			#print("*")
			#print(hex(addr))
			
			if addr in info.insnstringsmap and addr in info.insnsmap and  "(" in info.insnstringsmap[addr] and not info.insnstringsmap[addr].startswith("lea"):
				insn = info.insnsmap[addr]
				for op in insn.operands:
					if op.type == X86_OP_MEM:
						if (op.value.mem.disp < info.mmin_data_section_addr or op.value.mem.disp > info.mmax_data_section_addr) \
							and op.value.mem.base != 0 and insn.reg_name(op.value.mem.base) != "esp" \
							and insn.reg_name(op.value.mem.base) in info.gpr:
							base_reg_name = insn.reg_name(op.value.mem.base)
							if addr in info.insn_summary_map and base_reg_name in info.insn_summary_map[addr]:
								for value in info.insn_summary_map[addr][base_reg_name]:
									if value in [0x4, 0x8, 0xc, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x28] and value <= 4 * func_para_count:
										para_index = int(value / 4 - 1)
										#print("*")
										#print(value)
										#print(func_para_count)
										#print(para_index)
										#print(len(info.funcaddr_para_details_map[func_addr]))
										#print(info.funcaddr_para_details_map[func_addr])
										#print(info.funcaddr_para_details_map[func_addr][para_index])
										info.funcaddr_para_details_map[func_addr][para_index] = 1
										#print("*1")
										#print(hex(addr))
										#print(info.funcaddr_para_details_map[func_addr])
										
									# generate typed callsite signature
									elif isinstance(value, str) and value.startswith("CALLSITE_P"):
										callsite_addr = int(value[value.index("0x"):], 16)
										para_index = int(value[10:value.index("_0x")], 10) - 1
										#print("*")
										#print(value)
										#print(para_index)
										#print(info.callsite_para_details_map[callsite_addr])
										info.callsite_para_details_map[callsite_addr][para_index] = 1
										#print("*1")
										#print(hex(addr))
										#print(value)
										#print(hex(callsite_addr))
										#print(info.callsite_para_details_map[callsite_addr])
						elif (op.value.mem.disp < info.mmin_data_section_addr or op.value.mem.disp > info.mmax_data_section_addr) \
							and op.value.mem.base == 0 and op.value.mem.index != 0 and insn.reg_name(op.value.mem.index) != "esp" \
							and insn.reg_name(op.value.mem.index) in info.gpr:
							index_reg_name = insn.reg_name(op.value.mem.index)
							if addr in info.insn_summary_map and index_reg_name in info.insn_summary_map[addr]:
								for value in info.insn_summary_map[addr][index_reg_name]:
									if value in [0x4, 0x8, 0xc, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x28] and value <= 4 * func_para_count:
										para_index = int(value / 4 - 1)
										info.funcaddr_para_details_map[func_addr][para_index] = 1
										#print("*2")
										#print(hex(addr))
										#print(info.funcaddr_para_details_map[func_addr])
									
									# generate typed callsite signature
									elif isinstance(value, str) and value.startswith("CALLSITE_P"):
										callsite_addr = int(value[value.index("0x"):], 16)
										para_index = int(value[10:value.index("_0x")], 10) - 1
										info.callsite_para_details_map[callsite_addr][para_index] = 1
										#print("*2")
										#print(hex(addr))
										#print(value)
										#print(hex(callsite_addr))
										#print(info.callsite_para_details_map[callsite_addr])
										
			# generate typed callsite signature
			if addr in info.call_insn_addresses and addr in info.insn_stack_offset_map and addr in info.callsite_para_access_map and addr in info.callsite_para_details_map \
				and addr in info.bbendaddr_bbstartaddr_map:
				callsite_para_count = info.callsite_para_access_map[addr]
				#current_esp_value = info.insn_stack_offset_map[addr]
				#print("*")
				#print(hex(addr))
				#print(hex(current_esp_value))
				##para_esp_values = []
				##for i in range(callsite_para_count):
				##	para_esp_values.append(i * 4 + current_esp_value)
				##print(para_esp_values)
				para_strs = []
				for i in range(callsite_para_count):
					#para_esp_value = i * 4 + current_esp_value
					#if addr in info.insn_summary_map and para_esp_value in info.insn_summary_map[addr]:
					#	for value in info.insn_summary_map[addr][para_esp_value]:
					#		#print("*")
					#		#print(hex(addr))
					#		##print(hex(current_esp_value))
					#		#print(i)
					#		#print(value)
					#		if isinstance(value, int) and ((value >= info.first_insn_addr and value <= info.last_insn_addr) \
					#			or (value >= info.mmin_data_section_addr and value <= info.mmax_data_section_addr)):
					#			info.callsite_para_details_map[addr][i] = 1
					#			#print("*")
					#			#print(hex(addr))
					#			#print(hex(current_esp_value))
					#			#print(i)
					#			#print(info.callsite_para_details_map[addr])
					#			break
					para_strs.append(hex(i * 4) + "(%esp)")
				bbstartaddr = info.bbendaddr_bbstartaddr_map[addr]
				addr1 = bbstartaddr
				while addr1 < addr and addr1 != -1:
					if addr1 in info.insnstringsmap:
						insnstring1 = info.insnstringsmap[addr1]
						for para_str in para_strs:
							if para_str in insnstring1 and "mov" in insnstring1 and "$0x" in insnstring1 and "," in insnstring1:
								src_value = int(insnstring1[insnstring1.index("$0x") + 3: insnstring1.index(",")], 16)
								if (src_value >= info.first_insn_addr and src_value <= info.last_insn_addr) \
									or (src_value >= info.mmin_data_section_addr and src_value <= info.mmax_data_section_addr):
									para_index = int(int(para_str[:para_str.index("(")], 16) / 4)
									info.callsite_para_details_map[addr][para_index] = 1
									#print("*")
									#print(hex(addr))
									#print(hex(addr1))
									#print(para_index)
									#print(info.callsite_para_details_map[addr])
							elif ",(%esp)" in insnstring1 and "mov" in insnstring1 and "$0x" in insnstring1 and "," in insnstring1:
								src_value = int(insnstring1[insnstring1.index("$0x") + 3: insnstring1.index(",")], 16)
								if (src_value >= info.first_insn_addr and src_value <= info.last_insn_addr) \
									or (src_value >= info.mmin_data_section_addr and src_value <= info.mmax_data_section_addr):
									info.callsite_para_details_map[addr][0] = 1
									#print("*")
									#print(hex(addr))
									#print(hex(addr1))
									#print(0)
									#print(info.callsite_para_details_map[addr])
								
					addr1 = findnextinsaddr(addr1)
			
			addr = findnextinsaddr(addr)
	
	#print("second pass")
	# second pass, update typed function prototype with type callsite signature
	for callsite in sorted(info.callsite_para_details_map):
		if callsite in info.callsite_explicit_call_targets_map:
			#print("*")
			#print(hex(callsite))
			#print(hex(info.callsite_explicit_call_targets_map[callsite]))
			callsite_target = info.callsite_explicit_call_targets_map[callsite]
			if callsite_target in info.funcaddr_para_details_map and callsite_target in info.funcaddr_para_access_map:
				#print("*")
				#print(hex(callsite))
				for para_index in range(info.callsite_para_access_map[callsite]):
					#print("*")
					#print(hex(callsite))
					#print(info.callsite_para_access_map[callsite])
					#print(info.callsite_para_details_map[callsite])
					#print(hex(callsite_target))
					#print(info.funcaddr_para_access_map[callsite_target])
					#print(info.funcaddr_para_details_map[callsite_target])
					if para_index < info.funcaddr_para_access_map[callsite_target]:
						#print("*")
						#print(info.funcaddr_para_details_map[callsite_target][para_index])
						#print(info.callsite_para_details_map[callsite][para_index])
						
						#old = info.funcaddr_para_details_map[callsite_target][para_index]
						info.funcaddr_para_details_map[callsite_target][para_index] |= info.callsite_para_details_map[callsite][para_index]
						#if info.funcaddr_para_details_map[callsite_target][para_index] != old:
						#	print("*")
						#	print(hex(callsite))
						#	print(hex(callsite_target))
						#	print(old)
						#	print(info.funcaddr_para_details_map[callsite_target][para_index])
						#	print(info.funcaddr_para_details_map[callsite_target])

	#print("third pass")
	# third pass, update jmp targets using func prototype
	for func_addr in sorted(info.func_addr_map):
		func_name = info.func_addr_map[func_addr][0]
		func_end_addr = info.func_addr_map[func_addr][1]
		#print("generate_func_prototype")
		#print("*")
		#print(func_name)
		#print(hex(func_addr))
		##print(hex(func_end_addr))
		
		if func_addr not in info.insnsmap:
			continue
		if func_addr not in info.cfg.kb.functions:
			continue
		if func_addr not in info.func_addr_map:
			continue
			
		func_para_count = info.funcaddr_para_access_map[func_addr]
			
		addr = func_addr
		while addr <= func_end_addr and addr != -1:
			#print("*")
			#print(hex(addr))
			
			if addr in info.jmp_insn_addresses \
				and addr in info.callsite_para_access_map and addr in info.callsite_para_details_map \
				and func_addr in info.funcaddr_para_access_map and func_addr in info.funcaddr_para_details_map:
				#print("*")
				#print(hex(addr))
				for para_index in range(func_para_count):
					if para_index < info.callsite_para_access_map[addr]:
						#print("*")
						info.callsite_para_details_map[addr][para_index] |= info.funcaddr_para_details_map[func_addr][para_index]
			addr = findnextinsaddr(addr)

	#print("reset CFG")
	# reset CFG
	info.cfg = info.project.analyses.CFGFast()

	#print("update CFG")
	# update CFG
	#index = 0
	#print(len(info.callsite_para_access_map))
	max_total = 250000
	if len(info.callsite_para_access_map) > 50000:
		max_total = 10000
	total_index = 0
	for callsite_insn_addr in sorted(info.callsite_para_access_map):
		#print("*")
		#print("add edge")
		##print(str(index))
		#print("callsite_insn_addr")
		#print(hex(callsite_insn_addr))
		index = 0
		#print(str(total_index))
		if total_index > max_total:
			break
		# first connect newly resolved jmp insn to its targets
		if callsite_insn_addr in info.jmp_insn_addresses:
			if callsite_insn_addr in info.bbendaddr_bbstartaddr_map:
				jmp_insn_bb_addr = info.bbendaddr_bbstartaddr_map[callsite_insn_addr]
				from_bb = info.cfg.model.get_any_node(jmp_insn_bb_addr)
				old_to_bbs = []
				if from_bb != None:
					old_to_bbs = from_bb.successors
				# remove edge if the target is fake
				for old_to_bb in old_to_bbs:
					if old_to_bb.name == "UnresolvableJumpTarget":
						info.cfg.graph.remove_edge(from_bb, old_to_bb)
						#print("*")
						#print(hex(from_bb.addr))
						#print(hex(old_to_bb.addr))
				# add edge
				for func_addr in sorted(info.funcaddr_para_access_map):
					if info.funcaddr_para_details_map[func_addr] == info.callsite_para_details_map[callsite_insn_addr]:
						index = index + 1
						total_index = total_index + 1
						if index > 500:
							break
						if total_index > max_total:
							break
						to_bb = info.cfg.model.get_any_node(func_addr)
						data = {}
						data["jumpkind"] = "Ijk_Boring"
						info.cfg.graph.add_edge(from_bb, to_bb, **data)
						#print("*")
						#print(hex(from_bb.addr))
						#print(hex(to_bb.addr))
						
		# connect newly resolved call insn to its targets
		if callsite_insn_addr in info.call_insn_addresses:
			#print(hex(callsite_insn_addr))
			if callsite_insn_addr in info.bbendaddr_bbstartaddr_map:
				call_insn_bb_addr = info.bbendaddr_bbstartaddr_map[callsite_insn_addr]
				from_bb = info.cfg.model.get_any_node(call_insn_bb_addr)
				old_to_bbs = []
				if from_bb != None:
					old_to_bbs = from_bb.successors
				unsolved = False
				# remove edge if the target is fake
				for old_to_bb in old_to_bbs:
					if old_to_bb.name == "UnresolvableCallTarget":
						info.cfg.graph.remove_edge(from_bb, old_to_bb)
						#print("*")
						#print(hex(from_bb.addr))
						#print(hex(old_to_bb.addr))
						unsolved = True
				if unsolved == True:
					# add edge
					for func_addr in sorted(info.funcaddr_para_access_map):
						if info.funcaddr_para_details_map[func_addr] == info.callsite_para_details_map[callsite_insn_addr]:
						#if info.funcaddr_para_access_map[func_addr] == info.callsite_para_access_map[callsite_insn_addr]:
							index = index + 1
							total_index = total_index + 1
							if index > 500:
								break
							if total_index > max_total:
								break
							#print("*")
							#print(hex(callsite_insn_addr))
							#print(hex(func_addr))
							#print(info.callsite_para_details_map[callsite_insn_addr])
							#print(info.funcaddr_para_details_map[func_addr])
							to_bb = info.cfg.model.get_any_node(func_addr)
							data = {}
							data["jumpkind"] = "Ijk_Call"
							info.cfg.graph.add_edge(from_bb, to_bb, **data)
							#print("*")
							#print(hex(from_bb.addr))
							#print(hex(to_bb.addr))
							
							for ret_insn_addr in info.func_rets_map[func_addr]:
								index = index + 1
								total_index = total_index + 1
								if index > 500:
									break
								if total_index > max_total:
									break
								ret_insn_bb_addr = info.bbendaddr_bbstartaddr_map[ret_insn_addr]
								ret_bb = info.cfg.model.get_any_node(ret_insn_bb_addr)
								data = {}
								data["jumpkind"] = "Ijk_Ret"
								info.cfg.graph.add_edge(ret_bb, from_bb, **data)
								#print("*")
								#print(hex(ret_bb.addr))
								#print(hex(from_bb.addr))
	
	info.concise_callgraph = nx.DiGraph()
	info.concise_callgraph_acyclic = nx.DiGraph()
	info.ordered_func_addresses = []
			
	# on the updated CFG, generate our concise callgraph
	#print("generate callgraph")
	for func_addr in sorted(info.func_addr_map):
		info.concise_callgraph.add_node(func_addr)
		info.concise_callgraph_acyclic.add_node(func_addr)
	
	for callsite_insn_addr in info.call_insn_addresses:
		#print(hex(callsite_insn_addr))
		if callsite_insn_addr in info.bbendaddr_bbstartaddr_map:
			#print("*")
			#print(hex(callsite_insn_addr))
			info.callsite_map[callsite_insn_addr] = set()
			call_insn_bb_addr = info.bbendaddr_bbstartaddr_map[callsite_insn_addr]
			from_bb = info.cfg.model.get_any_node(call_insn_bb_addr)
			to_bbs = []
			if from_bb != None:
				to_bbs = from_bb.successors
			for to_bb in to_bbs:
				#print("*")
				#print(hex(callsite_insn_addr))
				#print(hex(to_bb.addr))
				if callsite_insn_addr in info.insn_func_map:
					caller_func_addr = info.insn_func_map[callsite_insn_addr]
					callee_func_addr = to_bb.addr
					if to_bb.addr in info.func_addr_map:
						info.concise_callgraph.add_edge(caller_func_addr, callee_func_addr)
						info.concise_callgraph_acyclic.add_edge(caller_func_addr, callee_func_addr)
						info.callsite_map[callsite_insn_addr].add(callee_func_addr)
						
	# prune to be acyclic for sorting orders
	#print(list(nx.simple_cycles(info.concise_callgraph)))


	#pruned = []

	#print(len(info.concise_callgraph_acyclic.edges()))
	
	#index = 1
	
	try:
		#while_true_start = time.time()
		while True:
			edge = list(nx.find_cycle(info.concise_callgraph_acyclic, orientation='original'))[-1]
			#print("*")
			#print("remove edge")
			##print(str(index))
			##print(list(nx.find_cycle(info.concise_callgraph_acyclic, orientation='original')))
			#print(edge)
			info.concise_callgraph_acyclic.remove_edge(edge[0], edge[1])
			#print(info.concise_callgraph_acyclic.has_edge(edge[0], edge[1]))
			#pruned.append(edge[0], edge[1])
			#list(nx.find_cycle(info.concise_callgraph, orientation='original'))[-1]
			#print("*")
			#print(list(nx.find_cycle(info.concise_callgraph, orientation='original')))
			#print(list(nx.find_cycle(info.concise_callgraph, orientation='original'))[-1])
			#print(hex(edge[0]))
			#print(hex(edge[1]))
			#index = index + 1
			
			
			# if time-out, also break
			#while_true_end = time.time()
			#while_true_time = while_true_end - while_true_start
			#if while_true_time > 300:
			#	break
			
	except:
		pass

	#for p in pruned:
	#	print("*")
	#	print(hex(p[0]))
	#	print(hex(p[1]))
	
	#print(len(info.concise_callgraph_acyclic.edges()))

	#print("topological sort")
	#print(len(info.func_addr_map))
	#print(len(info.concise_callgraph_acyclic.nodes()))
	#print(len(list(reversed(list(nx.topological_sort(info.concise_callgraph_acyclic))))))
	info.ordered_func_addresses = list(reversed(list(nx.topological_sort(info.concise_callgraph_acyclic))))

	#print("*")
	#for ordered_func_addr in info.ordered_func_addresses:
	#	print(hex(ordered_func_addr))
	

	#for callsite in sorted(info.callsite_map):
	#	print("*")
	#	print(hex(callsite))
	#	for callee in sorted(info.callsite_map[callsite]):
	#		print(hex(callee))
	
	#print("update_CFG finishes")



def reset_CFG():
	pass
	'''
	info.cfg = info.project.analyses.CFGFast()
	
	if not os.path.exists("./tmp_dir"):
		os.system("mkdir tmp_dir")
	
	if os.path.exists(info.func_summary_map_tmp_file) \
		and os.path.exists(info.insn_summary_map_tmp_file) \
		and os.path.exists(info.tainted_insn_output_file):
		
		command1 = "mv " + info.func_summary_map_tmp_file + " ./tmp_dir"
		command2 = "mv " + info.insn_summary_map_tmp_file + " ./tmp_dir"
		command3 = "mv " + info.tainted_insn_output_file + " ./tmp_dir"
		
		os.system(command1)
		os.system(command2)
		os.system(command3)
	'''



def build_CFG():
	
	info.cfg = info.project.analyses.CFGFast()
	#embed()
	for f in info.cfg.kb.functions:
		#print(dir(f))
		if f <= info.func_list[-1][-1]:
			unsolved_addr = 1
			'''
			for b in info.cfg.kb.functions[f].blocks:
				info.bbendaddr_bbstartaddr_map[b.instruction_addrs[-1]] = b.instruction_addrs[0]
				info.bbstartaddr_bbendaddr_map[b.instruction_addrs[0]] = b.instruction_addrs[-1]
				if b.instruction_addrs[-1] not in info.insnaddrs:
					#print(hex(b.instruction_addrs[-1]))
					unsolved_addr = b.instruction_addrs[-1]
					break
				if b.instruction_addrs[0] not in info.insnaddrs:
					#print(hex(b.instruction_addrs[0]))
					unsolved_addr = b.instruction_addrs[0]
					break
			'''
			# if angr fails to identify basic block of this function, we do it ourselves
			if unsolved_addr != -1 and f in info.func_addr_map:
				#print("*")
				#print(hex(f))
				
				func_addr = f
				func_end_addr = info.func_addr_map[f][1]
				
				control_flow_transfer_insns = []
				if f in info.func_cond_uncond_jump_insn_addresses_map:
					control_flow_transfer_insns.extend(info.func_cond_uncond_jump_insn_addresses_map[f])
				if f in info.func_ret_insn_addresses_map:
					control_flow_transfer_insns.extend(info.func_ret_insn_addresses_map[f])
				if f in info.func_call_insn_addresses_map:
					#for control_flow_transfer_insn in control_flow_transfer_insns:
					#	print(hex(control_flow_transfer_insn))
					#print("+")
					control_flow_transfer_insns.extend(info.func_call_insn_addresses_map[f])
					#for control_flow_transfer_insn in control_flow_transfer_insns:
					#	print(hex(control_flow_transfer_insn))
				
				#for func_call_insn_addr in info.func_call_insn_addresses_map[f]:
				#	print(hex(func_call_insn_addr))
					
				#for control_flow_transfer_insn in control_flow_transfer_insns:
				#	print(hex(control_flow_transfer_insn))
				
				explicit_non_fall_through_control_flow_targets = []
				if f in info.func_explicit_non_fall_through_control_flow_targets_map:
					explicit_non_fall_through_control_flow_targets = sorted(info.func_explicit_non_fall_through_control_flow_targets_map[f])
				explicit_local_non_fall_through_control_flow_targets = []
				
				for explicit_non_fall_through_control_flow_target in explicit_non_fall_through_control_flow_targets:
					if explicit_non_fall_through_control_flow_target >= func_addr and explicit_non_fall_through_control_flow_target <= func_end_addr:
						explicit_local_non_fall_through_control_flow_targets.append(explicit_non_fall_through_control_flow_target)
						#print(hex(explicit_non_fall_through_control_flow_target))
				
				bb_start_addresses_set = set()
				bb_start_addresses_set.add(func_addr)
				bb_start_addresses_set = bb_start_addresses_set.union(set(explicit_local_non_fall_through_control_flow_targets))
				
				for control_flow_transfer_insn in control_flow_transfer_insns:
					#print("*")
					#print(hex(control_flow_transfer_insn))
					after_addr = findnextinsaddr(control_flow_transfer_insn)
					while after_addr <= func_end_addr and after_addr != -1:
						#print(hex(after_addr))
						if after_addr in info.insnsmap:
							bb_start_addresses_set.add(after_addr)
							break
						after_addr = findnextinsaddr(after_addr)
						
				bb_start_addresses = sorted(bb_start_addresses_set)
							
				for bb_start_address in bb_start_addresses:
					#print(hex(bb_start_address))
					current_index = bb_start_addresses.index(bb_start_address)
					if current_index != 0:
						before_addr = findpreviousinsaddr(bb_start_address)
						while before_addr >= bb_start_addresses[current_index - 1] and before_addr != -1:
							if before_addr == bb_start_addresses[current_index - 1] or before_addr in info.insnsmap:
								info.bbstartaddr_bbendaddr_map[bb_start_addresses[current_index - 1]] = before_addr
								info.bbendaddr_bbstartaddr_map[before_addr] = bb_start_addresses[current_index - 1]
								#print("*")
								#print(hex(bb_start_addresses[current_index - 1]))
								#print(hex(before_addr))
								break						
							before_addr = findpreviousinsaddr(before_addr)
					if bb_start_address == bb_start_addresses[-1]:
						#print("*")
						before_addr = func_end_addr#findpreviousinsaddr(func_end_addr)
						while before_addr >= bb_start_addresses[-1] and before_addr != -1:
							if before_addr == bb_start_addresses[-1] or before_addr in info.insnsmap:
								info.bbstartaddr_bbendaddr_map[bb_start_address] = before_addr
								info.bbendaddr_bbstartaddr_map[before_addr] = bb_start_address
								#print("*")
								#print(hex(bb_start_address))
								#print(hex(before_addr))
								break						
							before_addr = findpreviousinsaddr(before_addr)
					
				
	#print("+++++")
	#for addr in sorted(info.bbendaddr_bbstartaddr_map):
	#	print("*")
	#	print(hex(addr))
	#	print(hex(info.bbendaddr_bbstartaddr_map[addr]))



def load_binary():
	file_command_return_string = subprocess.check_output(['file', info.args.input]).decode('utf-8')

	#if info.args.input.endswith(".so"):
	if "shared object" in file_command_return_string and "dynamically linked" in file_command_return_string:
		info.picflag = 1
	else:
		info.picflag = 0

	try:
		info.project = angr.Project(info.args.input,load_options={'auto_load_libs': False})
	except:
		info.picflag = 0
		info.project = angr.Project(info.args.input, 
			main_opts = {'backend': 'blob'},
			load_options={'auto_load_libs': False})

	#print(hex(info.picflag))


def parse_parameters():
	parser = argparse.ArgumentParser(description='SelectiveTaint static analysis')
	parser.add_argument("-input", help = "input enclave binary file", type=str, required=True)
	parser.add_argument('-taintsources', help = "taint source function names", type=str, nargs='*')
	info.args = parser.parse_args()
	#print(info.args.input)
	#print(info.args.taintsources)
	f = open("debug_tmp_file", "a")
	f.write("analyzing " + info.args.input + "\n")
	f.close()


def main():
	start = time.time()
	# check parameters
	print("STEP 01.parse_parameters()", flush=True)
	parse_parameters()
	print("STEP 02.load_binary()", flush=True)
	load_binary()
	print("STEP 03.disassemble()", flush=True)
	disassemble()
	print("STEP 04.readelf_sections_info()", flush=True)
	readelf_sections_info()
	print("STEP 05.find_ins_addr()", flush=True)
	find_ins_addr()
	print("STEP 06.capstone_parse()", flush=True)
	capstone_parse()
	print("STEP 07.find_functions()", flush=True)
	find_functions()
	print("STEP 08.build_CFG()", flush=True)
	build_CFG()
	#find_deadcode()
	print("STEP 09.generate_func_prototype()", flush=True)
	generate_func_prototype()
	print("STEP 10.generate_callsite_signature()", flush=True)
	generate_callsite_signature()
	print("STEP 11.update_CFG()", flush=True)
	update_CFG()
	print("STEP 12.generate_function_summary()", flush=True)
	generate_function_summary()
	print("STEP 13.binary_static_taint()", flush=True)
	binary_static_taint()
	
	#
	# selectivetaint-typed
	#
	#reset_CFG()
	print("STEP 14.reset_update_CFG_typed()", flush=True)
	reset_update_CFG_typed()
	print("STEP 15.generate_function_summary_typed()", flush=True)
	generate_function_summary_typed()
	print("STEP 16.binary_static_taint_typed()", flush=True)
	binary_static_taint_typed()
	
	end = time.time()
	f = open("debug_tmp_file", "a")
	f.write(info.args.input + " time: " + str(end-start) + "\n")
	f.close()

'''
proj = angr.Project('perlbench_base.i386-m32-gcc42-nn', auto_load_libs=False)
cfg = proj.analyses.CFGFast()

#for func in cfg.kb.functions:
#	print(hex(func))

print(len(cfg.kb.functions))
	
print(dir(cfg))

#for pred in sorted(cfg.functions.callgraph.predecessors(0x8049390)):
#	print(hex(pred))


funcs = [0x8049390]
visited = set()
visited.add(0x8049390)

while True:
	if len(funcs) == 0:
		break
	func = funcs.pop(0)

	visited.add(func)
	embed()

	for pred in sorted(cfg.functions.callgraph.predecessors(func)):
		funcs.append(pred)


print("*****")

#for v in sorted(visited):
#	print(hex(v))

print(len(visited))
'''




#
#main function
#
if __name__ == "__main__":
	main()
