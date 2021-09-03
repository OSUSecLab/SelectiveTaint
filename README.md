#  SelectiveTaint
**SelectiveTaint** is an efficient **selective taint analysis framework** for binary executables. The key idea is to **selectively** instrument the instructions involving taint analysis using **static binary rewriting** instead of dynamic binary instrumentation. At a high level, SelectiveTaint statically scans taint sources of interest in the binary code, leverages value set analysis to conservatively determine whether an instruction operand needs to be tainted or not, and then selectively taints the instructions of interest. For more details, please see our [paper](https://www.usenix.org/conference/usenixsecurity21/presentation/chen-sanchuan) (USENIX Security 2021).


SelectiveTint has four key components inside:

- (1) **CFG Reconstruction**. When given an application binary, we will first disassemble and build its CFG starting from the main function. If there is a library call, we will resolve the calling target and use the function summaries to decide whether further instrumentation of the library is needed. If an indirect jmp/call is encountered, we will perform backward slicing and use the VSA and type information to resolve the target.

- (2) **Value Set Analysis**. VSA has become a standard technique in static binary analysis for determining the possible values of a register or a symbolic memory address. We use the VSA to help identify the instruction operands that are never involved in the taint analysis.

- (3) **Taint Instruction Identification**. Selective tainting essentially aims to identify the instructions that are involved in the taint analysis. With the identification of Iu by VSA, we then start from the instructions that introduce the taint sources, and systematically identify the rest of instructions that are not in Iu.

- (4) **Binary Rewriting**. Having identified the instructions that need to be tainted, we then use the static binary rewriting to insert the taint analysis logic including tracking of the taint sources and taint propagations as well as the taint checks at the taint sinks.

SelectiveTaint passed USENIX 2021 Artifact Evaluation and the artifact evaluation instructions can be found in selectivetaint_instructions.pdf.

# Downloads

Please refer to selectivetaint_instructions.pdf on how to download and use SelectiveTaint.

## Run Command Examples

Please set up environment according to selectivetaint_instructions.pdf.

As for static analysis, change to analysis directory and execute corresponding command. For instance, for perlbench:

```
cd analysis

python3 static.py -input ./perlbench_base.i386-m32-gcc42-nn -taintsources read fread fgetc
```

As for static rewriting, change to rewriting directory and execute corresponding command. For instance, for perlbench:

```
cd ../rewriting

. ./scripts/set_environment.sh

make

./selectivetaint -i ./perlbench_base.i386-m32-gcc42-nn -o ./perlbench_base.i386-m32-gcc42-nn_selective -t ./tests/perlbench_base.i386-m32-gcc42-nn_tainted_insn_typed_output_file
```

# Citing

If you create a research work that uses our work, please citing the associated paper:
```
@inproceedings {Chen:2021:SelectiveTaint,
	author = {Sanchuan Chen and Zhiqiang Lin and Yinqian Zhang},
	title = {SelectiveTaint: Efficient Data Flow Tracking With Static Binary Rewriting},
	booktitle = {30th {USENIX} Security Symposium ({USENIX} Security 21)},
	year = {2021},
	url = {https://www.usenix.org/conference/usenixsecurity21/presentation/chen-sanchuan},
	publisher = {{USENIX} Association},
	month = aug,
}
```

