#  SelectiveTaint
**SelectiveTaint** is an efficient **selective taint analysis framework** for binary executables. The key idea is to **selectively** instrument the instructions involving taint analysis using **static binary rewriting** instead of dynamic binary instrumentation. At a high level, SelectiveTaint statically scans taint sources of interest in the binary code, leverages value set analysis to conservatively determine whether an instruction operand needs to be tainted or not, and then selectively taints the instructions of interest. 

For more details, please refer to selectivetaint_instructions.pdf for how to download and use SelectiveTaint.

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

