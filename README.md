# Differential Testing of x86 Disassemblers

x86 Disassemblers translate a stream of machine code into a sequence of assembly instructions which can produce completely unreliable results due to bad decoding of an instruction. This project is about the correctness of the *instruction decoder*, the component of disassemblers that is responsible for the decoding of machine instructions using a *n-version disassembly* methodology based on differential analysis which is specific for Intel x86 archicture. 

Given an arbitrary string of bytes, we use multiple *(n−1)* disassemblers to decode the instruction potentially starting with the first byte of the string, and then we compare the output of the various disassemblers to detect discrepancies. Any discrepancy is a symptom that the instruction decoder of at least one of the tested disassemblers is buggy.

The *n<sup>th</sup>* instruction decoder is a CPU-assisted inbstrcution decoder which does not perform itself the decoding, but instead delegates the duty to the *perfect instruction decoder* implemented in the CPU. While it does not output a disassembly code, it can infer some information about the instruction the string encodes (e.g., whether the instruction is valid, the length of the instruction, and the type of operands) to check whether the output produced by the tested disassemblers is compliant with the format of the instruction.

The output of each disassemblers is normalized to allow a comparison between them and computing a coefficient of agreement, the rationale being to be more confident in the output with the highest agreement among disassemblers.

