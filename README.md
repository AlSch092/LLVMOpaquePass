# LLVMOpaquePass
LLVM Pass which inserts an opaque predicate at the end of a function, filled with junk bytes to cause IDA analysis to fail (x86_64). As of right now, the routine generates 100 random bytes as instructions and inserts them into the 'false' block of the predicate, which are never executed. Since it's a random set of instructions generated, the resulting impact on static analysis tools can vary. In the best case, it can completely break decompilation or greatly change the expected behavior of the function. Instructions that modify the stack in some misaligned way might be more prone to causing an analysis failure (such as `add rsp, 0x07`). The techniques presented are specific to x64, since they involve inline assembler using numeric byte numbers instead of explicit instructions  

Basic XOR integer const obfuscation has also been added, with pass name `xorconst`. Constant values are xor'd when declared, and xor'd (decoded) when they are referenced in an instruction's operand.  

## Usage: 
 x64: `opt -load-pass-plugin="OpaquePass.dll" -passes='opaque' Input.ll -S -o Output.ll`   

 AArch64: `opt -load-pass-plugin="OpaquePass.dll" -passes='opaqueAARCH64' Input.ll -S -o Output.ll`   

or, for XOR encoding of constants:  

`opt -load-pass-plugin="OpaquePass.dll" -passes='xorconst' Input.ll -S -o Output.ll`  
 
## Comparison (IDA)

Before:   
![Clean_IDA](https://github.com/user-attachments/assets/4fa985f4-e5a0-4803-b4ee-abf3c6bbfdbe)  

After using pass:   

![IDA](https://github.com/user-attachments/assets/4e313a59-1d8c-4044-80b2-01e5ae0309fc)  

Decompilation:  Removes information about local vars  
![compare](https://github.com/user-attachments/assets/eaaa0706-f301-4f86-b287-aaea11abadfe)
