# LLVMOpaquePass
LLVM Pass which inserts an opaque predicate at the end of a function, filled with junk bytes to cause IDA analysis to fail (x86_64). Will be improved over time as I get better with LLVM passes. The techniques presented are specific to x64, since they involve inline assembler using numeric byte numbers instead of explicit instructions  

Basic XOR integer const obfuscation has also been added, with pass name `xorconst`. Constant values are xor'd when declared, and xor'd (decoded) when they are referenced in an instruction's operand.  

## Usage: 
 `opt -load-pass-plugin="OpaquePass.dll" -passes='opaque' Input.ll -S -o Output.ll`  
 
## Comparison (IDA)

Before:   
![Clean_IDA](https://github.com/user-attachments/assets/4fa985f4-e5a0-4803-b4ee-abf3c6bbfdbe)  

After using pass:   

![IDA](https://github.com/user-attachments/assets/4e313a59-1d8c-4044-80b2-01e5ae0309fc)  

Decompilation:  Removes information about local vars  
![compare](https://github.com/user-attachments/assets/eaaa0706-f301-4f86-b287-aaea11abadfe)
