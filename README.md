# LLVMOpaquePass
Some test passes that I'm making to improve my LLVM skills. The Opaque Pass inserts an opaque predicate at the end of a function, filled with junk bytes to cause IDA analysis to fail. As of right now, the routine generates 100 random bytes as instructions and inserts them into the 'false' block of the predicate, which are never executed, but still included in analysis by disassemblers. Since it's a random set of instructions generated, the resulting impact on static analysis tools can vary. In the best case, it can break decompilation or greatly change the expected behavior of the function. Instructions that modify the stack in some misaligned way might be more prone to causing an analysis failure (such as `add rsp, 0x07`). Both AArch64 and x64 are supported for the opaque pass, so use the appropriate command under the "Usage" section below. Most passes in the code are not production ready, so approach with caution (the opaque pass is probably the most reliable/applicable one currently).  

Basic XOR integer const obfuscation has also been added, with pass name `xorconst`. Constant values are xor'd when declared, and xor'd (decoded) inside functions when they are used as arguments. We do it this way instead of replacing all uses of the xor'd const because after optimizing with O1 or O2, the IR is changed in a way that removes load usages and thus they won't be deobfuscated properly. If we decode them in specific functions where theyre used as parameters, we can still use O2 optimization and have the pass work.   

## Attribute tags
To tag your function as being one you want to have an opaque pass added to it, tag it with `insertopaque`. If you're trying out the XOR const one, functions where the const values are declared in can be tagged with `xorconst-obfs`, then functions where those consts are used must be tagged with `xorconst-deobfs`. If you're using the forceinline, tag with `forceinline`.    

## Usage: 
 x64: `opt -load-pass-plugin="OpaquePass.dll" -passes='opaque' Input.ll -S -o Output.ll`   

 AArch64: `opt -load-pass-plugin="OpaquePass.dll" -passes='opaqueAARCH64' Input.ll -S -o Output.ll`   

or, for XOR encoding of constants:  

`opt -load-pass-plugin="OpaquePass.dll" -passes='xorconst-obfs' Input.ll -S -o Output.ll`  and `opt -load-pass-plugin="OpaquePass.dll" -passes='xorconst-deobfs' Input.ll -S -o Output.ll`    

or, force inline:

`opt -load-pass-plugin="OpaquePass.dll" -passes='function(forceinline),module(cleanup_inlined)' Input.ll -S -o Output.ll`   

## Comparison (IDA)

Before:   
![Clean_IDA](https://github.com/user-attachments/assets/4fa985f4-e5a0-4803-b4ee-abf3c6bbfdbe)  

After using pass:   

![IDA](https://github.com/user-attachments/assets/4e313a59-1d8c-4044-80b2-01e5ae0309fc)  

Decompilation:  Removes information about local vars  
![compare](https://github.com/user-attachments/assets/eaaa0706-f301-4f86-b287-aaea11abadfe)
