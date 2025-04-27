# LLVMOpaquePass
LLVM Pass which inserts an opaque predicate at the end of a function, filled with junk bytes to cause IDA analysis to fail (x86_64)

## Usage: 
 `opt -load-pass-plugin="OpaquePass.dll" -passes='opaque' Input.ll -S -o Output.ll`  
 
## Comparison (IDA)

Before:   
![Clean_IDA](https://github.com/user-attachments/assets/4fa985f4-e5a0-4803-b4ee-abf3c6bbfdbe)  

After using pass:   

![IDA](https://github.com/user-attachments/assets/4e313a59-1d8c-4044-80b2-01e5ae0309fc)
