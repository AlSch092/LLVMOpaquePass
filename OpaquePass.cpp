#include "llvm/Passes/PassPlugin.h"  
#include "llvm/Passes/PassBuilder.h"  
#include "llvm/IR/PassManager.h"  
#include "llvm/IR/Function.h"  
#include "llvm/Support/raw_ostream.h"  
#include <map>

using namespace llvm;  

namespace {  

    void InsertUnreachableJunkBlock(Function* F, BasicBlock* TargetBlock) 
    {
        IRBuilder<> Builder(TargetBlock);

        LLVMContext& Ctx = F->getContext();
        FunctionType* JunkTy = FunctionType::get(Builder.getVoidTy(), false);

        // Inline asm payload - fake logic + trap
		InlineAsm* IA = InlineAsm::get(JunkTy, ".byte 0xEB,0x01,0x0F,0x13,0x17,0x21,0xFF,0xF1,0x01,0x55,0x88,0x23,0x79,0xc3,0xc3", "", false); //insert junk asm in opaque predicate block which never gets executed
        Builder.CreateCall(IA);
        Builder.CreateUnreachable(); // ensures nothing follows
    }

    void AddOpaquePredicate(Function* F) 
    {
        LLVMContext& Ctx = F->getContext();

        for (BasicBlock& BB : *F) 
        {
            Instruction* Term = BB.getTerminator(); // inserts opaque predicate with junk bytes at the end of a function which makes IDA analysis more difficult
            
            if (isa<ReturnInst>(Term)) //check if terminator is a 'ret' instruction
            {
                BasicBlock* RetBlock = BB.splitBasicBlock(Term, "retBlock");

                BasicBlock* OpaqueEntry = BasicBlock::Create(Ctx, "opaque_entry", F, RetBlock); // create new opaque logic blocks before RetBlock
                BasicBlock* TrueBlock = BasicBlock::Create(Ctx, "trueBlock", F, RetBlock);
                BasicBlock* FalseBlock = BasicBlock::Create(Ctx, "falseBlock", F, RetBlock);

                InsertUnreachableJunkBlock(F, FalseBlock); // insert junk asm in the never-taken false block


                IRBuilder<> Builder(OpaqueEntry);                 // build opaque conditional branch
                Value* Cond = Builder.getTrue();                  //always true statement
                Builder.CreateCondBr(Cond, TrueBlock, FalseBlock);

                IRBuilder<>(TrueBlock).CreateBr(RetBlock);       //link True/False to RetBlock

                BB.getTerminator()->eraseFromParent();           //redirect original BB to opaque_entry
                IRBuilder<>(&BB).CreateBr(OpaqueEntry);

                break; //insert once per function, removing this causes extremely slow pass time
            }
        }
    }

    // Define the pass that inherits from PassInfoMixin  
    struct OpaqueTransformPass : public PassInfoMixin<OpaqueTransformPass>
    {
        // Implement the run function  
        PreservedAnalyses run(Function& F, FunctionAnalysisManager& AM) 
        {
            errs() << "Applying OpaqueTransformPass to function: " << F.getName() << "\n";

            AddOpaquePredicate(&F); // Insert opaque predicate logic

            errs() << "Transformed IR: " << "\n" << F << "\n";

            return PreservedAnalyses::all();
        }
    };

    struct AlignPass : public PassInfoMixin<AlignPass>  //test, not particularly useful
    {
       PreservedAnalyses run(Function & F, FunctionAnalysisManager & AM)
       {
           for (auto& BB : F) 
           {
               for (auto& I : BB) 
               {
                   if (auto* AI = llvm::dyn_cast<llvm::AllocaInst>(&I)) 
                   {
                       AI->setAlignment(llvm::Align(16)); //set alignment to 16 bytes
                   }
               }
           }

		   return PreservedAnalyses::all();
       }
    };

   struct ControlFlattenPass : public PassInfoMixin<ControlFlattenPass>  //this is not yet working, don't use it
   {
       PreservedAnalyses run(Function& F, FunctionAnalysisManager& AM) 
       {
           if (F.isDeclaration() || F.size() < 2)
               return PreservedAnalyses::all();

           LLVMContext& Ctx = F.getContext();
           IntegerType* Int32Ty = Type::getInt32Ty(Ctx);
           IRBuilder<> Builder(&*F.getEntryBlock().getFirstInsertionPt());

           AllocaInst* stateVar = Builder.CreateAlloca(Int32Ty, nullptr, "state"); //state var to keep track of control flow
           Builder.CreateStore(ConstantInt::get(Int32Ty, 0), stateVar);

           BasicBlock* dispatcher = BasicBlock::Create(Ctx, "dispatcher", &F);
           Builder.CreateBr(dispatcher);

           IRBuilder<> DispatchBuilder(dispatcher);
           LoadInst* stateVal = DispatchBuilder.CreateLoad(Int32Ty, stateVar);
           SwitchInst* Switch = DispatchBuilder.CreateSwitch(stateVal, dispatcher);

           std::map<BasicBlock*, int> BBIDs; //map basic block to state ID
           int id = 1;
           std::vector<BasicBlock*> blocks;

           for (auto& BB : F)  //loop over basic blocks for function F
           {
               if (&BB == &F.getEntryBlock() || &BB == dispatcher) //ignore entry block & dispatcher
                   continue;

               BBIDs[&BB] = id++;
               blocks.push_back(&BB);
           }

           auto hasPhi = [](BasicBlock* BB) //helper func to check if a block has PHI nodes
           {
               for (auto& I : *BB)
                   if (isa<PHINode>(&I)) 
                       return true;

               return false;
           };

           for (BasicBlock* BB : blocks) 
           {
               Instruction* term = BB->getTerminator();
               if (!term) continue;

               BranchInst* br = dyn_cast<BranchInst>(term);
               if (!br) continue;

               // Check successors
               bool canFlatten = true;
               for (unsigned i = 0; i < br->getNumSuccessors(); ++i) 
               {
                   if (hasPhi(br->getSuccessor(i))) 
                   {
                       canFlatten = false;
                       break;
                   }
               }

               if (canFlatten) 
               {
                   IRBuilder<> B(term);
                   for (unsigned i = 0; i < br->getNumSuccessors(); ++i) 
                   {
                       BasicBlock* Succ = br->getSuccessor(i);
                       B.CreateStore(ConstantInt::get(Int32Ty, BBIDs[Succ]), stateVar);
                       B.CreateBr(dispatcher);
                   }
                   term->eraseFromParent();
               }

               Switch->addCase(ConstantInt::get(Int32Ty, BBIDs[BB]), BB);
           }

           return PreservedAnalyses::none();
       }
   };

}
 
extern "C" __declspec(dllexport) ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK  llvmGetPassPluginInfo() 
{
   return 
   {  
       LLVM_PLUGIN_API_VERSION, // Version of the plugin interface  
       "TestTransformPass",                // Name of the pass  
       LLVM_VERSION_STRING,     // LLVM version  
       [](PassBuilder &PB) 
       {  
           // Register the pass with the pass builder  
           PB.registerPipelineParsingCallback(  
               [](StringRef Name, FunctionPassManager &FPM,  
                  ArrayRef<PassBuilder::PipelineElement>) 
               {  
                   if (Name == "opaque") 
                   {  
                       FPM.addPass(OpaqueTransformPass());
                       return true;  
                   }  
				   else if (Name == "controlflatten") 
                   {
					   FPM.addPass(ControlFlattenPass());
					   return true;
				   }
                   else if (Name == "align") 
                   {
                       FPM.addPass(AlignPass());
                       return true;
                   }
                   return false;  
               });  
       }  
   };  
}