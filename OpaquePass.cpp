//By AlSch092 @ Github
#include "llvm/Passes/PassPlugin.h"  
#include "llvm/Passes/PassBuilder.h"  
#include "llvm/IR/PassManager.h"  
#include "llvm/IR/Function.h"  
#include "llvm/Support/raw_ostream.h"  
#include <map>
#include <random>
#include <string>
#include <sstream>

using namespace llvm;

namespace  //this project's transformations are specific to x64!
{
	enum Architecture
	{
		X86_64,
		AARCH64
	};

	/*
		ConvertToHexByte - Converts a byte to a hexadecimal string representation.
	*/
	std::string ConvertToHexByte(__in const uint8_t& byte)
	{
		std::string hexByte = "0x";
		char buffer[3];
		sprintf_s(buffer, "%02X", byte);
		hexByte += buffer;
		return hexByte;
	}

	/*
	    getBlockLabel - returns a string of `BB`'s label, ex. %0 or %27
	*/
	std::string getBlockLabel(llvm::BasicBlock* BB)
	{
		std::string str;
		llvm::raw_string_ostream rso(str);
		BB->printAsOperand(rso, false); // 'false' = don't print type
		return rso.str();
	}

	/*
	    InsertUnreachableJunkBlock - Inserts a random block of unreachable junk code into the function `F` at the specified `TargetBlock` of size `JunkByteSize`.
    */
	void InsertUnreachableJunkBlock(__inout BasicBlock* TargetBlock, __in const int& JunkByteSize)
	{
		IRBuilder<> Builder(TargetBlock);

		FunctionType* JunkTy = FunctionType::get(Builder.getVoidTy(), false);

		std::string byteString = ".byte ";

		for (int i = 0; i < JunkByteSize; i++)
		{
			std::mt19937 rng((std::random_device())());
			uint8_t byte = rng() % 256; // Generate a random byte
			std::string hexByte = ConvertToHexByte(byte);
			byteString += hexByte;

			if(i < JunkByteSize - 1)
				byteString += ",";
		}

		errs() << "Generated junk byte string: " << byteString << "\n";

		InlineAsm* IA = InlineAsm::get(JunkTy, byteString, "", true); //use 'true' as 2nd param to avoid getting optimized out
		Builder.CreateCall(IA);
		Builder.CreateUnreachable(); // ensures nothing follows
	}

	/*
	    InsertUnreachableJunkBlock - Inserts a block of unreachable junk code into the function `F` at the specified `TargetBlock`.
	*/
	void InsertUnreachableJunkBlock(__inout BasicBlock* TargetBlock, __in const std::string& JunkByteString) 
	{
		IRBuilder<> Builder(TargetBlock);

		FunctionType* JunkTy = FunctionType::get(Builder.getVoidTy(), false);

		std::string byteString = ".byte " + JunkByteString;

		InlineAsm* IA = InlineAsm::get(JunkTy, byteString, "", true); //insert junk asm in opaque predicate block which never gets executed , use 'true' as 2nd param to avoid getting optimized out
		Builder.CreateCall(IA);
		Builder.CreateUnreachable(); // ensures nothing follows
	}

	/*
		AddOpaquePredicate - Inserts an opaque predicate into the function `F`.
	*/
	void AddOpaquePredicate(__in Function* F, Architecture A)
	{
		LLVMContext& Ctx = F->getContext();

		for (BasicBlock& BB : *F)
		{
			for (Instruction& I : BB)
			{
				if (auto* Ret = dyn_cast<ReturnInst>(&I))
				{
					BasicBlock* RetBlock = Ret->getParent()->splitBasicBlock(Ret, "retBlock");

					BasicBlock* OpaqueEntry = BasicBlock::Create(Ctx, "opaque_entry", F, RetBlock);
					BasicBlock* TrueBlock = BasicBlock::Create(Ctx, "trueBlock", F, RetBlock);
					BasicBlock* FalseBlock = BasicBlock::Create(Ctx, "falseBlock", F, RetBlock);

					InsertUnreachableJunkBlock(FalseBlock, 100); //insert 100 junk bytes in false block of predicate

					llvm::Type* voidTy = llvm::Type::getVoidTy(Ctx);
					llvm::FunctionType* asmFuncTy = llvm::FunctionType::get(voidTy, false);

					IRBuilder<> Builder(OpaqueEntry);

					llvm::InlineAsm* PushAsm;

					if (A == X86_64)
						PushAsm = llvm::InlineAsm::get(asmFuncTy, ".byte 0x50", "", true); //insert push rax since we muddy up the 'al' register with the .getTrue() statement
					else if (A == AARCH64)
						PushAsm = llvm::InlineAsm::get(asmFuncTy, ".byte 0xE0,0x0F,0x1F,0xF8", "", true); // str x0, [sp, -16]! ;  push rax equivalent
					
					Builder.CreateCall(PushAsm);

					Value* Cond = Builder.getTrue();
				
					Builder.CreateCondBr(Cond, TrueBlock, FalseBlock);
					
					llvm::InlineAsm* PopAsm;

					if (A == X86_64)
					    PopAsm = llvm::InlineAsm::get(asmFuncTy, ".byte 0x58", "", true); //pop rax   , the true as 2nd parameter forces it to not be optimized out
					else if (A == AARCH64)
						PopAsm = llvm::InlineAsm::get(asmFuncTy, ".byte 0xE0,0x07,0x41,0xF8", "", true); // ldr x0, [sp], 16 ; pop rax equivalent
					
					IRBuilder<>(TrueBlock).CreateCall(PopAsm);

					IRBuilder<>(TrueBlock).CreateBr(RetBlock);

					BB.getTerminator()->eraseFromParent();
					IRBuilder<>(&BB).CreateBr(OpaqueEntry);

					return; // insert once
				}
			}
		}
	}

	bool isInConditionalPath(BasicBlock* BB, std::set<BasicBlock*>& visited)
	{
		if (!visited.insert(BB).second) //already visited
			return false;

		for (BasicBlock* Pred : predecessors(BB)) //loop over predecessors of BB
		{
			if (pred_empty(Pred))
				return false;

			Instruction* term = Pred->getTerminator();

			if (auto* BI = dyn_cast<BranchInst>(term)) //is predecessor's terminator a branch instruction?
			{
				if (BI->isConditional())
				{
					if (BI->getSuccessor(0) == BB || BI->getSuccessor(1) == BB)
						return true;
				}

				if (isInConditionalPath(Pred, visited))
					return true;
			}
		}

		return false;
	}

	bool isInIfElseStructure(BasicBlock* BB)
	{
		std::set<BasicBlock*> visited;

		// Entry block should never be nested
		if (pred_empty(BB))
			return false;

		return isInConditionalPath(BB, visited);
	}

	struct MyTestPass : public PassInfoMixin<MyTestPass> //control flow flattening test
	{
		PreservedAnalyses run(Function& F, FunctionAnalysisManager& AM)
		{
			if (F.isDeclaration() || F.size() < 2 || F.getName() != "DoControlFlow")
				return PreservedAnalyses::all();

			errs() << "MyTestPass: " << F.getName() << "\n";
			
			LLVMContext& Ctx = F.getContext();
			IRBuilder<> Builder(&*F.getEntryBlock().getFirstInsertionPt());
			IntegerType* Int32Ty = Type::getInt32Ty(Ctx);

			AllocaInst* store = Builder.CreateAlloca(Builder.getInt32Ty(), nullptr, "stateVar");
			Builder.CreateStore(Builder.getInt32(0), store); //state var to 0
			
			BasicBlock* dispatcher = BasicBlock::Create(Ctx, "dispatcher", &F); //make a block for dispatcher/switch statement
			//Builder.CreateBr(dispatcher);

			IRBuilder<> DispatchBuilder(dispatcher);
			LoadInst* stateVal = DispatchBuilder.CreateLoad(Int32Ty, store);
			SwitchInst* Switch = DispatchBuilder.CreateSwitch(stateVal, dispatcher);

			for (BasicBlock& BB : F)
			{
				bool nested = false;

				//else 
				if (isInIfElseStructure(&BB))
				{
					nested = true;
				}

				for (BasicBlock* Pred : predecessors(&BB))
				{
					if (getBlockLabel(Pred) == "%0")
					{
						nested = false;
					}
				}

				if (nested)
				{
					errs() << "Nested block found: " << getBlockLabel(&BB) << "\n" ;
				}
				else
				{
					errs() << "NON-Nested block found: " << getBlockLabel(&BB) << "\n" ;
				}
			}

			return PreservedAnalyses::all();
		}
	};

	struct CleanupInlinedFunctionsPass : public PassInfoMixin<CleanupInlinedFunctionsPass>  //module pass
	{
		PreservedAnalyses run(Module& M, ModuleAnalysisManager&) 
		{
			std::vector<Function*> toRemove;

			for (Function& F : M) 
			{
				if (F.isDeclaration())
					continue;

				if (F.isDeclaration()) continue;

				if (F.getName() == "main" || F.getName() == "DllMain" || F.getName() == "DriverEntry") continue;

				//if (!F.hasInternalLinkage()) continue;

				//if (F.hasAddressTaken()) continue;

				if (!F.use_empty()) continue;

				errs() << "Cleanup: Deleting inlined and unused function: " << F.getName() << "\n";
				toRemove.push_back(&F);
			}

			for (Function* F : toRemove) 
			{
				F->eraseFromParent();
			}

			return PreservedAnalyses::none();
		}
	};

	struct ForceInlinePass : public PassInfoMixin<ForceInlinePass> //works, but needs to call module(cleanup_inlined) in order to delete unused functions which were inlined
	{
		PreservedAnalyses run(Function& F, FunctionAnalysisManager& AM)
		{
			if (F.isDeclaration() || F.size() < 2)
				return PreservedAnalyses::all();

			bool InlinedFunc = false;

			errs() << "ForceInlinePass: " << F.getName() << "\n";

			if (!F.isDeclaration() && !F.hasFnAttribute(Attribute::AlwaysInline) && !F.hasFnAttribute(Attribute::NoInline))
			{
				F.addFnAttr(Attribute::AlwaysInline);
				errs() << "ForceInlinePass: Inlining function " << F.getName() << "\n";
				InlinedFunc = true;
			}

			return InlinedFunc ? PreservedAnalyses::none() : PreservedAnalyses::all();
		}
	};

	struct OpaqueTransformPass : public PassInfoMixin<OpaqueTransformPass>
	{
		PreservedAnalyses run(Function& F, FunctionAnalysisManager& AM)
		{
			if (F.isDeclaration() || F.size() < 2)
				return PreservedAnalyses::all();

			errs() << "Applying OpaqueTransformPass (x64) to function: " << F.getName() << "\n";

		    AddOpaquePredicate(&F, Architecture::X86_64);

			errs() << "Transformed IR: " << "\n" << F << "\n";

			return PreservedAnalyses::all();
		}
	};

	struct OpaqueTransformPassAA64 : public PassInfoMixin<OpaqueTransformPassAA64>
	{
		PreservedAnalyses run(Function& F, FunctionAnalysisManager& AM)
		{
			if (F.isDeclaration() || F.size() < 2)
				return PreservedAnalyses::all();

			errs() << "Applying OpaqueTransformPass (AARCH64) to function: " << F.getName() << "\n";

			AddOpaquePredicate(&F, Architecture::AARCH64); // Insert opaque predicate logic

			errs() << "Transformed IR: " << "\n" << F << "\n";

			return PreservedAnalyses::all();
		}
	};

	struct XORConstInt : public PassInfoMixin<XORConstInt>  //xor obfuscate constants declared in entry block, decodes them when they are used in function calls
	{
		PreservedAnalyses run(Function& F, FunctionAnalysisManager& AM)
		{
			bool modified = false;
			std::mt19937 rng((std::random_device())());
			const uint32_t key = rng();

			for (auto& BB : F) //loop over basic blocks
			{
				for (auto& I : BB) //loop over instructions in each basic block
				{
					if (auto* store = llvm::dyn_cast<llvm::StoreInst>(&I))
					{
						if (getBlockLabel(&BB) != "%0")
							continue;

						auto* CI = dyn_cast<ConstantInt>(store->getValueOperand());

						if (!CI || CI->getBitWidth() != 32)
							continue;

						uint32_t value = CI->getZExtValue();
						uint32_t obf_val = value ^ key;

						Value* obfConst = ConstantInt::get(CI->getType(), obf_val); //make our obfuscated value
						Value* keyConst = ConstantInt::get(CI->getType(), key);
						store->setOperand(0, obfConst);
				
						modified = true;
					}
					
					if (auto* callInst = dyn_cast<CallInst>(&I)) 
					{
						auto* calledFunc = callInst->getCalledFunction();
						if (!calledFunc || calledFunc->isVarArg())
							continue;

						for (unsigned i = 0; i < callInst->getNumOperands(); ++i) 
						{
							Value* arg = callInst->getArgOperand(i);
				
							if (auto* loadInst = dyn_cast<LoadInst>(arg)) 
							{
								if (!loadInst->getType()->isIntegerTy(32))
									continue;

								IRBuilder<> builder(loadInst->getNextNode());
								Value* keyConst = ConstantInt::get(loadInst->getType(), key);
								Value* decoded = builder.CreateXor(loadInst, keyConst, "decoded");

								callInst->setArgOperand(i, decoded);
								modified = true;

								errs() << "Inserted XOR decode for argument " << i << "\n";
							}
						}
					}
				}
			}

			if(modified)
				errs() << "Transformed IR: " << "\n" << F << "\n";

			return modified ? PreservedAnalyses::none() : PreservedAnalyses::all(); //if modified, none of our preserved analysis are valid -> pass modified IR
		}
	};

	struct AlignPass : public PassInfoMixin<AlignPass>  //test, not particularly useful. sets alignment to 16 for alloca instructs
	{
		PreservedAnalyses run(Function& F, FunctionAnalysisManager& AM)
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
		LLVM_PLUGIN_API_VERSION, "TestTransformPass", LLVM_VERSION_STRING, [](PassBuilder& PB)
		{
			//function passes
			PB.registerPipelineParsingCallback(
				[](StringRef Name, FunctionPassManager& FPM,
				   ArrayRef<PassBuilder::PipelineElement>)
				{
					if (Name == "opaque")
					{
						FPM.addPass(OpaqueTransformPass());
						return true;
					}
					else if (Name == "opaqueAARCH64")
					{
						FPM.addPass(OpaqueTransformPassAA64());
						return true;
					}
					else if (Name == "controlflatten") //not yet finished - we need to make a state variable and then flatten all nested blocks into a "base layer" block, where flow is decided by the state
					{
						FPM.addPass(ControlFlattenPass());
						return true;
					}
					else if (Name == "xorconst")
					{
						FPM.addPass(XORConstInt());
						return true;
					}
					else if (Name == "align")
					{
						FPM.addPass(AlignPass());
						return true;
					}
					else if (Name == "forceinline")
					{
						FPM.addPass(ForceInlinePass());
						return true;
					}
					else if (Name == "test")
					{
						FPM.addPass(MyTestPass());
						return true;
					}

					return false;
				});
			
			//module passes
			PB.registerPipelineParsingCallback(
				[](StringRef Name, ModulePassManager& MPM,
					ArrayRef<PassBuilder::PipelineElement>)
				{
					if (Name == "cleanup-inlined")
					{
						MPM.addPass(CleanupInlinedFunctionsPass());
						return true;
					}

					return false;
				}
			);
		}
	};
}