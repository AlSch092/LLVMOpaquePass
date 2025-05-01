#include "llvm/Passes/PassPlugin.h"  
#include "llvm/Passes/PassBuilder.h"  
#include "llvm/IR/PassManager.h"  
#include "llvm/IR/Function.h"  
#include "llvm/Support/raw_ostream.h"  
#include <map>
#include <random>
#include <string>

using namespace llvm;

namespace 
{
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
	    InsertUnreachableJunkBlock - Inserts a random block of unreachable junk code into the function `F` at the specified `TargetBlock` of size `JunkByteSize`.
    */
	void InsertUnreachableJunkBlock(Function* F, BasicBlock* TargetBlock, int JunkByteSize)
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

		InlineAsm* IA = InlineAsm::get(JunkTy, byteString, "", false);
		Builder.CreateCall(IA);
		Builder.CreateUnreachable(); // ensures nothing follows
	}

	/*
	    InsertUnreachableJunkBlock - Inserts a block of unreachable junk code into the function `F` at the specified `TargetBlock`.
	*/
	void InsertUnreachableJunkBlock(Function* F, BasicBlock* TargetBlock, std::string JunkByteString) 
	{
		IRBuilder<> Builder(TargetBlock);

		FunctionType* JunkTy = FunctionType::get(Builder.getVoidTy(), false);

		std::string byteString = ".byte " + JunkByteString;

		InlineAsm* IA = InlineAsm::get(JunkTy, byteString, "", false); //insert junk asm in opaque predicate block which never gets executed
		Builder.CreateCall(IA);
		Builder.CreateUnreachable(); // ensures nothing follows
	}

	/*
		AddOpaquePredicate - Inserts an opaque predicate into the function `F`.
	*/
	void AddOpaquePredicate(Function* F)
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

					InsertUnreachableJunkBlock(F, FalseBlock, 100); //insert 100 junk bytes in false block of predicate

					IRBuilder<> Builder(OpaqueEntry);
					Value* Cond = Builder.getTrue();
					Builder.CreateCondBr(Cond, TrueBlock, FalseBlock);

					IRBuilder<>(TrueBlock).CreateBr(RetBlock);

					BB.getTerminator()->eraseFromParent();
					IRBuilder<>(&BB).CreateBr(OpaqueEntry);

					return; // insert once
				}
			}
		}
	}
  
	struct OpaqueTransformPass : public PassInfoMixin<OpaqueTransformPass>
	{
		PreservedAnalyses run(Function& F, FunctionAnalysisManager& AM)
		{
			errs() << "Applying OpaqueTransformPass to function: " << F.getName() << "\n";

			AddOpaquePredicate(&F); // Insert opaque predicate logic

			errs() << "Transformed IR: " << "\n" << F << "\n";

			return PreservedAnalyses::all();
		}
	};

	struct XORConstInt : public PassInfoMixin<XORConstInt>  //xor obfuscate constants, working on basic tests (without arithmetic involved)
	{
		PreservedAnalyses run(Function& F, FunctionAnalysisManager& AM)
		{
			bool modified = false;
			std::mt19937 rng((std::random_device())());

			for (auto& BB : F) //loop over basic blocks
			{
				for (auto& I : BB) //loop over instructions in each basic block
				{
					if (auto* store = llvm::dyn_cast<llvm::StoreInst>(&I))
					{
						auto* CI = dyn_cast<ConstantInt>(store->getValueOperand());

						if (!CI || CI->getBitWidth() != 32)
							continue;

						uint32_t value = CI->getZExtValue();
						uint32_t key = rng();
						uint32_t obf_val = value ^ key;

						Value* obfConst = ConstantInt::get(CI->getType(), obf_val); //make our obfuscated value
						Value* keyConst = ConstantInt::get(CI->getType(), key);
						store->setOperand(0, obfConst);

						for (User* u : store->getPointerOperand()->users())
						{
							if (auto* load = dyn_cast<LoadInst>(u))
							{
								IRBuilder<> lb(load->getNextNode()); // Insert after the load to ensure dominance

								Value* decoded = lb.CreateXor(load, keyConst);

								SmallVector<Use*, 8> usesToReplace;

								for (auto& use : load->uses())
								{
									if (use.getUser() != decoded)
										usesToReplace.push_back(&use);
								}

								for (auto* use : usesToReplace)
									use->set(decoded);
							}
						}

						modified = true;
					}
				}
			}

			if(modified)
				errs() << "Transformed IR: " << "\n" << F << "\n";

			return modified ? PreservedAnalyses::none() : PreservedAnalyses::all(); //if modified, none of our preserved analysis are valid -> pass modified IR
		}
	};

	struct AlignPass : public PassInfoMixin<AlignPass>  //test, not particularly useful
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
		LLVM_PLUGIN_API_VERSION, // Version of the plugin interface  
		"TestTransformPass",                // Name of the pass  
		LLVM_VERSION_STRING,     // LLVM version  
		[](PassBuilder& PB)
		{
			// Register the pass with the pass builder  
			PB.registerPipelineParsingCallback(
				[](StringRef Name, FunctionPassManager& FPM,
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
					return false;
				});
		}
	};
}