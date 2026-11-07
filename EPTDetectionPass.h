#pragma once

#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"

struct EPTDetectionPass : llvm::PassInfoMixin<EPTDetectionPass>
{
    llvm::PreservedAnalyses run(llvm::Module& m, llvm::ModuleAnalysisManager&);
};

bool RunEPTDetection(llvm::Module& m);

extern llvm::cl::opt<bool> EPTDetectEnable;