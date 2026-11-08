#include "EPTDetectionPass.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

using namespace llvm;

llvm::cl::opt<bool> EPTDetectEnable("obfeptdetect", llvm::cl::init(true), llvm::cl::desc("Master Toggle"));

static std::mt19937 Rng((std::random_device{}() ^ (unsigned)std::chrono::high_resolution_clock::now().time_since_epoch().count()));

static constexpr uint8_t KindErmsb = 3;
static constexpr unsigned MaxSitesPerFn = 4;
static constexpr unsigned MinSites = 1;
static constexpr unsigned ErmsbPct = 30;
static constexpr unsigned HyperDosPausesPerIter = 16;

struct RewriteSite
{
    Function* F;
    Instruction* InsertBefore;
    Function* SuspectFn;
    uint64_t SiteId;
    uint8_t Kind;
};

static std::vector<RewriteSite> Sites;
static std::vector<Function*> SuspectPool;

static bool HasAnnotationTag(Function& f, const char* tag)
{
    Module* m = f.getParent();
    GlobalVariable* ga = m->getGlobalVariable("llvm.global.annotations");
    if (!ga) return false;
    ConstantArray* ca = dyn_cast<ConstantArray>(ga->getOperand(0));
    if (!ca) return false;
    for (unsigned i = 0; i < ca->getNumOperands(); ++i)
    {
        ConstantStruct* cs = dyn_cast<ConstantStruct>(ca->getOperand(i));
        if (!cs) continue;
        if (cs->getOperand(0)->stripPointerCasts() != &f) continue;
        auto* strgv = dyn_cast<GlobalVariable>(cs->getOperand(1)->stripPointerCasts());
        if (!strgv || !strgv->hasInitializer()) continue;
        auto* cds = dyn_cast<ConstantDataSequential>(strgv->getInitializer());
        if (!cds || !cds->isString()) continue;
        if (strcmp(cds->getAsString().str().c_str(), tag) == 0) return true;
    }
    return false;
}

static bool HasEPTDetectAnnotation(Function& f)
{
    return HasAnnotationTag(f, "EPTDetect");
}

static bool HasNoEPTDetectAnnotation(Function& f)
{
    return HasAnnotationTag(f, "NoEPTDetect");
}

static bool HasObfuscateAnnotation(Function& f)
{
    return HasAnnotationTag(f, "obfus");
}

static bool HasNoObfuscateAnnotation(Function& f)
{
    return HasAnnotationTag(f, "noobfus");
}

static bool HasResponseAnnotation(Function& f)
{
    return HasAnnotationTag(f, "EPTDetectionResponse");
}

static unsigned GetHyperDosLevel(Function& f)
{
    Module* m = f.getParent();
    GlobalVariable* ga = m->getGlobalVariable("llvm.global.annotations");
    if (!ga) return 0;
    ConstantArray* ca = dyn_cast<ConstantArray>(ga->getOperand(0));
    if (!ca) return 0;
    const char* prefix = "HyperDos-";
    size_t prefixlen = strlen(prefix);
    for (unsigned i = 0; i < ca->getNumOperands(); ++i)
    {
        ConstantStruct* cs = dyn_cast<ConstantStruct>(ca->getOperand(i));
        if (!cs) continue;
        if (cs->getOperand(0)->stripPointerCasts() != &f) continue;
        auto* strgv = dyn_cast<GlobalVariable>(cs->getOperand(1)->stripPointerCasts());
        if (!strgv || !strgv->hasInitializer()) continue;
        auto* cds = dyn_cast<ConstantDataSequential>(strgv->getInitializer());
        if (!cds || !cds->isString()) continue;
        StringRef s = cds->getAsString();
        while (!s.empty() && s.back() == '\0') s = s.drop_back();
        if (!s.starts_with(prefix)) continue;
        StringRef suffix = s.drop_front(prefixlen);
        unsigned n = 0;
        if (!suffix.getAsInteger(10, n) && n > 0) return n;
    }
    return 0;
}

static uint64_t NextNonce()
{
    std::uniform_int_distribution<uint64_t> dist(1, ~0ULL);
    return dist(Rng);
}

static bool ShouldEmitErmsbSite()
{
    if (ErmsbPct == 0) return false;
    if (ErmsbPct >= 100) return true;
    std::uniform_int_distribution<unsigned> dist(0, 99);
    return dist(Rng) < ErmsbPct;
}

static Function* FindResponseHandler(Module& m)
{
    Function* found = nullptr;
    for (Function& f : m)
    {
        if (f.isDeclaration()) continue;
        if (!HasResponseAnnotation(f)) continue;
        FunctionType* ft = f.getFunctionType();
        if (!ft->getReturnType()->isVoidTy() || ft->getNumParams() != 0) continue;
        if (found) continue;
        found = &f;
    }
    return found;
}

static void BuildSuspectPool(Module& m)
{
    SuspectPool.clear();
    for (Function& f : m)
    {
        if (f.isDeclaration()) continue;
        if (f.empty()) continue;
        if (f.getName().starts_with("EPTDetect")) continue;
        if (!HasEPTDetectAnnotation(f) && !HasObfuscateAnnotation(f)) continue;
        if (HasNoEPTDetectAnnotation(f) || HasNoObfuscateAnnotation(f)) continue;
        SuspectPool.push_back(&f);
    }
}

static Function* PickSuspect(Function& currentfn)
{
    if (SuspectPool.empty()) return nullptr;
    SmallVector<unsigned, 32> otheridx;
    for (size_t i = 0; i < SuspectPool.size(); ++i)
        if (SuspectPool[i] != &currentfn)
            otheridx.push_back((unsigned)i);
    if (otheridx.empty()) return &currentfn;
    std::uniform_int_distribution<unsigned> dist(0, (unsigned)otheridx.size() - 1);
    return SuspectPool[otheridx[dist(Rng)]];
}

static bool HasOptIn(Function& f)
{
    return HasEPTDetectAnnotation(f) || HasObfuscateAnnotation(f);
}

static bool HasOptOut(Function& f)
{
    return HasNoEPTDetectAnnotation(f) || HasNoObfuscateAnnotation(f);
}

static bool IsEligibleSite(Instruction& i)
{
    auto* call = dyn_cast<CallBase>(&i);
    if (!call) return false;
    if (isa<CallBrInst>(call)) return false;
    if (call->isInlineAsm()) return false;
    if (auto* ci = dyn_cast<CallInst>(call))
        if (ci->isMustTailCall()) return false;
    if (call->getParent()->isEHPad()) return false;
    if (Function* callee = call->getCalledFunction())
        if (callee->getName().starts_with("EPTDetect"))
            return false;
    return true;
}

static void CollectCandidates(Function& f, std::vector<Instruction*>& out)
{
    unsigned perfnkept = 0;
    for (BasicBlock& bb : f)
    {
        for (Instruction& i : bb)
        {
            auto* call = dyn_cast<CallBase>(&i);
            if (!call) continue;
            if (call->getParent()->isEHPad()) continue;
            if (!IsEligibleSite(i)) continue;
            if (perfnkept >= MaxSitesPerFn) continue;
            ++perfnkept;
            out.push_back(&i);
        }
    }
}

static StructType* GetEntryType(LLVMContext& c)
{
    return StructType::get(c, {Type::getInt8Ty(c), PointerType::get(c, 0), Type::getInt64Ty(c)}, false);
}

static void AddSite(Function& f, Instruction* site)
{
    Function* suspect = PickSuspect(f);
    if (!suspect) return;
    if (!ShouldEmitErmsbSite()) return;
    RewriteSite rs;
    rs.F = &f;
    rs.InsertBefore = site;
    rs.SuspectFn = suspect;
    rs.SiteId = NextNonce();
    rs.Kind = KindErmsb;
    Sites.push_back(rs);
}

static void EmitErmsbSiteCalls(Module& m, GlobalVariable* table, Function* ermsbprobe, ArrayRef<RewriteSite> sites)
{
    LLVMContext& c = m.getContext();
    StructType* entryt = GetEntryType(c);
    ArrayType* arrt = ArrayType::get(entryt, sites.size());
    Type* i64 = Type::getInt64Ty(c);
    for (size_t i = 0; i < sites.size(); ++i)
    {
        const RewriteSite& s = sites[i];
        IRBuilder<> b(s.InsertBefore);
        Value* slot = b.CreateGEP(arrt, table, {ConstantInt::get(i64, 0), ConstantInt::get(i64, i)}, "EPTDetectSlot");
        b.CreateCall(ermsbprobe, {slot});
    }
}

static GlobalVariable* EmitErmsbResultSlot(Module& m)
{
    LLVMContext& c = m.getContext();
    Type* i8 = Type::getInt8Ty(c);
    auto* gv = new GlobalVariable(m, i8, false, GlobalValue::InternalLinkage, ConstantInt::get(i8, 0), "EPTDetectErmsbResult");
    gv->setThreadLocalMode(GlobalValue::GeneralDynamicTLSModel);
    return gv;
}

static GlobalVariable* EmitTable(Module& m, ArrayRef<RewriteSite> sites)
{
    LLVMContext& c = m.getContext();
    StructType* entryt = GetEntryType(c);
    Type* i8 = Type::getInt8Ty(c);
    Type* i64 = Type::getInt64Ty(c);
    SmallVector<Constant*, 16> entries;
    entries.reserve(sites.size());
    for (const RewriteSite& s : sites)
    {
        Constant* kindc = ConstantInt::get(i8, s.Kind);
        Constant* suspectc = s.SuspectFn;
        Constant* sidc = ConstantInt::get(i64, s.SiteId);
        entries.push_back(ConstantStruct::get(entryt, {kindc, suspectc, sidc}));
    }
    ArrayType* arrt = ArrayType::get(entryt, entries.size());
    Constant* init = ConstantArray::get(arrt, entries);
    auto* gv = new GlobalVariable(m, arrt, true, GlobalValue::InternalLinkage, init, "EPTDetectTable");
    return gv;
}

static Function* GetOrDeclareGetCurrentThread(Module& m)
{
    const char* name = "GetCurrentThread";
    if (Function* existing = m.getFunction(name)) return existing;
    LLVMContext& c = m.getContext();
    Type* ptrt = PointerType::get(c, 0);
    FunctionType* ft = FunctionType::get(ptrt, {}, false);
    Function* f = Function::Create(ft, GlobalValue::ExternalLinkage, name, &m);
    f->setDLLStorageClass(GlobalValue::DLLImportStorageClass);
    return f;
}

static Function* GetOrDeclareSetThreadContext(Module& m)
{
    const char* name = "SetThreadContext";
    if (Function* existing = m.getFunction(name)) return existing;
    LLVMContext& c = m.getContext();
    Type* ptrt = PointerType::get(c, 0);
    Type* i32 = Type::getInt32Ty(c);
    FunctionType* ft = FunctionType::get(i32, {ptrt, ptrt}, false);
    Function* f = Function::Create(ft, GlobalValue::ExternalLinkage, name, &m);
    f->setDLLStorageClass(GlobalValue::DLLImportStorageClass);
    return f;
}

static Function* GetOrDeclareAddVectoredExceptionHandler(Module& m)
{
    const char* name = "AddVectoredExceptionHandler";
    if (Function* existing = m.getFunction(name)) return existing;
    LLVMContext& c = m.getContext();
    Type* ptrt = PointerType::get(c, 0);
    Type* i32 = Type::getInt32Ty(c);
    FunctionType* ft = FunctionType::get(ptrt, {i32, ptrt}, false);
    Function* f = Function::Create(ft, GlobalValue::ExternalLinkage, name, &m);
    f->setDLLStorageClass(GlobalValue::DLLImportStorageClass);
    return f;
}

static void InsertLodsdInlineProbe(Function& f, Function* handler, uint64_t siteid)
{
    LLVMContext& c = f.getContext();
    Type* voidt = Type::getVoidTy(c);
    Type* i32 = Type::getInt32Ty(c);
    Type* i64 = Type::getInt64Ty(c);

    BasicBlock& entrybb = f.getEntryBlock();
    Instruction* insertbefore = &*entrybb.getFirstInsertionPt();
    while (insertbefore && isa<AllocaInst>(insertbefore))
        insertbefore = insertbefore->getNextNode();
    if (!insertbefore) insertbefore = entrybb.getTerminator();

    IRBuilder<> b(insertbefore);

    FunctionType* asmty = FunctionType::get(StructType::get(c, {i64, i64}), {}, false);

    InlineAsm* probeasm = InlineAsm::get(asmty,
        "jmp Past${:uid}\n\t"
        "Gadget${:uid}:\n\t"
        ".byte 0xAD\n\t"
        ".byte 0xC3\n"
        "Past${:uid}:\n\t"
        "lea rbx, [rip + Gadget${:uid}]\n\t"
        "xor rdx, rdx\n\t"
        "mov edx, dword ptr [rbx]\n\t"
        "mov $0, rdx\n\t"
        "mov rsi, rbx\n\t"
        "xor rax, rax\n\t"
        "call rbx\n\t"
        "mov $1, rax",
        "=&r,=&r,~{rax},~{rbx},~{rcx},~{rdx},~{rsi},~{rdi},~{r8},~{r9},~{r10},~{r11},~{dirflag},~{fpsr},~{flags},~{memory}",
        true, false, InlineAsm::AD_Intel);

    // if the attacker's trampoline never RETs the probe hangs here
    Value* vals = b.CreateCall(probeasm, {}, "EPTDetectLodsdVals");
    Value* direct64 = b.CreateExtractValue(vals, {0}, "EPTDetectDirect");
    Value* viag64 = b.CreateExtractValue(vals, {1}, "EPTDetectViaG");

    Value* direct32 = b.CreateTrunc(direct64, i32, "EPTDetectDirect32");
    Value* viag32 = b.CreateTrunc(viag64, i32, "EPTDetectViaG32");
    Value* ismis = b.CreateICmpNE(direct32, viag32, "EPTDetectIsMis");

    BasicBlock* cont = entrybb.splitBasicBlock(insertbefore, "EPTDetectLodsdCont");
    Instruction* oldterm = entrybb.getTerminator();
    BasicBlock* miss = BasicBlock::Create(c, "EPTDetectLodsdMiss", &f, cont);
    IRBuilder<> termb(oldterm);
    termb.CreateCondBr(ismis, miss, cont);
    oldterm->eraseFromParent();

    IRBuilder<> missb(miss);
    if (handler)
    {
        missb.CreateCall(handler);
        missb.CreateBr(cont);
    }
    else
    {
        FunctionType* int3ty = FunctionType::get(voidt, {}, false);
        InlineAsm* int3asm = InlineAsm::get(int3ty, "int3", "~{dirflag},~{fpsr},~{flags}", true, false, InlineAsm::AD_Intel);
        missb.CreateCall(int3asm);
        Function* trapfn = Intrinsic::getDeclaration(f.getParent(), Intrinsic::trap);
        missb.CreateCall(trapfn);
        missb.CreateUnreachable();
    }

    (void)siteid;
}

static Function* EmitErmsbVeh(Module& m, GlobalVariable* ermsbresult)
{
    const char* name = "EPTDetectErmsbVeh";
    if (Function* existing = m.getFunction(name)) return existing;

    LLVMContext& c = m.getContext();
    Type* i8 = Type::getInt8Ty(c);
    Type* i32 = Type::getInt32Ty(c);
    Type* i64 = Type::getInt64Ty(c);
    Type* ptrt = PointerType::get(c, 0);

    FunctionType* ft = FunctionType::get(i32, {ptrt}, false);
    Function* f = Function::Create(ft, GlobalValue::InternalLinkage, name, &m);
    f->addFnAttr(Attribute::NoUnwind);
    f->setCallingConv(CallingConv::Win64);
    f->getArg(0)->setName("ep");

    BasicBlock* entry = BasicBlock::Create(c, "Entry", f);
    BasicBlock* codeok = BasicBlock::Create(c, "CodeOk", f);
    BasicBlock* checkdr6 = BasicBlock::Create(c, "CheckDr6", f);
    BasicBlock* ours = BasicBlock::Create(c, "Ours", f);
    BasicBlock* alignedbb = BasicBlock::Create(c, "Aligned", f);
    BasicBlock* misalignbb = BasicBlock::Create(c, "Misaligned", f);
    BasicBlock* finish = BasicBlock::Create(c, "Finish", f);
    BasicBlock* passthru = BasicBlock::Create(c, "Passthru", f);

    IRBuilder<> b(entry);
    Value* ep = f->getArg(0);

    Value* erslot = b.CreateGEP(ptrt, ep, ConstantInt::get(i64, 0), "ErSlot");
    Value* er = b.CreateLoad(ptrt, erslot, "Er");

    Value* codeval = b.CreateLoad(i32, er, "Code");
    Value* isss = b.CreateICmpEQ(codeval, ConstantInt::get(i32, 0x80000004u), "IsSingleStep");
    b.CreateCondBr(isss, codeok, passthru);

    b.SetInsertPoint(codeok);
    Value* ctxslotptr = b.CreateGEP(i8, ep, ConstantInt::get(i64, 8), "CtxSlotPtr");
    Value* ctx = b.CreateLoad(ptrt, ctxslotptr, "Ctx");

    Value* dr6ptr = b.CreateGEP(i8, ctx, ConstantInt::get(i64, 0x68), "Dr6Ptr");
    Value* dr6 = b.CreateLoad(i64, dr6ptr, "Dr6");
    Value* dr6bit0 = b.CreateAnd(dr6, ConstantInt::get(i64, 1), "Dr6Bit0");
    Value* isdr0 = b.CreateICmpNE(dr6bit0, ConstantInt::get(i64, 0), "IsDr0Trip");
    b.CreateCondBr(isdr0, checkdr6, passthru);

    b.SetInsertPoint(checkdr6);
    b.CreateBr(ours);

    b.SetInsertPoint(ours);
    Value* rdiptr = b.CreateGEP(i8, ctx, ConstantInt::get(i64, 0xA0), "RdiPtr");
    Value* rdi = b.CreateLoad(i64, rdiptr, "Rdi");
    Value* rdilow3 = b.CreateAnd(rdi, ConstantInt::get(i64, 7), "RdiLow3");
    Value* isaligned = b.CreateICmpEQ(rdilow3, ConstantInt::get(i64, 0), "IsAligned");
    b.CreateCondBr(isaligned, alignedbb, misalignbb);

    b.SetInsertPoint(alignedbb);
    b.CreateStore(ConstantInt::get(i8, 1), ermsbresult);
    b.CreateBr(finish);

    b.SetInsertPoint(misalignbb);
    b.CreateStore(ConstantInt::get(i8, 2), ermsbresult);
    b.CreateBr(finish);

    b.SetInsertPoint(finish);
    Value* dr0ptr = b.CreateGEP(i8, ctx, ConstantInt::get(i64, 0x48), "Dr0Ptr");
    b.CreateStore(ConstantInt::get(i64, 0), dr0ptr);
    Value* dr7ptr = b.CreateGEP(i8, ctx, ConstantInt::get(i64, 0x70), "Dr7Ptr");
    b.CreateStore(ConstantInt::get(i64, 0), dr7ptr);
    Value* dr6new = b.CreateAnd(dr6, ConstantInt::get(i64, ~1ULL), "Dr6Cleared");
    b.CreateStore(dr6new, dr6ptr);
    b.CreateRet(ConstantInt::get(i32, (uint32_t)-1));

    b.SetInsertPoint(passthru);
    b.CreateRet(ConstantInt::get(i32, 0));

    return f;
}

static Function* EmitErmsbProbe(Module& m, GlobalVariable* ermsbresult, Function* handler)
{
    const char* name = "EPTDetectRunErmsb";
    if (Function* existing = m.getFunction(name)) return existing;

    LLVMContext& c = m.getContext();
    Type* voidt = Type::getVoidTy(c);
    Type* i8 = Type::getInt8Ty(c);
    Type* i32 = Type::getInt32Ty(c);
    Type* i64 = Type::getInt64Ty(c);
    Type* ptrt = PointerType::get(c, 0);
    StructType* entryt = GetEntryType(c);

    FunctionType* ft = FunctionType::get(voidt, {ptrt}, false);
    Function* f = Function::Create(ft, GlobalValue::InternalLinkage, name, &m);
    f->addFnAttr(Attribute::NoUnwind);
    f->getArg(0)->setName("e");

    BasicBlock* entry = BasicBlock::Create(c, "Entry", f);
    BasicBlock* check = BasicBlock::Create(c, "Check", f);
    BasicBlock* miss = BasicBlock::Create(c, "Miss", f);
    BasicBlock* exit = BasicBlock::Create(c, "Exit", f);

    IRBuilder<> b(entry);

    Value* suspectslot = b.CreateGEP(entryt, f->getArg(0), {ConstantInt::get(i32, 0), ConstantInt::get(i32, 1)}, "EPTDetectSuspectSlot");
    Value* suspect = b.CreateLoad(ptrt, suspectslot, "EPTDetectSuspect");

    b.CreateStore(ConstantInt::get(i8, 0), ermsbresult);

    ArrayType* ctxarrt = ArrayType::get(i8, 0x4D0);
    AllocaInst* ctxbuf = b.CreateAlloca(ctxarrt, nullptr, "CtxBuf");
    ctxbuf->setAlignment(Align(16));

    Function* memsetfn = Intrinsic::getDeclaration(&m, Intrinsic::memset, {ptrt, i64});
    b.CreateCall(memsetfn, {ctxbuf, ConstantInt::get(i8, 0), ConstantInt::get(i64, 0x4D0), ConstantInt::get(Type::getInt1Ty(c), 0)});

    Value* cfptr = b.CreateGEP(ctxarrt, ctxbuf, {ConstantInt::get(i64, 0), ConstantInt::get(i64, 0x30)}, "CfPtr");
    b.CreateStore(ConstantInt::get(i32, 0x00100010), cfptr);

    Value* dr0ptr = b.CreateGEP(ctxarrt, ctxbuf, {ConstantInt::get(i64, 0), ConstantInt::get(i64, 0x48)}, "Dr0Ptr");
    Value* susint = b.CreatePtrToInt(suspect, i64, "SusInt");
    Value* dr0val = b.CreateAdd(susint, ConstantInt::get(i64, 8), "Dr0Val");
    b.CreateStore(dr0val, dr0ptr);

    Value* dr7ptr = b.CreateGEP(ctxarrt, ctxbuf, {ConstantInt::get(i64, 0), ConstantInt::get(i64, 0x70)}, "Dr7Ptr");
    b.CreateStore(ConstantInt::get(i64, 0x30001ULL), dr7ptr);

    Function* getthread = GetOrDeclareGetCurrentThread(m);
    Value* hthread = b.CreateCall(getthread, {}, "HThread");
    Function* setctx = GetOrDeclareSetThreadContext(m);
    b.CreateCall(setctx, {hthread, ctxbuf});

    ArrayType* scratcharrt = ArrayType::get(i8, 0x2000);
    AllocaInst* scratch = b.CreateAlloca(scratcharrt, nullptr, "ErmsbScratch");
    scratch->setAlignment(Align(16));

    Value* srcint = b.CreateSub(susint, ConstantInt::get(i64, 0x1000), "SrcInt");
    Value* srcptr = b.CreateIntToPtr(srcint, ptrt, "SrcPtr");
    Value* dstptr = b.CreateGEP(scratcharrt, scratch, {ConstantInt::get(i64, 0), ConstantInt::get(i64, 0)}, "DstPtr");

    FunctionType* asmty = FunctionType::get(voidt, {ptrt, ptrt, i64}, false);
    InlineAsm* repmovsbasm = InlineAsm::get(asmty, "cld\n\trep movsb", "{rsi},{rdi},{rcx},~{rsi},~{rdi},~{rcx},~{memory},~{dirflag},~{fpsr},~{flags}", true, false, InlineAsm::AD_Intel);
    b.CreateCall(repmovsbasm, {srcptr, dstptr, ConstantInt::get(i64, 0x2000)});

    b.CreateCall(memsetfn, {ctxbuf, ConstantInt::get(i8, 0), ConstantInt::get(i64, 0x4D0), ConstantInt::get(Type::getInt1Ty(c), 0)});
    b.CreateStore(ConstantInt::get(i32, 0x00100010), cfptr);
    b.CreateCall(setctx, {hthread, ctxbuf});

    b.CreateBr(check);
    b.SetInsertPoint(check);
    Value* resval = b.CreateLoad(i8, ermsbresult, "ErmsbRes");
    Value* ismis = b.CreateICmpNE(resval, ConstantInt::get(i8, 1), "IsMis");
    b.CreateCondBr(ismis, miss, exit);

    b.SetInsertPoint(miss);
    if (handler)
    {
        b.CreateCall(handler);
        b.CreateBr(exit);
    }
    else
    {
        FunctionType* int3ty = FunctionType::get(voidt, {}, false);
        InlineAsm* int3asm = InlineAsm::get(int3ty, "int3", "~{dirflag},~{fpsr},~{flags}", true, false, InlineAsm::AD_Intel);
        b.CreateCall(int3asm);
        Function* trapfn = Intrinsic::getDeclaration(&m, Intrinsic::trap);
        b.CreateCall(trapfn);
        b.CreateUnreachable();
    }

    b.SetInsertPoint(exit);
    b.CreateRetVoid();

    return f;
}

static Function* EmitInit(Module& m, Function* ermsbveh)
{
    const char* name = "EPTDetectInit";
    if (Function* existing = m.getFunction(name)) return existing;

    LLVMContext& c = m.getContext();
    Type* voidt = Type::getVoidTy(c);
    Type* i32 = Type::getInt32Ty(c);

    FunctionType* ft = FunctionType::get(voidt, {}, false);
    Function* f = Function::Create(ft, GlobalValue::InternalLinkage, name, &m);
    f->addFnAttr(Attribute::NoUnwind);

    BasicBlock* entry = BasicBlock::Create(c, "Entry", f);
    IRBuilder<> b(entry);

    if (ermsbveh)
    {
        Function* addveh = GetOrDeclareAddVectoredExceptionHandler(m);
        b.CreateCall(addveh, {ConstantInt::get(i32, 1), ermsbveh});
    }

    b.CreateRetVoid();
    return f;
}

static Function* EmitPlumbing(Module& m, ArrayRef<RewriteSite> ermsbsites)
{
    Function* handler = FindResponseHandler(m);

    if (ermsbsites.empty()) return handler;
    if (m.getFunction("EPTDetectRunErmsb")) return handler;

    GlobalVariable* ermsbresult = EmitErmsbResultSlot(m);
    GlobalVariable* table = EmitTable(m, ermsbsites);

    Function* ermsbveh = EmitErmsbVeh(m, ermsbresult);
    Function* ermsbprobe = EmitErmsbProbe(m, ermsbresult, handler);
    Function* init = EmitInit(m, ermsbveh);

    EmitErmsbSiteCalls(m, table, ermsbprobe, ermsbsites);

    appendToGlobalCtors(m, init, 65535);

    return handler;
}

static std::string BuildHyperDosAsm(uint64_t count, unsigned k)
{
    uint64_t iters = count / k;
    if (iters == 0) iters = 1;

    std::string s;
    s.reserve(64 + k * 7);

    char buf[64];
    snprintf(buf, sizeof(buf), "mov rax, %llu\n", (unsigned long long)iters);
    s += buf;

    s += "HyperDosLoop${:uid}:\n";

    for (unsigned i = 0; i < k; ++i)
        s += "pause\n";

    s += "dec rax\n";
    s += "jnz HyperDosLoop${:uid}";
    return s;
}

static void InsertHyperDosInlinePauses(Function& f, unsigned level)
{
    LLVMContext& c = f.getContext();
    Type* voidt = Type::getVoidTy(c);

    BasicBlock& entrybb = f.getEntryBlock();
    Instruction* insertbefore = &*entrybb.getFirstInsertionPt();
    while (insertbefore && isa<AllocaInst>(insertbefore))
        insertbefore = insertbefore->getNextNode();
    if (!insertbefore) insertbefore = entrybb.getTerminator();

    IRBuilder<> b(insertbefore);

    uint64_t count = (uint64_t)level * 1000000ULL;
    std::string asmstr = BuildHyperDosAsm(count, HyperDosPausesPerIter);

    FunctionType* asmty = FunctionType::get(voidt, {}, false);
    InlineAsm* asmblock = InlineAsm::get(asmty, asmstr, "~{rax},~{dirflag},~{fpsr},~{flags}", true, false, InlineAsm::AD_Intel);
    b.CreateCall(asmblock);
}

static bool ProcessFunctionHyperDos(Function& f)
{
    if (f.isDeclaration()) return false;
    if (f.getName().starts_with("EPTDetect")) return false;
    unsigned level = GetHyperDosLevel(f);
    if (level == 0) return false;
    InsertHyperDosInlinePauses(f, level);
    return true;
}

static bool ProcessFunction(Function& f)
{
    if (f.isDeclaration()) return false;
    if (f.getName().starts_with("EPTDetect")) return false;
    if (HasOptOut(f)) return false;
    if (!HasOptIn(f)) return false;

    std::vector<Instruction*> cands;
    CollectCandidates(f, cands);

    if (cands.size() < MinSites) return false;

    for (Instruction* site : cands)
        AddSite(f, site);

    return true;
}

bool RunEPTDetection(Module& m)
{
    if (!EPTDetectEnable) return false;

    Sites.clear();
    BuildSuspectPool(m);

    bool mutated = false;

    for (Function& f : m)
        mutated |= ProcessFunction(f);

    Function* handler = EmitPlumbing(m, Sites);

    for (Function& f : m)
    {
        if (f.isDeclaration()) continue;
        if (f.getName().starts_with("EPTDetect")) continue;
        if (HasOptOut(f)) continue;
        if (!HasOptIn(f)) continue;
        InsertLodsdInlineProbe(f, handler, NextNonce());
        mutated = true;
    }

    for (Function& f : m)
        mutated |= ProcessFunctionHyperDos(f);

    return mutated;
}

PreservedAnalyses EPTDetectionPass::run(Module& m, ModuleAnalysisManager&)
{
    if (!RunEPTDetection(m)) return PreservedAnalyses::all();
    return PreservedAnalyses::none();
}
