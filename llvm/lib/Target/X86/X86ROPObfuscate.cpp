//===- X86ROPObfuscate.cpp - obfuscate by using ROP ---------===//
//
//===--------------------------------------------------------===//
//
// This file defines the pass that obfuscate by using ROP
//
//===--------------------------------------------------------===//

#include "MCTargetDesc/X86BaseInfo.h"
#include "X86.h"
#include "X86CallingConv.h"
#include "X86InstrBuilder.h"
#include "X86InstrInfo.h"
#include "X86MachineFunctionInfo.h"
#include "X86Subtarget.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/CodeGen/LazyMachineBlockFrequencyInfo.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineOperand.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/MachineSizeOpts.h"
#include "llvm/CodeGen/TargetOpcodes.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/CodeGen/SelectionDAG.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/MC/MCInstrDesc.h"
#include "llvm/MC/MCSymbol.h"
#include "llvm/MC/MCContext.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include <cstdint>
#include <iterator>

using namespace llvm;

#define DEBUG_TYPE "x86-rop-obfuscate"

static cl::opt<bool> 
  DisableX86ROPObfuscate(
          "disable-x86-rop-obfuscate",
          cl::Hidden,
          cl::desc("X86: Disable ROP Obfuscate."),
          cl::init(false)
  );

STATISTIC(NumObfuscated, "Number of ROP Obfuscated functions");

// Returns true if machine function has 'rop_obfuscate' attribute
static inline bool hasROPAttribute(const MachineFunction &MF);

// Returns true if the instruction is JMP
static inline bool isJMP(const MachineInstr &MI);

// Returns true if the instruction is CALL
static inline bool isCALL(const MachineInstr &MI);

// Return true if the instruction is a non-meta, non-pseudo instruction.
static inline bool isRealInstruction(const MachineInstr &MI);

namespace {
class X86ROPObfuscatePass : public MachineFunctionPass {
public:
  X86ROPObfuscatePass() : MachineFunctionPass(ID) {}

  StringRef getPassName() const override { return "X86 ROP Obfuscate"; }

  bool runOnMachineFunction(MachineFunction &MF) override;

  static char ID;

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.setPreservesCFG();
    AU.addRequired<LazyMachineBlockFrequencyInfoPass>();
    MachineFunctionPass::getAnalysisUsage(AU);
  }

private:
  // return true if instruction is obfuscatable
  bool isObfuscatable(const MachineInstr &MI) const;
    
  // obfuscate CALL instruction
  bool ObfuscateCallInst(MachineFunction &MF, MachineInstr &MI);

  // obfuscate JMP instruction
  bool ObfuscateJmpInst(MachineFunction &MF, MachineInstr &MI);

  MachineRegisterInfo *MRI = nullptr;
  bool Is64Bit = false;
  const X86InstrInfo *TII = nullptr;
  const X86RegisterInfo *TRI = nullptr;
  unsigned SymId = 0;
};
}

char X86ROPObfuscatePass::ID = 0;


FunctionPass *llvm::createX86ROPObfuscatePass() { return new X86ROPObfuscatePass(); }
INITIALIZE_PASS(X86ROPObfuscatePass, DEBUG_TYPE, "X86 ROP Obfuscate pass", false, false)

static inline bool hasROPAttribute(const MachineFunction &MF) {
  return MF.getFunction().hasFnAttribute(Attribute::ROPObfuscate);
}

static inline bool isJMP(const MachineInstr &MI) {
  return  MI.isBranch() &&
          MI.isBarrier(); // is unconditional branch
}

static inline bool isCALL(const MachineInstr &MI) {
  return MI.isCall();
}

static inline bool isRealInstruction(const MachineInstr &MI) {
  return !MI.isPseudo() && !MI.isMetaInstruction();
}

bool X86ROPObfuscatePass::isObfuscatable(const MachineInstr &MI) const {
  return isCALL(MI) || isJMP(MI);
}

bool X86ROPObfuscatePass::ObfuscateCallInst(MachineFunction &MF, MachineInstr &MI) {
  bool Changed = false;
  /*
   * TODO

  const unsigned PushOpc = Is64Bit ? X86::PUSH64r : X86::PUSH32r;
  const unsigned PopOpc = Is64Bit ? X86::POP64r : X86::POP64r;
  const unsigned LeaOpc = Is64Bit ? X86::LEA64r : X86::LEA32r;
  const unsigned MovOpc = Is64Bit ? X86::MOV64mr : X86::MOV32mr;
  const unsigned RetOpc = Is64Bit ? X86::RETQ : X86::RETL;
  const Register StackPtr = Is64Bit ? X86::RSP : X86::ESP;
  const Register WorkReg = Is64Bit ? X86::RAX : X86::EAX;
  const unsigned RetValOffset = Is64Bit ? 0x10 : 0x8;
  const unsigned CalleeOffset = Is64Bit ? 0x8 : 0x4;

  auto SymName = ".callee_recover_" + MF.getName() + std::to_string(SymId++);

  MCContext &Ctx = MF.getContext();
  MCSymbol *CalleeRecoverSym = Ctx.getOrCreateSymbol(SymName);
  
//  const CallInst *Call = cast<CallInst>(&MI);

  switch (MI.getOpcode()) {

  }
  */

  return Changed;
}

bool X86ROPObfuscatePass::ObfuscateJmpInst(MachineFunction &MF, MachineInstr &MI) {
  bool Changed = false;

  if (MI.getNumOperands() != 1)
    return Changed;

  MachineBasicBlock *MBB = MI.getParent();
  DebugLoc DL = MI.getDebugLoc();
  const unsigned PushOpc = Is64Bit ? X86::PUSH64r : X86::PUSH32r;
  const unsigned PopOpc = Is64Bit ? X86::POP64r : X86::POP32r;
  const unsigned LeaOpc = Is64Bit ? X86::LEA64r : X86::LEA32r;
  const unsigned MovOpc = Is64Bit ? X86::MOV64mr : X86::MOV32mr;
  const unsigned RetOpc = Is64Bit ? X86::RETQ : X86::RETL;
  const Register StackPtr = Is64Bit ? X86::RSP : X86::ESP;
  const Register WorkReg = Is64Bit ? X86::RAX : X86::EAX;
  const unsigned RetValOffset = Is64Bit ? 8 : 4;

  const MachineOperand &Operand = MI.getOperand(0);
  assert(Operand.isMBB());
  MachineBasicBlock *TargetAddr = Operand.getMBB();

  // lea StackPtr, [StackPtr - RetValOffset]
  addRegOffset(BuildMI(*MBB, MBB->erase(&MI), DL, TII->get(LeaOpc), StackPtr), StackPtr, true, -RetValOffset);
  Changed = true;

  // push WorkReg
  MachineInstr *I = BuildMI(&*MBB, MBB->findDebugLoc(MI), TII->get(PushOpc))
    .addReg(WorkReg)
    .getInstr();

  // lea WorkReg, [dst]
  BuildMI(&*MBB, MBB->findDebugLoc(I), TII->get(LeaOpc), WorkReg)
    .addReg(0)
    .addImm(1)
    .addReg(0)
    .addMBB(TargetAddr)
    .addReg(0);

  // mov [StackPtr+RetValOffset], WorkReg
  addRegOffset(BuildMI(&*MBB, MBB->findDebugLoc(I), TII->get(MovOpc)), StackPtr, true, RetValOffset)
    .addReg(WorkReg);

  // pop WorkReg
  BuildMI(&*MBB, MBB->findDebugLoc(I), TII->get(PopOpc))
    .addReg(WorkReg);

  // ret
  BuildMI(&*MBB, MBB->findDebugLoc(I), TII->get(RetOpc));

  return Changed;
}

bool X86ROPObfuscatePass::runOnMachineFunction(MachineFunction &MF) {
  bool Changed = false;
  if (DisableX86ROPObfuscate || !hasROPAttribute(MF))
      return Changed;
  const X86Subtarget &STI = MF.getSubtarget<X86Subtarget>();

  Is64Bit = STI.is64Bit();
  TII = STI.getInstrInfo();

  // Process all basic blocks.
  for (auto &MBB : MF) {
    for (auto &MI : MBB) {
      if (!isRealInstruction(MI) || !isObfuscatable(MI))
        continue;
      if (isJMP(MI))
        Changed |= ObfuscateJmpInst(MF, MI);
      else if (isCALL(MI))
        Changed |= ObfuscateCallInst(MF, MI);
    }
  }

  return Changed;
}
