//===- X86ROPObfuscate.cpp - obfuscate by using ROP ---------===//
//
//===--------------------------------------------------------===//
//
// This file defines the pass that obfuscate by using ROP
//
//===--------------------------------------------------------===//

#include "MCTargetDesc/X86BaseInfo.h"
#include "X86.h"
#include "X86InstrInfo.h"
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
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/Function.h"
#include "llvm/MC/MCInstrDesc.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include <cassert>
#include <cstdint>
#include <iterator>
#include <llvm/CodeGen/SelectionDAG.h>

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

// Returns true if the instruction is JUMP
static inline bool isJUMP(const MachineInstr &MI);

// Returns true if the instruction is CALL
static inline bool isCALL(const MachineInstr &MI);

// Return true if the instruction is a non-meta, non-pseudo instrucion.
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
  bool isObfuscatable(const MachineInstr &MI) const;

  MachineRegisterInfo *MRI = nullptr;
  const X86InstrInfo *TII = nullptr;
  const X86RegisterInfo *TRI = nullptr;
};
}

char X86ROPObfuscatePass::ID = 0;


FunctionPass *llvm::createX86ROPObfuscatePass() { return new X86ROPObfuscatePass(); }
INITIALIZE_PASS(X86ROPObfuscatePass, DEBUG_TYPE, "X86 ROP Obfuscate pass", false, false)

static inline bool hasROPAttribute(const MachineFunction &MF) {
  return MF.getFunction().hasFnAttribute(Attribute::ROPObfuscate);
}

static inline bool isJUMP(const MachineInstr &MI) {
  unsigned Opcode = MI.getOpcode();
  switch (Opcode) {
    case X86::JMP16r:
    case X86::JMP16m:
    case X86::JMP32r:
    case X86::JMP32m:
    case X86::JMP64r:
    case X86::JMP64m:
    case X86::JMP_1:
    case X86::JMP_2:
    case X86::JMP_4:
    case X86::JMP16r_NT:
    case X86::JMP16m_NT:
    case X86::JMP32r_NT:
    case X86::JMP32m_NT:
    case X86::JMP64r_NT:
    case X86::JMP64m_NT:
        return true;
    default:
        return false;
  }
}

static inline bool isCALL(const MachineInstr &MI) {
  return MI.isCall();
}

static inline bool isRealInstruction(MachineInstr &MI) {
  return !MI.isPseudo() && !MI.isMetaInstruction();
}

bool X86ROPObfuscatePass::isObfuscatable(const MachineInstr &MI) const {
  return isCALL(MI) || isJUMP(MI);
}

bool X86ROPObfuscatePass::runOnMachineFunction(MachineFunction &MF) {
  bool Changed = false;
  if (DisableX86ROPObfuscate || !hasROPAttribute(MF))
      return false;

  // Process all basic blocks.
  for (auto &MBB : MF) {
      for (auto &MI : MBB) {
          if (isRealInstruction(MI))
              MI.dump();
      }
  }

  return Changed;
}
