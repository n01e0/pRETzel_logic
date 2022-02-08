//=- AArch64ROPObfuscate.cpp - obfuscate by using ROP for AArch64 -=//
//
// MIT License
//
// Copyright (c) 2020 n01e0
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
//===--------------------------------------------------------===//
//
// This file defines the pass that obfuscate by using ROP
//
//===--------------------------------------------------------===//

#include "AArch64.h"
#include "AArch64InstrInfo.h"
#include "AArch64Subtarget.h"
#include "AArch64MachineFunctionInfo.h"
#include "MCTargetDesc/AArch64AddressingModes.h"
#include "Utils/AArch64BaseInfo.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineDominators.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineOperand.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/Instruction.def"
#include "llvm/MC/MCInstrDesc.h"
#include "llvm/MC/MCSymbol.h"
#include "llvm/MC/MCContext.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include <cassert>
#include <cstdlib>

using namespace llvm;

#define DEBUG_TYPE "aarch64-rop-obfuscate"

static cl::opt<bool>
  DisableAArch64ROPObfuscate(
      "disable-aarch64-rop-obfuscate",
      cl::Hidden,
      cl::desc("AArch64: Disable ROP Obfuscate"),
      cl::init(false)
);

STATISTIC(NumObfuscate, "Number of obfuscated instruction");

// Returns true iff machine function has 'rop_obfuscate' attribute
static inline bool hasROPAttribute(const MachineFunction &MF);

// Returns if the instruction is a non-meta, non-pseudo instruction.
static inline bool isRealInstruction(const MachineInstr &MI);

// Removes operands that are currently not needed
static inline void filter_operand(MachineInstr &MI);

// iterator to the desired Index
MachineBasicBlock::instr_iterator skip_iterator(MachineBasicBlock *MBB, const unsigned Index);

namespace {

class AArch64ROPObfuscate: public MachineFunctionPass {
public:
  static char ID;

  AArch64ROPObfuscate() : MachineFunctionPass(ID) {
    initializeAArch64ROPObfuscatePass(*PassRegistry::getPassRegistry());
  }

  bool runOnMachineFunction(MachineFunction &MF) override;

  StringRef getPassName() const override { return "AArch64 ROP Obfuscate"; }
private:
  // return true if instruction is obfuscatable
  bool isObfuscatable(const MachineInstr &MI) const;

  // obfuscate B instruction
  bool ObfuscateBInst(MachineFunction &MF, MachineInstr &MI, const unsigned Index);
  // obfuscate BL instruction
  bool ObfuscateBlInst(MachineFunction &MF, MachineInstr &MI, const unsigned Index);

  const TargetInstrInfo *TII = nullptr;
  const MachineRegisterInfo *MRI = nullptr;
  unsigned SymId = 0;
};

} // end anonymous namespace

char AArch64ROPObfuscate::ID = 0;

FunctionPass *llvm::createAArch64ROPObfuscatePass() { return new AArch64ROPObfuscate(); }

INITIALIZE_PASS(AArch64ROPObfuscate, DEBUG_TYPE, "AArch64 ROP Obfuscate pass", false, false);

static inline bool hasROPAttribute(const MachineFunction &MF) {
  return MF.getFunction().hasFnAttribute(Attribute::ROPObfuscate);
}

static inline bool isRealInstruction(const MachineInstr &MI) {
  return (!MI.isPseudo() && !MI.isMetaInstruction());
}

static inline void filter_operand(MachineInstr &MI) {
  unsigned Idx = 0;
  while (Idx < MI.getNumOperands()) {
    const MachineOperand &Op = MI.getOperand(Idx);
    switch (Op.getType()) {
      case MachineOperand::MO_RegisterMask:
      case MachineOperand::MO_Metadata:
      case MachineOperand::MO_IntrinsicID:
      case MachineOperand::MO_Predicate:
      case MachineOperand::MO_ShuffleMask:
        MI.RemoveOperand(Idx);
        break;
      case MachineOperand::MO_Register:
        if (Op.isDef() || Op.isImplicit() || Op.isDead())
          MI.RemoveOperand(Idx);
        else
          ++Idx;
        break;
      default:
        ++Idx;
        continue;
    }
  }
}

MachineBasicBlock::instr_iterator skip_iterator(MachineBasicBlock *MBB, const unsigned Index) {
  auto I = MBB->instr_begin();
  auto E = MBB->instr_end();
  unsigned Cur = 0;
  while (I != E && Cur != Index)
    ++I, ++Cur;
  return ++I;
}

bool AArch64ROPObfuscate::isObfuscatable(const MachineInstr &MI) const {
  switch (MI.getOpcode()) {
    case AArch64::B:
    case AArch64::BL:
      return true;
    default:
      return false;
  }
}

bool AArch64ROPObfuscate::ObfuscateBInst(MachineFunction &MF, MachineInstr &MI, const unsigned Index) {
  bool Changed = false;

  assert(MI.getOpcode() == AArch64::B && "MI isn't b");

  assert(MI.getNumOperands() == 1 && "too meny operands");

  auto SymName = ".dest_label_" + MF.getName() + std::to_string(SymId++);

  MCContext &Ctx = MF.getContext();
  MCSymbol *CalleeRecoverSym = Ctx.getOrCreateSymbol(SymName);

  MachineBasicBlock *MBB = MI.getParent();
  MachineBasicBlock::instr_iterator Iter = skip_iterator(MBB, Index);
  DebugLoc DL = MI.getDebugLoc();
  MachineOperand &Callee = MI.getOperand(0);
//  BuildMI(CalleeMBB, )


  const unsigned SubOpc = AArch64::SUBXri;
  const unsigned AddOpc = AArch64::ADDXri;
  const unsigned StrOpc = AArch64::STRXui;
  const unsigned AdrOpc = AArch64::ADR;
  const unsigned RetOpc = AArch64::RET;
  const unsigned LdrOpc = AArch64::LDRXui;

  const Register Sp = AArch64::SP;
  const Register Lr = AArch64::LR;

  const unsigned LrOffset = 8 / 8;

  /* # how impl
   * ## b transformation
   * ### default
   *   b %label
   * ~ snip ~
   *   code
   * label:
   *   code
   * 
   * ### obfuscated
   *   sub sp, sp, #16
   *   str x30, [sp, #8]
   *   adr x30, %rop_label
   *   ret
   * ~ snip ~
   * label:
   *   sub sp, sp, #16
   *   str x30, [sp, #8]
   * rop_label:
   *   ldr x30, [sp, #8]
   *   add sp, sp, #16
   *
   */

  // str x30, [sp, #8]
  BuildMI(*MBB, Iter, DL, TII->get(StrOpc))
    .addUse(Lr)
    .addUse(Sp)
    .addImm(LrOffset);

  // adr x30, %rop_label
  BuildMI(*MBB, Iter, DL, TII->get(AdrOpc), Lr)
    .addSym(CalleeRecoverSym);

  // ret
  BuildMI(*MBB, Iter, DL, TII->get(RetOpc))
    .addReg(Lr);

  // 遷移先でのrestore
  // 逆順でbuildする必要がある
  MachineBasicBlock *CalleeMBB = Callee.getMBB();
  
  // add sp, sp, #16
  BuildMI(*CalleeMBB, CalleeMBB->instr_begin(), DL, TII->get(AddOpc), Sp)
    .addReg(Sp)
    .addImm(16)
    .addImm(0);

  // ldr x30, [sp, #8]
  BuildMI(*CalleeMBB, CalleeMBB->instr_begin(), DL, TII->get(LdrOpc))
    .addDef(Lr)
    .addUse(Sp)
    .addImm(LrOffset);
  
  // str x30, [sp, #8]
  auto MIB = BuildMI(*CalleeMBB, CalleeMBB->instr_begin(), DL, TII->get(StrOpc))
    .addUse(Lr)
    .addUse(Sp)
    .addImm(LrOffset);


  // set callee recover symbol after str
  MIB.getInstr()->setPostInstrSymbol(MF, CalleeRecoverSym);

  // label:
  //   sub sp, sp, #16
  BuildMI(*CalleeMBB, CalleeMBB->instr_begin(), DL, TII->get(SubOpc), Sp)
    .addReg(Sp)
    .addImm(16)
    .addImm(0);

  // replace b with sub sp, sp, #16
  BuildMI(*MBB, MBB->erase(MI), DL, TII->get(SubOpc), Sp)
    .addReg(Sp)
    .addImm(16)
    .addImm(0);

  Changed = true;
  ++NumObfuscate;

  return Changed;
}

bool AArch64ROPObfuscate::ObfuscateBlInst(MachineFunction &MF, MachineInstr &MI, const unsigned Index) {
  bool Changed = false;

  assert(MI.getOpcode() == AArch64::BL && "MI isn't bl");
  filter_operand(MI);

  MachineOperand &Callee = MI.getOperand(0);

  auto CalleeSymName = Callee.getGlobal()->getGlobalIdentifier();
  auto DestSymName = std::string("rop_") + CalleeSymName;
  auto RecoverSymName = ".callee_recover_" + MF.getName() + std::to_string(SymId++);

  MCContext &Ctx = MF.getContext();
  MCSymbol *CalleeSym = Ctx.lookupSymbol(CalleeSymName);

  if (CalleeSym == nullptr || CalleeSym->isUndefined()) {
    return Changed;
  }


  MCSymbol *DestSym = Ctx.getOrCreateSymbol(DestSymName);
  MCSymbol *CalleeRecoverSym = Ctx.getOrCreateSymbol(RecoverSymName);

  MachineBasicBlock *MBB = MI.getParent();
  MachineBasicBlock::instr_iterator Iter = skip_iterator(MBB, Index);
  DebugLoc DL = MI.getDebugLoc();

  const unsigned SubOpc = AArch64::SUBXri;
  const unsigned AddOpc = AArch64::ADDXri;
  const unsigned StrOpc = AArch64::STRXui;
  const unsigned AdrOpc = AArch64::ADR;
  const unsigned RetOpc = AArch64::RET;
  const unsigned LdrOpc = AArch64::LDRXui;

  const Register Sp = AArch64::SP;
  const Register Lr = AArch64::LR;
  const Register X0 = AArch64::X0;

  /* # how impl
   * ## bl transformation
   * ### default
   *    bl func
   *  ~snip~
   *  func:
   *    code
   *    
   *  ### obfuscated
   *    sub sp, sp, #16
   *    str x0, [sp, #8]
   *    adr x0, %recover
   *    str x0, [sp, #16]
   *    adr x30, %func_rop
   *    ldr x0, [sp, #8]
   *    ret
   *  recover:
   *  ~snip~
   *  func:
   *    sub sp, sp, #16
   *    str x30, [sp, #16]
   *  func_rop:
   *    ldr x30, [sp, #16]
   *    code
   */

  // str x0, [sp, #8]
//  BuildMI(*MBB, Iter, DL, TII->get(StrOpc))
//    .addUse(X0)
//    .addUse(Sp)
//    .addUse(8/8);

  // adr, x0, %recover

  return Changed;
}

bool AArch64ROPObfuscate::runOnMachineFunction(MachineFunction &MF) {
  LLVM_DEBUG(dbgs() << "********** AArch64 ROP Obfuscate **********\n"
                    << "********** Function: " << MF.getName() << '\n');

  if (DisableAArch64ROPObfuscate || !hasROPAttribute(MF))
    return false;

  TII = MF.getSubtarget().getInstrInfo();
  MRI = &MF.getRegInfo();

  bool Changed = false;

  for (MachineBasicBlock &MBB : MF) {
    unsigned Index = 0;
    for (MachineBasicBlock::iterator MI = MBB.begin(), E = MBB.end(); MI != E; ++MI, ++Index) {
      if (isObfuscatable(*MI)) {
        switch ((*MI).getOpcode()) {
          case AArch64::B:
            Changed |= ObfuscateBInst(MF, *MI, Index);
            break;
          case AArch64::BL:
            Changed |= ObfuscateBlInst(MF, *MI, Index);
            break;
          default:
            break;
        }
      }
    }
  }

  return Changed;
}
