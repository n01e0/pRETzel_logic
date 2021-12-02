//===- X86ROPObfuscate.cpp - obfuscate by using ROP ---------===//
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
#include <cassert>
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

STATISTIC(NumObfuscatedCalls, "Number of ROP Obfuscated call instructions");
STATISTIC(NumObfuscatedJumps, "Number of ROP Obfuscated jmp instructions");

// Returns true iff machine function has 'rop_obfuscate' attribute
static inline bool hasROPAttribute(const MachineFunction &MF);

// Returns true if the instruction is JMP
static inline bool isJMP(const MachineInstr &MI);

// Returns true if the instruction is CALL
static inline bool isCALL(const MachineInstr &MI);

// Returns true if the instruction is tail call
static inline bool isTAILCALL(const MachineInstr &MI);

// Return true if the instruction is a non-meta, non-pseudo instruction.
static inline bool isRealInstruction(const MachineInstr &MI);

// removes operands that are currently not needed
static inline void filter_operand(MachineInstr &MI);

// iterator to the desired Index
MachineBasicBlock::instr_iterator skip(MachineBasicBlock *MBB, unsigned Index);

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
  bool ObfuscateCallInst(MachineFunction &MF, MachineInstr &MI,
                         unsigned &Index);

  // obfuscate JMP instruction
  bool ObfuscateJmpInst(MachineFunction &MF, MachineInstr &MI, unsigned &Index);

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
  return (MI.isBarrier() && MI.isBranch() &&
          MI.isTerminator()) || // Unconditional
         (MI.isBranch() && MI.isTerminator() && MI.isBarrier() &&
          MI.isIndirectBranch()) || // Indirect
         isTAILCALL(MI);            // Tail call is jmp
}

static inline bool isCALL(const MachineInstr &MI) {
  return MI.isCall() && !isTAILCALL(MI);
}

static inline bool isTAILCALL(const MachineInstr &MI) {
  return MI.isCall() && MI.isReturn();
}

static inline bool isRealInstruction(const MachineInstr &MI) {
  return !MI.isPseudo() && !MI.isMetaInstruction();
}

bool X86ROPObfuscatePass::isObfuscatable(const MachineInstr &MI) const {
  return isCALL(MI) || isJMP(MI);
}

static inline void filter_operand(MachineInstr &MI) {
  unsigned i = 0;
  while (i < MI.getNumOperands()) { 
    const MachineOperand &Op = MI.getOperand(i);
    switch (Op.getType()) {
      case MachineOperand::MO_RegisterMask:
      case MachineOperand::MO_Metadata:
      case MachineOperand::MO_IntrinsicID:
      case MachineOperand::MO_Predicate:
      case MachineOperand::MO_ShuffleMask:
        MI.RemoveOperand(i);
        break;
      case MachineOperand::MO_Register:
        if (Op.isDef() || Op.isImplicit() || Op.isDead())
          MI.RemoveOperand(i);
        else
          ++i;
        break;
      default:
        ++i;
        continue;
    }
  }
}

MachineBasicBlock::instr_iterator skip(MachineBasicBlock *MBB, unsigned Index) {
  auto I = MBB->instr_begin();
  unsigned Cur = 0;
  while (I != MBB->instr_end() && Cur != Index)
    ++I, ++Cur;
  return ++I;
}

bool X86ROPObfuscatePass::ObfuscateCallInst(MachineFunction &MF,
                                            MachineInstr &MI, unsigned &Index) {
  bool Changed = false;

  assert(isCALL(MI) && "MI isn't call");
  filter_operand(MI);

  assert(MI.getNumOperands() > 0 && "filter_operand failed");

  auto SymName = ".callee_recover_" + MF.getName() + std::to_string(SymId++);

  MCContext &Ctx = MF.getContext();
  MCSymbol *CalleeRecoverSym = Ctx.getOrCreateSymbol(SymName);
  MachineBasicBlock *MBB = MI.getParent();
  MachineBasicBlock::instr_iterator Iter = skip(MBB, Index);
  DebugLoc DL = MI.getDebugLoc();
  MachineOperand &Callee = MI.getOperand(0);
  MachineOperand::MachineOperandType Ty = Callee.getType();

  const unsigned PushOpc = Is64Bit ? X86::PUSH64r : X86::PUSH32r;
  const unsigned PopOpc = Is64Bit ? X86::POP64r : X86::POP64r;
  const unsigned LeaOpc = Is64Bit ? X86::LEA64r : X86::LEA32r;
  const unsigned SubOpc = Is64Bit ? X86::SUB64ri8 : X86::SUB32ri8;
  const unsigned MovmrOpc = Is64Bit ? X86::MOV64mr : X86::MOV32mr;
  const unsigned MovrmOpc = Is64Bit ? X86::MOV64rm : X86::MOV32rm;
  const unsigned MovrrOpc = Is64Bit ? X86::MOV64rr : X86::MOV32rr;
  const unsigned MovriOpc = Is64Bit ? X86::MOV64ri32 : X86::MOV32ri;
  const unsigned RetOpc = Is64Bit ? X86::RETQ : X86::RETL;
  const Register StackPtr = Is64Bit ? X86::RSP : X86::ESP;
  const Register WorkReg = Is64Bit ? X86::RAX : X86::EAX;
  const unsigned RetValOffset = Is64Bit ? 0x10 : 0x8;
  const unsigned CalleeOffset = Is64Bit ? 0x8 : 0x4;

  switch (Ty) {
  case MachineOperand::MO_Register:
  case MachineOperand::MO_Immediate:
  case MachineOperand::MO_ExternalSymbol:
  case MachineOperand::MO_GlobalAddress:
  case MachineOperand::MO_BlockAddress:
  case MachineOperand::MO_MCSymbol:
    Changed = true;
    break;
  default:
    Changed = false;
    return Changed;
    break;
  }

  assert((Ty == MachineOperand::MO_Register ||
          Ty == MachineOperand::MO_Immediate ||
          Ty == MachineOperand::MO_ExternalSymbol ||
          Ty == MachineOperand::MO_GlobalAddress ||
          Ty == MachineOperand::MO_BlockAddress ||
          Ty == MachineOperand::MO_MCSymbol) &&
         "Not Implemented");
  /*
   * sub rsp, RetValOffset
   * push WorkReg
   * mov WorkReg, Callee
   * mov [rsp+CalleeOffset], WorkReg
   * mov WorkReg, CalleeRecoverSym
   * mov [rsp+RetValOffset], WorkReg,
   * pop WorkReg
   * ret
   * :CalleeRecoverSym
   *
   * First, make stack look like this
   *
   * +------stack------+
   * |     WorkReg     |
   * +-----------------+
   * |     Callee      |
   * +-----------------+
   * | CalleeRecoverSym|
   * +-----------------+
   *
   * Then, the registers that had been saved for the work are returned, and the ROP is started by ret.
   *
   * +------stack------+
   * |     Callee      |
   * +-----------------+
   * | CalleeRecoverSym|
   * +-----------------+
   *
   *
   */

  // push WorkReg
  BuildMI(*MBB, Iter, DL, TII->get(PushOpc)).addReg(WorkReg);

  // WorkReg <- Callee
  switch (Ty) {
  case MachineOperand::MO_Register:
    // Register indirect call
    if (MI.getNumOperands() == 1) {
      Register OpReg = Callee.getReg();
      // mov WorkReg, Callee
      BuildMI(*MBB, Iter, DL, TII->get(MovrrOpc), WorkReg).addReg(OpReg);
    } else {
      // with offset
      // lea WorkReg, Callee
      auto LeaMIB = BuildMI(*MBB, Iter, DL, TII->get(MovrmOpc), WorkReg);
      for (unsigned i = 0; i < MI.getNumOperands(); i++)
        LeaMIB.add(MI.getOperand(i));
    }
    break;
  case MachineOperand::MO_Immediate:
    // mov WorkReg, Callee
    BuildMI(*MBB, Iter, DL, TII->get(MovriOpc), WorkReg).add(Callee);
    break;
  case MachineOperand::MO_ExternalSymbol:
  case MachineOperand::MO_GlobalAddress:
  case MachineOperand::MO_BlockAddress:
  case MachineOperand::MO_MCSymbol:
    // lea WorkReg, Callee
    BuildMI(*MBB, Iter, DL, TII->get(LeaOpc), WorkReg)
        .addReg(0)
        .addImm(1)
        .addReg(0)
        .add(Callee)
        .addReg(0);
    break;
  default:
    assert(1 && "The operand doesn't implemented");
    break;
  }
  // mov [rsp+CalleeOffset], WorkReg
  addRegOffset(BuildMI(*MBB, Iter, DL, TII->get(MovmrOpc)), StackPtr, true,
               CalleeOffset)
      .addReg(WorkReg);
  // mov WorkReg, CalleeRecoverSym
  BuildMI(*MBB, Iter, DL, TII->get(MovriOpc), WorkReg).addSym(CalleeRecoverSym);
  // mov [rsp+RetValOffset], WorkReg
  addRegOffset(BuildMI(*MBB, Iter, DL, TII->get(MovmrOpc)), StackPtr, true,
               RetValOffset)
      .addReg(WorkReg);
  // pop WorkReg
  BuildMI(*MBB, Iter, DL, TII->get(PopOpc)).addReg(WorkReg);
  // ret
  auto MIB = BuildMI(*MBB, Iter, DL, TII->get(RetOpc));

  // Callee will disappear if replace is not done last.
  // replace call to stack allocate
  BuildMI(*MBB, MBB->erase(MI), DL, TII->get(SubOpc), StackPtr)
      .addReg(StackPtr)
      .addImm(RetValOffset);

  // set callee recover symbol after the ret
  MIB.getInstr()->setPostInstrSymbol(MF, CalleeRecoverSym);

  ++NumObfuscatedCalls;
  return Changed;
}

bool X86ROPObfuscatePass::ObfuscateJmpInst(MachineFunction &MF,
                                           MachineInstr &MI, unsigned &Index) {
  bool Changed = false;

  filter_operand(MI);

  MachineBasicBlock *MBB = MI.getParent();
  DebugLoc DL = MI.getDebugLoc();
  MachineOperand &Operand = MI.getOperand(0);

  MachineOperand::MachineOperandType Ty = Operand.getType();

  const unsigned PushOpc = Is64Bit ? X86::PUSH64r : X86::PUSH32r;
  const unsigned PopOpc = Is64Bit ? X86::POP64r : X86::POP32r;
  const unsigned LeaOpc = Is64Bit ? X86::LEA64r : X86::LEA32r;
  const unsigned SubOpc = Is64Bit ? X86::SUB64ri8 : X86::SUB32ri8;
  const unsigned MovmrOpc = Is64Bit ? X86::MOV64mr : X86::MOV32mr;
  const unsigned MovrrOpc = Is64Bit ? X86::MOV64rr : X86::MOV32rr;
  const unsigned MovrmOpc = Is64Bit ? X86::MOV64rm : X86::MOV32rm;
  const unsigned MovriOpc = Is64Bit ? X86::MOV64ri32 : X86::MOV32ri;
  const unsigned RetOpc = Is64Bit ? X86::RETQ : X86::RETL;
  const Register StackPtr = Is64Bit ? X86::RSP : X86::ESP;
  const Register WorkReg = Is64Bit ? X86::RAX : X86::EAX;
  const unsigned RetValOffset = Is64Bit ? 8 : 4;

  if (MI.getNumOperands() == 1) {
    if (Ty == MachineOperand::MO_Register) {
      BuildMI(*MBB, MBB->erase(MI), DL, TII->get(PushOpc), Operand.getReg());
      BuildMI(&*MBB, DL, TII->get(RetOpc));
      Changed = true;
    } else {
      // push WorkReg
      BuildMI(&*MBB, DL, TII->get(PushOpc)).addReg(WorkReg);
      // lea WorkReg, Operand
      BuildMI(&*MBB, DL, TII->get(LeaOpc), WorkReg)
          .addReg(0)
          .addImm(1)
          .addReg(0)
          .add(Operand)
          .addReg(0);
      // mov [StackPtr+RetValOffset], WorkReg
      addRegOffset(BuildMI(&*MBB, DL, TII->get(MovmrOpc)), StackPtr, true,
                   RetValOffset)
          .addReg(WorkReg);
      // pop WorkReg
      BuildMI(&*MBB, DL, TII->get(PopOpc)).addReg(WorkReg);
      // ret
      BuildMI(&*MBB, DL, TII->get(RetOpc));

      // replace `jmp` instruction with `lea` for allocate stack
      // lea StackPtr, [StackPtr - RetValOffset]
      BuildMI(*MBB, MBB->erase(MI), DL, TII->get(SubOpc), StackPtr)
          .addReg(StackPtr)
          .addImm(RetValOffset);
      Changed = true;
    }
  } else {
    // push WorkReg
    BuildMI(&*MBB, DL, TII->get(PushOpc))
      .addReg(WorkReg)
      .getInstr();
    // WorkReg <- Operand
    switch (Ty) {
    case MachineOperand::MO_Register:
      // Register indirect call
      if (MI.getNumOperands() == 1) {
        Register OpReg = Operand.getReg();
        // mov WorkReg, Operand
        BuildMI(&*MBB, DL, TII->get(MovrrOpc), WorkReg).addReg(OpReg);
      } else {
        // with offset
        // lea WorkReg, Operand
        auto LeaMIB = BuildMI(&*MBB, DL, TII->get(MovrmOpc), WorkReg);
        for (unsigned i = 0; i < MI.getNumOperands(); i++)
          LeaMIB.add(MI.getOperand(i));
      }
      break;
    case MachineOperand::MO_Immediate:
      // mov WorkReg, Operand
      BuildMI(&*MBB, DL, TII->get(MovriOpc), WorkReg).add(Operand);
      break;
    case MachineOperand::MO_ExternalSymbol:
    case MachineOperand::MO_GlobalAddress:
    case MachineOperand::MO_BlockAddress:
    case MachineOperand::MO_MCSymbol:
      // lea WorkReg, Operand
      BuildMI(&*MBB, DL, TII->get(LeaOpc), WorkReg)
          .addReg(0)
          .addImm(1)
          .addReg(0)
          .add(Operand)
          .addReg(0);
      break;
    default:
      assert(1 && "The operand doesn't implemented");
      break;
    }

    // mov [StackPtr+RetValOffset], WorkReg
    addRegOffset(BuildMI(&*MBB, DL, TII->get(MovmrOpc)), StackPtr, true, RetValOffset)
      .addReg(WorkReg);
    // pop WorkReg
    BuildMI(&*MBB, DL, TII->get(PopOpc))
      .addReg(WorkReg);
    // ret
    BuildMI(&*MBB, DL, TII->get(RetOpc));

    // replace `jmp` instruction with allocate stack
    // lea StackPtr, [StackPtr - RetValOffset]
    BuildMI(*MBB, MBB->erase(MI), DL, TII->get(SubOpc), StackPtr)
        .addReg(StackPtr)
        .addImm(RetValOffset);
    Changed = true;
  }

  ++NumObfuscatedJumps;

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
  for (MachineBasicBlock &MBB : MF) {
    unsigned Index = 0;
    for (MachineBasicBlock::iterator MI = MBB.begin(), E = MBB.end(); MI != E;
         ++MI, ++Index) {
      if (!isRealInstruction(*MI) || !isObfuscatable(*MI))
        continue;
      if (isJMP(*MI))
        Changed |= ObfuscateJmpInst(MF, *MI, Index);
      if (isCALL(*MI))
        Changed |= ObfuscateCallInst(MF, *MI, Index);
    }
  }

  return Changed;
}
