//===- FuzzerMutate.h - Internal header for the Fuzzer ----------*- C++ -* ===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
// fuzzer::MutationDispatcher
//===----------------------------------------------------------------------===//

#ifndef LLVM_FUZZER_MUTATE_H
#define LLVM_FUZZER_MUTATE_H

#include "FuzzerDefs.h"
#include "FuzzerDictionary.h"
#include "FuzzerOptions.h"
#include "FuzzerRandom.h"
#include "FuzzerCorpus.h"

namespace fuzzer {

class MutationDispatcher {
public:
  MutationDispatcher(Random &Rand, const FuzzingOptions &Options);
  ~MutationDispatcher() {}
  /// Indicate that we are about to start a new sequence of mutations.
  void StartMutationSequence();
  /// Print the current sequence of mutations. Only prints the full sequence
  /// when Verbose is true.
  void PrintMutationSequence(bool Verbose = true);
  /// Return the current sequence of mutations.
  std::string MutationSequence();
  int MutationSequenceSize();
  /// Indicate that the current sequence of mutations was successful.
  void RecordSuccessfulMutationSequence();
  /// Mutates data by invoking user-provided mutator.
  size_t Mutate_Custom(uint8_t *Data, size_t Size, size_t MaxSize);
  /// Mutates data by invoking user-provided crossover.
  size_t Mutate_CustomCrossOver(uint8_t *Data, size_t Size, size_t MaxSize);
  /// Mutates data by shuffling bytes.
  size_t Mutate_ShuffleBytes(uint8_t *Data, size_t Size, size_t MaxSize);
  /// Mutates data by erasing bytes.
  size_t Mutate_EraseBytes(uint8_t *Data, size_t Size, size_t MaxSize);
  /// Mutates data by inserting a byte.
  size_t Mutate_InsertByte(uint8_t *Data, size_t Size, size_t MaxSize);
  /// Mutates data by inserting several repeated bytes.
  size_t Mutate_InsertRepeatedBytes(uint8_t *Data, size_t Size, size_t MaxSize);
  /// Mutates data by changing one byte.
  size_t Mutate_ChangeByte(uint8_t *Data, size_t Size, size_t MaxSize);
  /// Mutates data by changing one bit.
  size_t Mutate_ChangeBit(uint8_t *Data, size_t Size, size_t MaxSize);
  /// Mutates data by copying/inserting a part of data into a different place.
  size_t Mutate_CopyPart(uint8_t *Data, size_t Size, size_t MaxSize);


  // CMP Hotspot Mutations
  size_t Mutate_ReplaceHotspotHint(uint8_t *Data, size_t Size, size_t MaxSize);
  size_t Mutate_ChangeByteAroundHotspot(uint8_t *Data, size_t Size, size_t MaxSize);

  size_t Mutate_Test(uint8_t *Data, size_t Size, size_t MaxSize);

  /* ================ SYSCALL MUTATIONS =============== */

  /// Remove a System Call from the Input
  size_t Mutate_RemoveSystemCall(uint8_t *Data, size_t Size, size_t MaxSize);
  
  ///  Insert a System Call into the Input
  size_t Mutate_InsertSystemCall(uint8_t *Data, size_t Size, size_t MaxSize);
  
  ///  Remove Bytes from a System-Call
  size_t Mutate_RemoveSystemCallBytes(uint8_t *Data, size_t Size, size_t MaxSize);
  
  ///  Insert  System Call Bytes
  size_t Mutate_InsertSystemCallBytes(uint8_t *Data, size_t Size, size_t MaxSize);
  
  ///  Mutates System Call using simple bit/byte mutations
  size_t Mutate_MutateSystemCallBytes(uint8_t *Data, size_t Size, size_t MaxSize);

  /// Take two full inputs and concatenate them (do not repeat the common initial 
  /// system-calls).
  size_t Mutate_CrossOverInputs(uint8_t *Data, size_t Size, size_t MaxSize);
  
  /// Crossover a syscall with another syscall of the same type
  size_t Mutate_CrossOverSyscalls(uint8_t *Data, size_t Size, size_t MaxSize);

  /// Mutates data by adding a word from the manual dictionary.
  size_t Mutate_AddWordFromManualDictionary(uint8_t *Data, size_t Size,
                                            size_t MaxSize);

  /// Mutates data by adding a word from the TORC.
  size_t Mutate_AddWordFromTORC(uint8_t *Data, size_t Size, size_t MaxSize);

  /// Mutates data by adding a word from the persistent automatic dictionary.
  size_t Mutate_AddWordFromPersistentAutoDictionary(uint8_t *Data, size_t Size,
                                                    size_t MaxSize);

  /// Tries to find an ASCII integer in Data, changes it to another ASCII int.
  size_t Mutate_ChangeASCIIInteger(uint8_t *Data, size_t Size, size_t MaxSize);
  /// Change a 1-, 2-, 4-, or 8-byte integer in interesting ways.
  size_t Mutate_ChangeBinaryInteger(uint8_t *Data, size_t Size, size_t MaxSize);

  /// CrossOver Data with CrossOverWith.
  size_t Mutate_CrossOver(uint8_t *Data, size_t Size, size_t MaxSize);

  /// Applies one of the configured mutations.
  /// Returns the new size of data which could be up to MaxSize.
  size_t Mutate(uint8_t *Data, size_t Size, size_t MaxSize);

  /// Applies one of the configured mutations to the bytes of Data
  /// that have '1' in Mask.
  /// Mask.size() should be >= Size.
  size_t MutateWithMask(uint8_t *Data, size_t Size, size_t MaxSize,
                        const std::vector<uint8_t> &Mask);

  /// Applies one of the default mutations. Provided as a service
  /// to mutation authors.
  size_t DefaultMutate(uint8_t *Data, size_t Size, size_t MaxSize);

  /// Creates a cross-over of two pieces of Data, returns its size.
  size_t CrossOver(const uint8_t *Data1, size_t Size1, const uint8_t *Data2,
                   size_t Size2, uint8_t *Out, size_t MaxOutSize);

  /* ================ VMCS OP MUTATIONS =============== */

  size_t Mutate_RemoveOp(uint8_t *Data, size_t Size, size_t MaxSize);
  size_t Mutate_InsertOp(uint8_t *Data, size_t Size, size_t MaxSize);
  size_t Mutate_RemoveOpBytes(uint8_t *Data, size_t Size, size_t MaxSize);
  size_t Mutate_InsertOpBytes(uint8_t *Data, size_t Size, size_t MaxSize);
  size_t Mutate_MutateOpBytes(uint8_t *Data, size_t Size, size_t MaxSize);
  size_t Mutate_CrossOverOps(uint8_t *Data, size_t Size, size_t MaxSize);

  void AddWordToManualDictionary(const Word &W);

  void PrintRecommendedDictionary();

  void SetCrossOverWith(const Unit *U) { CrossOverWith = U; }

  void SetBaseII(const InputInfo *II) { OurBaseII  = II; }

  Random &GetRand() { return Rand; }

  uint16_t LastChangedIdx;

 private:
  struct Mutator {
    size_t (MutationDispatcher::*Fn)(uint8_t *Data, size_t Size, size_t Max);
    const char *Name;
  };

  size_t AddWordFromDictionary(Dictionary &D, uint8_t *Data, size_t Size,
                               size_t MaxSize);
  void TestSyscallMutateImpl(uint8_t *Data, size_t Size,
          size_t MaxSize);
  size_t SyscallMutateImpl(uint8_t *Data, size_t Size, size_t MaxSize);
  size_t VmcsMutateImpl(uint8_t *Data, size_t Size, size_t MaxSize);
  size_t MutateImpl(uint8_t *Data, size_t Size, size_t MaxSize,
                    std::vector<Mutator> &Mutators);

  size_t InsertPartOf(const uint8_t *From, size_t FromSize, uint8_t *To,
                      size_t ToSize, size_t MaxToSize);
  size_t CopyPartOf(const uint8_t *From, size_t FromSize, uint8_t *To,
                    size_t ToSize);
  size_t ApplyDictionaryEntry(uint8_t *Data, size_t Size, size_t MaxSize,
                              DictionaryEntry &DE);

  template <class T>
  DictionaryEntry MakeDictionaryEntryFromCMP(T Arg1, T Arg2,
                                             const uint8_t *Data, size_t Size);
  DictionaryEntry MakeDictionaryEntryFromCMP(const Word &Arg1, const Word &Arg2,
                                             const uint8_t *Data, size_t Size);
  DictionaryEntry MakeDictionaryEntryFromCMP(const void *Arg1, const void *Arg2,
                                             const void *Arg1Mutation,
                                             const void *Arg2Mutation,
                                             size_t ArgSize,
                                             const uint8_t *Data, size_t Size);

  Random &Rand;
  const FuzzingOptions Options;

  // Dictionary provided by the user via -dict=DICT_FILE.
  Dictionary ManualDictionary;
  // Persistent dictionary modified by the fuzzer, consists of
  // entries that led to successful discoveries in the past mutations.
  Dictionary PersistentAutoDictionary;

  std::vector<DictionaryEntry *> CurrentDictionaryEntrySequence;

  static const size_t kCmpDictionaryEntriesDequeSize = 16;
  DictionaryEntry CmpDictionaryEntriesDeque[kCmpDictionaryEntriesDequeSize];
  size_t CmpDictionaryEntriesDequeIdx = 0;

  const Unit *CrossOverWith = nullptr;
  const InputInfo *OurBaseII = nullptr;
  std::vector<uint8_t> MutateInPlaceHere;
  std::vector<uint8_t> MutateWithMaskTemp;
  // CustomCrossOver needs its own buffer as a custom implementation may call
  // LLVMFuzzerMutate, which in turn may resize MutateInPlaceHere.
  std::vector<uint8_t> CustomCrossOverInPlaceHere;

  std::vector<Mutator> Mutators;
  std::vector<Mutator> DefaultMutators;
  std::vector<Mutator> CurrentMutatorSequence;
  
  std::vector<Mutator> NonDestructiveMutators;
  std::vector<Mutator> DestructiveMutators;
  std::vector<Mutator> VmcsMutators;

};

}  // namespace fuzzer

#endif  // LLVM_FUZZER_MUTATE_H
