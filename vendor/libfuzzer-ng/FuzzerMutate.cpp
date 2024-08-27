//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
// Mutate a test input.
//===----------------------------------------------------------------------===//

#include "FuzzerDefs.h"
#include "FuzzerExtFunctions.h"
#include "FuzzerIO.h"
#include "FuzzerMutate.h"
#include "FuzzerOptions.h"
#include "FuzzerTracePC.h"
#include "FuzzerCorpus.h"
#include "FuzzerInternal.h"

namespace fuzzer {

extern Fuzzer *F;
const size_t Dictionary::kMaxDictSize;
static const size_t kMaxMutationsToPrint = 10;

static void PrintASCII(const Word &W, const char *PrintAfter) {
  PrintASCII(W.data(), W.size(), PrintAfter);
}

MutationDispatcher::MutationDispatcher(Random &Rand,
                                       const FuzzingOptions &Options)
    : Rand(Rand), Options(Options) {
  DefaultMutators.insert(
      DefaultMutators.begin(),
      {
          // Erase System-call - Ez
          // Insert System-call
          // Remove System-call bytes - Ez
          // Mutate System-Call CFU Bytes -Ez
          // Mutate System-Call Argument Bytes -Ez
          // Crossover Inputs (Combine system-calls)
          // Crossover Inputs (Combine two CFU Parts)
          // Hotspot Hints
          {&MutationDispatcher::Mutate_EraseBytes, "EraseBytes"},
          {&MutationDispatcher::Mutate_InsertByte, "InsertByte"},
          {&MutationDispatcher::Mutate_InsertRepeatedBytes,
           "InsertRepeatedBytes"},
          {&MutationDispatcher::Mutate_ChangeByte, "ChangeByte"},
          {&MutationDispatcher::Mutate_ChangeBit, "ChangeBit"},
          {&MutationDispatcher::Mutate_ShuffleBytes, "ShuffleBytes"},
          {&MutationDispatcher::Mutate_ChangeASCIIInteger, "ChangeASCIIInt"},
          {&MutationDispatcher::Mutate_ChangeBinaryInteger, "ChangeBinInt"},
          {&MutationDispatcher::Mutate_CopyPart, "CopyPart"},
          {&MutationDispatcher::Mutate_CrossOver, "CrossOver"},
          {&MutationDispatcher::Mutate_AddWordFromManualDictionary,
           "ManualDict"},
          {&MutationDispatcher::Mutate_AddWordFromPersistentAutoDictionary,
           "PersAutoDict"},

           {&MutationDispatcher::Mutate_ReplaceHotspotHint,
           "ReplaceHotspot"},
           /* {&MutationDispatcher::Mutate_ChangeByteAroundHotspot, */
           /* "FlipHotspotBits"}, */
      });
  DestructiveMutators.insert(
      DestructiveMutators.begin(),
      {
          /* {&MutationDispatcher::Mutate_RemoveSystemCall, "RemoveSystemCall"}, */
          /* {&MutationDispatcher::Mutate_InsertSystemCall, "InsertSystemCall"}, */
          /* {&MutationDispatcher::Mutate_InsertSystemCallBytes, "InsertSystemCallBytes"}, */
          /* {&MutationDispatcher::Mutate_RemoveSystemCallBytes, "RemoveSystemCallBytes"}, */
          /* {&MutationDispatcher::Mutate_EraseBytes, "EraseBytes"}, */
          {&MutationDispatcher::Mutate_RemoveOp, "RemoveOp"},
          {&MutationDispatcher::Mutate_InsertOp, "InsertOp"},
          {&MutationDispatcher::Mutate_InsertOpBytes, "InsertOpBytes"},
          {&MutationDispatcher::Mutate_RemoveOpBytes, "RemoveOpBytes"},
          {&MutationDispatcher::Mutate_EraseBytes, "EraseBytes"},
      });
  VmcsMutators.insert(
      VmcsMutators.begin(),
      {
           {&MutationDispatcher::Mutate_ReplaceHotspotHint,
           "ReplaceHotspot"},
          {&MutationDispatcher::Mutate_MutateOpBytes, "MutateOp"},
          // {&MutationDispatcher::Mutate_CrossOverOps, "CrossOverOp"},
          /* {&MutationDispatcher::Mutate_CrossOver, "CrossOver"}, */
           {&MutationDispatcher::Mutate_ChangeByteAroundHotspot,
           "FlipHotspotBits"},
      });
  
  if(Options.UseCmp) {
    DefaultMutators.push_back(
        {&MutationDispatcher::Mutate_AddWordFromTORC, "CMP"});
    DestructiveMutators.push_back(
        {&MutationDispatcher::Mutate_AddWordFromTORC, "CMP"});
  }

  if (EF->LLVMFuzzerCustomMutator)
    Mutators.push_back({&MutationDispatcher::Mutate_Custom, "Custom"});
  else
    Mutators = DefaultMutators;

  if (EF->LLVMFuzzerCustomCrossOver)
    Mutators.push_back(
        {&MutationDispatcher::Mutate_CustomCrossOver, "CustomCrossOver"});
}

static char RandCh(Random &Rand) {
  if (Rand.RandBool())
    return static_cast<char>(Rand(256));
  const char Special[] = "!*'();:@&=+$,/?%#[]012Az-`~.\xff\x00";
  return Special[Rand(sizeof(Special) - 1)];
}

size_t MutationDispatcher::Mutate_Custom(uint8_t *Data, size_t Size,
                                         size_t MaxSize) {
  if (EF->__msan_unpoison)
    EF->__msan_unpoison(Data, Size);
  if (EF->__msan_unpoison_param)
    EF->__msan_unpoison_param(4);
  return EF->LLVMFuzzerCustomMutator(Data, Size, MaxSize,
                                     Rand.Rand<unsigned int>());
}

/* =============== Fuzzer Mutation =================== */
//#ifdef FUZZMUT
#define SEPARATOR "FUZZ"
bool op_log_tainted = false;

size_t MutationDispatcher::Mutate_RemoveSystemCall(uint8_t *Data, size_t Size,
                                                  size_t MaxSize) {
    if(!OurBaseII || !OurBaseII->InputSyscalls.size()) {
        return 0;
    }
    int n_syscalls = OurBaseII->InputSyscalls.size();
    if(n_syscalls < 2)
        return 0;
    int remove = Rand(n_syscalls);

    size_t Idx = OurBaseII->InputSyscalls[remove]->start;
    size_t N = OurBaseII->InputSyscalls[remove]->len;

    if(Size < Idx + N)
        return 0;
    memmove(Data + Idx, Data + Idx + N, Size - Idx - N);

    return Size - N;
}

size_t MutationDispatcher::Mutate_InsertSystemCall(uint8_t *Data, size_t Size,
                                                  size_t MaxSize) {
    size_t Idx;
    size_t N = MaxSize - Size;
    if(N < 5)
        return 0;
    if(OurBaseII && OurBaseII->InputSyscalls.size()) {
        int n_syscalls = OurBaseII->InputSyscalls.size();
        int insert = biased_rand(n_syscalls+1, 5, Rand);
        // If 0, insert the syscall before everything else
        if(insert == 0) {
            Idx = 0;
        } else {
            insert--;
            Idx = OurBaseII->InputSyscalls[insert]->start + OurBaseII->InputSyscalls[insert]->len;
        }

    } else {
        Idx = Rand(Size);
    }
    //printf("Insert: idx %lx n %lx Size %lx maxsize %lx\n", Idx, N, Size, MaxSize);
    if(Size < Idx+N)
        return 0;
    memmove(Data + Idx + N, Data + Idx, Size - Idx);
    if(Idx) {
        memcpy(Data + Idx, SEPARATOR, 4);
    } else {
        memcpy(Data + N - 4, SEPARATOR, 4);
    }

    uint8_t Byte = Rand(256);
    size_t i = Idx ? 4 : 0;
    for (; i < N; i++)
        Data[Idx + i] = Rand(256);

    size_t NewSize = Size + N;
    return NewSize;
}

size_t MutationDispatcher::Mutate_RemoveSystemCallBytes(uint8_t *Data, size_t Size,
                                                  size_t MaxSize) {
    if(!OurBaseII || !OurBaseII->InputSyscalls.size()) {
        return 0;
    }
    int n_syscalls = OurBaseII->InputSyscalls.size();
    int sc = biased_rand(n_syscalls, 5, Rand);

    size_t Idx = OurBaseII->InputSyscalls[sc]->start 
        + biased_rand(OurBaseII->InputSyscalls[sc]->len, 3, Rand);
    size_t N = biased_rand(OurBaseII->InputSyscalls[sc]->len - 
                                (Idx - OurBaseII->InputSyscalls[sc]->start),
                           5, Rand);
    
    if(Size < Idx + N)
        return 0;
    
    memmove(Data + Idx, Data + Idx + N, Size - Idx - N);

    return Size - N;
}

size_t MutationDispatcher::Mutate_InsertSystemCallBytes(uint8_t *Data, size_t Size,
                                                  size_t MaxSize) {
    if(!OurBaseII || !OurBaseII->InputSyscalls.size()) {
        return 0;
    }
    int n_syscalls = OurBaseII->InputSyscalls.size();
    int sc = biased_rand(n_syscalls, 5, Rand);
    
    size_t Idx = OurBaseII->InputSyscalls[sc]->start 
        + biased_rand(OurBaseII->InputSyscalls[sc]->len, 3, Rand);
    size_t N = Rand(MaxSize-Size);
    
    if(MaxSize < Idx + N)
        return 0;
    
    if(Size <= Idx)
        return 0;
    
    memmove(Data + Idx + N, Data + Idx, Size - Idx);

    for(int i =0; i< N; i++){
        Data[Idx + N] = Rand(256);
    }
    return Size + N;
}
size_t MutationDispatcher::Mutate_MutateSystemCallBytes(uint8_t *Data, size_t Size,
                                                  size_t MaxSize) {
    if(!OurBaseII || !OurBaseII->InputSyscalls.size()) {
        return 0;
    }
    // Pick a system call (towards the end)
    int n_syscalls = OurBaseII->InputSyscalls.size();
    int sc_idx = biased_rand(n_syscalls, 5, Rand);

    auto sc = OurBaseII->InputSyscalls[sc_idx];

    size_t BeginMutate = sc->start;
    size_t MutateLen = sc->len;

    /* Printf("n_syscalls: %ld sc_idx: %ld MaxSize: %ld BeginMutate: %ld MutateLen:\n", n_syscalls, sc_idx, MaxSize, BeginMutate, MutateLen); */
    if(MaxSize < BeginMutate + MutateLen)
        return 0;
    // Look for a separator and only fuzz after it (avoid messing with syscall
    // arguments too much).
    if((Rand()%5) < 4 && MutateLen > 1)  {
        uint8_t *found = (uint8_t*) memmem(Data + BeginMutate + 1, MutateLen, SEPARATOR, 4);
        if(found) {
            MutateLen -= (found - Data) - BeginMutate;
            BeginMutate = found - Data;
            // If we have enough space, advance past the separator
            if(MutateLen > 4){
                MutateLen-=4;
                BeginMutate+=4;
            }
        }
    }
    /* Printf("Mutating: %ld MutateLen:\n", BeginMutate, MutateLen); */
    int iters = Rand(3)+1;
    for(int i=0; i<iters; i++) {
        switch (Rand()%4){
            case 0:
                Mutate_ShuffleBytes(Data + BeginMutate, MutateLen, MutateLen);
                break;
            case 1:
                Mutate_ChangeByte(Data + BeginMutate, MutateLen, MutateLen);
                break;
            case 2:
                Mutate_ChangeBit(Data + BeginMutate, MutateLen,  MutateLen);
                break;
            case 3:
                Mutate_ChangeBinaryInteger(Data + BeginMutate, MutateLen, MutateLen);
                break;
        }
    }
    return Size;
} 
size_t MutationDispatcher::Mutate_CrossOverInputs(uint8_t *Data, size_t Size,
                                                  size_t MaxSize) {
    return Size;
}

// Does not change the size of the input
size_t MutationDispatcher::Mutate_CrossOverSyscalls(uint8_t *Data, size_t Size,
                                                  size_t MaxSize) {
    if(!OurBaseII || !OurBaseII->InputSyscalls.size()) {
        return 0;
    }
    int n_syscalls = OurBaseII->InputSyscalls.size();
    int sc_idx = biased_rand(n_syscalls, 5, Rand);

    auto sc = OurBaseII->InputSyscalls[sc_idx];
    auto xc = F->Corpus.FindSimilarSyscall(sc, Rand);
    if(!xc)
        return 0;
    
    if(!xc->II || !xc->II->U.data())
        return 0;

    // Weigh the cross-over to the later part of the system-call
    if(Rand(2)) {
        size_t ToBeg = sc->start + biased_rand(sc->len, 2, Rand);
        size_t CopySize = Rand(sc->len + (sc->start-ToBeg)) + 1;
        size_t FromBeg;
        if(Rand(2) && ToBeg - sc->start < xc->len) {
            FromBeg = ToBeg - sc->start + xc->start;
        } else {
            FromBeg = Rand(biased_rand(xc->len, 2, Rand));
        }
        CopySize = std::min(CopySize, xc->len - (FromBeg-xc->start));
        /* Printf("FromBeg: %ld FromSC: %d %d FromLen: %d CopySize: %d\n", FromBeg, xc->start, xc->len, xc->II->U.size(), CopySize); */
        if(MaxSize < ToBeg + CopySize || FromBeg + CopySize > xc->II->U.size())
            return 0;
        memcpy(Data + ToBeg, xc->II->U.data() + FromBeg, CopySize);
    } else { // Random Crossover (from built-in libfuzzer mutations)
        if(sc->start + sc->len > MaxSize || xc->start + xc->len > xc->II->U.size())
            return 0;
        CopyPartOf(xc->II->U.data() + xc->start,
                xc->len,
                Data + sc->start,
                sc->len);
    }
    return Size;
}
//#endif // FUZMUT

size_t MutationDispatcher::Mutate_CustomCrossOver(uint8_t *Data, size_t Size,
                                                  size_t MaxSize) {
  if (Size == 0)
    return 0;
  if (!CrossOverWith) return 0;
  const Unit &Other = *CrossOverWith;
  if (Other.empty())
    return 0;
  CustomCrossOverInPlaceHere.resize(MaxSize);
  auto &U = CustomCrossOverInPlaceHere;

  if (EF->__msan_unpoison) {
    EF->__msan_unpoison(Data, Size);
    EF->__msan_unpoison(Other.data(), Other.size());
    EF->__msan_unpoison(U.data(), U.size());
  }
  if (EF->__msan_unpoison_param)
    EF->__msan_unpoison_param(7);
  size_t NewSize = EF->LLVMFuzzerCustomCrossOver(
      Data, Size, Other.data(), Other.size(), U.data(), U.size(),
      Rand.Rand<unsigned int>());

  if (!NewSize)
    return 0;
  assert(NewSize <= MaxSize && "CustomCrossOver returned overisized unit");
  memcpy(Data, U.data(), NewSize);
  return NewSize;
}

size_t MutationDispatcher::Mutate_ShuffleBytes(uint8_t *Data, size_t Size,
                                               size_t MaxSize) {
  if (Size > MaxSize || Size == 0) return 0;
  size_t ShuffleAmount =
      Rand(std::min(Size, (size_t)8)) + 1; // [1,8] and <= Size.
  size_t ShuffleStart = Rand(Size - ShuffleAmount);
  assert(ShuffleStart + ShuffleAmount <= Size);
  std::shuffle(Data + ShuffleStart, Data + ShuffleStart + ShuffleAmount, Rand);
  return Size;
}

size_t MutationDispatcher::Mutate_EraseBytes(uint8_t *Data, size_t Size,
                                             size_t MaxSize) {
  if (Size <= 1) return 0;
  size_t N = Rand(Size / 2) + 1;
  assert(N < Size);
  size_t Idx = Rand(Size - N + 1);
  // Erase Data[Idx:Idx+N].
  memmove(Data + Idx, Data + Idx + N, Size - Idx - N);
  // Printf("Erase: %zd %zd => %zd; Idx %zd\n", N, Size, Size - N, Idx);
  return Size - N;
}

size_t MutationDispatcher::Mutate_InsertByte(uint8_t *Data, size_t Size,
                                             size_t MaxSize) {
  if (Size >= MaxSize) return 0;
  size_t Idx = Rand(Size + 1);
  // Insert new value at Data[Idx].
  memmove(Data + Idx + 1, Data + Idx, Size - Idx);
  Data[Idx] = RandCh(Rand);
  return Size + 1;
}

size_t MutationDispatcher::Mutate_InsertRepeatedBytes(uint8_t *Data,
                                                      size_t Size,
                                                      size_t MaxSize) {
  const size_t kMinBytesToInsert = 3;
  if (Size + kMinBytesToInsert >= MaxSize) return 0;
  size_t MaxBytesToInsert = std::min(MaxSize - Size, (size_t)128);
  size_t N = Rand(MaxBytesToInsert - kMinBytesToInsert + 1) + kMinBytesToInsert;
  assert(Size + N <= MaxSize && N);
  size_t Idx = Rand(Size + 1);
  // Insert new values at Data[Idx].
  memmove(Data + Idx + N, Data + Idx, Size - Idx);
  // Give preference to 0x00 and 0xff.
  uint8_t Byte = static_cast<uint8_t>(
      Rand.RandBool() ? Rand(256) : (Rand.RandBool() ? 0 : 255));
  for (size_t i = 0; i < N; i++)
    Data[Idx + i] = Byte;
  return Size + N;
}

size_t MutationDispatcher::Mutate_ChangeByte(uint8_t *Data, size_t Size,
                                             size_t MaxSize) {
  if (Size > MaxSize) return 0;
  size_t Idx = Rand(Size);
  LastChangedIdx = Idx;
  Data[Idx] = RandCh(Rand);
  return Size;
}

size_t MutationDispatcher::Mutate_ChangeBit(uint8_t *Data, size_t Size,
                                            size_t MaxSize) {
  if (Size > MaxSize) return 0;
  size_t Idx = Rand(Size);
  LastChangedIdx = Idx;
  Data[Idx] ^= 1 << Rand(8);
  return Size;
}


size_t MutationDispatcher::Mutate_ReplaceHotspotHint(uint8_t *Data, size_t Size,
                                            size_t MaxSize) {
    if(OurBaseII->HotSpots.size() == 0) {
        return 0;
    }
    //printf("Hotspot &II = %p %lx\n", OurBaseII, OurBaseII->HotSpots.size());
    auto *II = OurBaseII;
    size_t i = Rand(II->HotSpots.size());
    auto &h = II->HotSpots[i];

    if(h.pos + h.size > Size || h.hint == 0)
        return 0;
    //if(h.size > 4)
        //printf("Replacing %lx at %lx\n", h.size, h.pos);
    memcpy(Data + h.pos, &h.hint, h.size);
    return Size;
}

size_t MutationDispatcher::Mutate_ChangeByteAroundHotspot(uint8_t *Data, size_t Size,
                                            size_t MaxSize) {

    if(!OurBaseII || !OurBaseII->HotSpots.size()) {
        return 0;
    }
    size_t i = Rand(OurBaseII->HotSpots.size());
    auto &h = OurBaseII->HotSpots[i];

    size_t pos = (h.pos + Rand(h.size));
    size_t offset = (4-(biased_rand(5, 5, Rand))) *(Rand(3)-1);
    if((int)offset + int(pos) > 0) {
        pos += offset;
    }
    if(pos >= Size)
        return 0;
    Data[pos] = Rand(256);

    return Size;
}

size_t MutationDispatcher::Mutate_AddWordFromManualDictionary(uint8_t *Data,
                                                              size_t Size,
                                                              size_t MaxSize) {
  return AddWordFromDictionary(ManualDictionary, Data, Size, MaxSize);
}

size_t MutationDispatcher::ApplyDictionaryEntry(uint8_t *Data, size_t Size,
                                                size_t MaxSize,
                                                DictionaryEntry &DE) {
  const Word &W = DE.GetW();
  bool UsePositionHint = DE.HasPositionHint() &&
                         DE.GetPositionHint() + W.size() < Size &&
                         Rand.RandBool();
  if (Rand.RandBool()) {  // Insert W.
    if (Size + W.size() > MaxSize) return 0;
    size_t Idx = UsePositionHint ? DE.GetPositionHint() : Rand(Size + 1);
    memmove(Data + Idx + W.size(), Data + Idx, Size - Idx);
    memcpy(Data + Idx, W.data(), W.size());
    Size += W.size();
  } else {  // Overwrite some bytes with W.
    if (W.size() > Size) return 0;
    size_t Idx =
        UsePositionHint ? DE.GetPositionHint() : Rand(Size + 1 - W.size());
    memcpy(Data + Idx, W.data(), W.size());
  }
  return Size;
}

// Somewhere in the past we have observed a comparison instructions
// with arguments Arg1 Arg2. This function tries to guess a dictionary
// entry that will satisfy that comparison.
// It first tries to find one of the arguments (possibly swapped) in the
// input and if it succeeds it creates a DE with a position hint.
// Otherwise it creates a DE with one of the arguments w/o a position hint.
DictionaryEntry MutationDispatcher::MakeDictionaryEntryFromCMP(
    const void *Arg1, const void *Arg2,
    const void *Arg1Mutation, const void *Arg2Mutation,
    size_t ArgSize, const uint8_t *Data,
    size_t Size) {
  bool HandleFirst = Rand.RandBool();
  const void *ExistingBytes, *DesiredBytes;
  Word W;
  const uint8_t *End = Data + Size;
  for (int Arg = 0; Arg < 2; Arg++) {
    ExistingBytes = HandleFirst ? Arg1 : Arg2;
    DesiredBytes = HandleFirst ? Arg2Mutation : Arg1Mutation;
    HandleFirst = !HandleFirst;
    W.Set(reinterpret_cast<const uint8_t*>(DesiredBytes), ArgSize);
    const size_t kMaxNumPositions = 8;
    size_t Positions[kMaxNumPositions];
    size_t NumPositions = 0;
    for (const uint8_t *Cur = Data;
         Cur < End && NumPositions < kMaxNumPositions; Cur++) {
      Cur =
          (const uint8_t *)SearchMemory(Cur, End - Cur, ExistingBytes, ArgSize);
      if (!Cur) break;
      Positions[NumPositions++] = Cur - Data;
    }
    if (!NumPositions) continue;
    return DictionaryEntry(W, Positions[Rand(NumPositions)]);
  }
  DictionaryEntry DE(W);
  return DE;
}


template <class T>
DictionaryEntry MutationDispatcher::MakeDictionaryEntryFromCMP(
    T Arg1, T Arg2, const uint8_t *Data, size_t Size) {
  if (Rand.RandBool()) Arg1 = Bswap(Arg1);
  if (Rand.RandBool()) Arg2 = Bswap(Arg2);
  T Arg1Mutation = static_cast<T>(Arg1 + Rand(-1, 1));
  T Arg2Mutation = static_cast<T>(Arg2 + Rand(-1, 1));
  return MakeDictionaryEntryFromCMP(&Arg1, &Arg2, &Arg1Mutation, &Arg2Mutation,
                                    sizeof(Arg1), Data, Size);
}

DictionaryEntry MutationDispatcher::MakeDictionaryEntryFromCMP(
    const Word &Arg1, const Word &Arg2, const uint8_t *Data, size_t Size) {
  return MakeDictionaryEntryFromCMP(Arg1.data(), Arg2.data(), Arg1.data(),
                                    Arg2.data(), Arg1.size(), Data, Size);
}

size_t MutationDispatcher::Mutate_AddWordFromTORC(
    uint8_t *Data, size_t Size, size_t MaxSize) {
  Word W;
  DictionaryEntry DE;
  switch (Rand(4)) {
  case 0: {
    auto X = TPC.TORC8.Get(Rand.Rand<size_t>());
    DE = MakeDictionaryEntryFromCMP(X.A, X.B, Data, Size);
  } break;
  case 1: {
    auto X = TPC.TORC4.Get(Rand.Rand<size_t>());
    if ((X.A >> 16) == 0 && (X.B >> 16) == 0 && Rand.RandBool())
      DE = MakeDictionaryEntryFromCMP((uint16_t)X.A, (uint16_t)X.B, Data, Size);
    else
      DE = MakeDictionaryEntryFromCMP(X.A, X.B, Data, Size);
  } break;
  case 2: {
    auto X = TPC.TORCW.Get(Rand.Rand<size_t>());
    DE = MakeDictionaryEntryFromCMP(X.A, X.B, Data, Size);
  } break;
  case 3: if (Options.UseMemmem) {
      auto X = TPC.MMT.Get(Rand.Rand<size_t>());
      DE = DictionaryEntry(X);
  } break;
  default:
    assert(0);
  }
  if (!DE.GetW().size()) return 0;
  Size = ApplyDictionaryEntry(Data, Size, MaxSize, DE);
  if (!Size) return 0;
  DictionaryEntry &DERef =
      CmpDictionaryEntriesDeque[CmpDictionaryEntriesDequeIdx++ %
                                kCmpDictionaryEntriesDequeSize];
  DERef = DE;
  CurrentDictionaryEntrySequence.push_back(&DERef);
  return Size;
}

size_t MutationDispatcher::Mutate_AddWordFromPersistentAutoDictionary(
    uint8_t *Data, size_t Size, size_t MaxSize) {
  return AddWordFromDictionary(PersistentAutoDictionary, Data, Size, MaxSize);
}

size_t MutationDispatcher::AddWordFromDictionary(Dictionary &D, uint8_t *Data,
                                                 size_t Size, size_t MaxSize) {
  if (Size > MaxSize) return 0;
  if (D.empty()) return 0;
  DictionaryEntry &DE = D[Rand(D.size())];
  Size = ApplyDictionaryEntry(Data, Size, MaxSize, DE);
  if (!Size) return 0;
  DE.IncUseCount();
  CurrentDictionaryEntrySequence.push_back(&DE);
  return Size;
}

// Overwrites part of To[0,ToSize) with a part of From[0,FromSize).
// Returns ToSize.
size_t MutationDispatcher::CopyPartOf(const uint8_t *From, size_t FromSize,
                                      uint8_t *To, size_t ToSize) {
  // Copy From[FromBeg, FromBeg + CopySize) into To[ToBeg, ToBeg + CopySize).
  size_t ToBeg = Rand(ToSize);
  size_t CopySize = Rand(ToSize - ToBeg) + 1;
  assert(ToBeg + CopySize <= ToSize);
  CopySize = std::min(CopySize, FromSize);
  size_t FromBeg = Rand(FromSize - CopySize + 1);
  assert(FromBeg + CopySize <= FromSize);
  memmove(To + ToBeg, From + FromBeg, CopySize);
  return ToSize;
}

// Inserts part of From[0,ToSize) into To.
// Returns new size of To on success or 0 on failure.
size_t MutationDispatcher::InsertPartOf(const uint8_t *From, size_t FromSize,
                                        uint8_t *To, size_t ToSize,
                                        size_t MaxToSize) {
  if (ToSize >= MaxToSize) return 0;
  size_t AvailableSpace = MaxToSize - ToSize;
  size_t MaxCopySize = std::min(AvailableSpace, FromSize);
  size_t CopySize = Rand(MaxCopySize) + 1;
  size_t FromBeg = Rand(FromSize - CopySize + 1);
  assert(FromBeg + CopySize <= FromSize);
  size_t ToInsertPos = Rand(ToSize + 1);
  assert(ToInsertPos + CopySize <= MaxToSize);
  size_t TailSize = ToSize - ToInsertPos;
  if (To == From) {
    MutateInPlaceHere.resize(MaxToSize);
    memcpy(MutateInPlaceHere.data(), From + FromBeg, CopySize);
    memmove(To + ToInsertPos + CopySize, To + ToInsertPos, TailSize);
    memmove(To + ToInsertPos, MutateInPlaceHere.data(), CopySize);
  } else {
    memmove(To + ToInsertPos + CopySize, To + ToInsertPos, TailSize);
    memmove(To + ToInsertPos, From + FromBeg, CopySize);
  }
  return ToSize + CopySize;
}

size_t MutationDispatcher::Mutate_CopyPart(uint8_t *Data, size_t Size,
                                           size_t MaxSize) {
  if (Size > MaxSize || Size == 0) return 0;
  // If Size == MaxSize, `InsertPartOf(...)` will
  // fail so there's no point using it in this case.
  if (Size == MaxSize || Rand.RandBool())
    return CopyPartOf(Data, Size, Data, Size);
  else
    return InsertPartOf(Data, Size, Data, Size, MaxSize);
}

size_t MutationDispatcher::Mutate_ChangeASCIIInteger(uint8_t *Data, size_t Size,
                                                     size_t MaxSize) {
  if (Size > MaxSize) return 0;
  size_t B = Rand(Size);
  while (B < Size && !isdigit(Data[B])) B++;
  if (B == Size) return 0;
  size_t E = B;
  while (E < Size && isdigit(Data[E])) E++;
  assert(B < E);
  // now we have digits in [B, E).
  // strtol and friends don't accept non-zero-teminated data, parse it manually.
  uint64_t Val = Data[B] - '0';
  for (size_t i = B + 1; i < E; i++)
    Val = Val * 10 + Data[i] - '0';

  // Mutate the integer value.
  switch(Rand(5)) {
    case 0: Val++; break;
    case 1: Val--; break;
    case 2: Val /= 2; break;
    case 3: Val *= 2; break;
    case 4: Val = Rand(Val * Val); break;
    default: assert(0);
  }
  // Just replace the bytes with the new ones, don't bother moving bytes.
  for (size_t i = B; i < E; i++) {
    size_t Idx = E + B - i - 1;
    assert(Idx >= B && Idx < E);
    Data[Idx] = (Val % 10) + '0';
    Val /= 10;
  }
  return Size;
}

template<class T>
size_t ChangeBinaryInteger(uint8_t *Data, size_t Size, Random &Rand) {
  if (Size < sizeof(T)) return 0;
  size_t Off = Rand(Size - sizeof(T) + 1);
  assert(Off + sizeof(T) <= Size);
  T Val;
  if (Off < 64 && !Rand(4)) {
    Val = static_cast<T>(Size);
    if (Rand.RandBool())
      Val = Bswap(Val);
  } else {
    memcpy(&Val, Data + Off, sizeof(Val));
    T Add = static_cast<T>(Rand(21));
    Add -= 10;
    if (Rand.RandBool())
      Val = Bswap(T(Bswap(Val) + Add)); // Add assuming different endiannes.
    else
      Val = Val + Add;               // Add assuming current endiannes.
    if (Add == 0 || Rand.RandBool()) // Maybe negate.
      Val = -Val;
  }
  memcpy(Data + Off, &Val, sizeof(Val));
  return Size;
}

size_t MutationDispatcher::Mutate_ChangeBinaryInteger(uint8_t *Data,
                                                      size_t Size,
                                                      size_t MaxSize) {
  if (Size > MaxSize) return 0;
  switch (Rand(4)) {
    case 3: return ChangeBinaryInteger<uint64_t>(Data, Size, Rand);
    case 2: return ChangeBinaryInteger<uint32_t>(Data, Size, Rand);
    case 1: return ChangeBinaryInteger<uint16_t>(Data, Size, Rand);
    case 0: return ChangeBinaryInteger<uint8_t>(Data, Size, Rand);
    default: assert(0);
  }
  return 0;
}

size_t MutationDispatcher::Mutate_CrossOver(uint8_t *Data, size_t Size,
                                            size_t MaxSize) {
  if (Size > MaxSize) return 0;
  if (Size == 0) return 0;
  if (!CrossOverWith) return 0;
  const Unit &O = *CrossOverWith;
  if (O.empty()) return 0;
  size_t NewSize = 0;
  switch(Rand(3)) {
    case 0:
      MutateInPlaceHere.resize(MaxSize);
      NewSize = CrossOver(Data, Size, O.data(), O.size(),
                          MutateInPlaceHere.data(), MaxSize);
      memcpy(Data, MutateInPlaceHere.data(), NewSize);
      break;
    case 1:
      NewSize = InsertPartOf(O.data(), O.size(), Data, Size, MaxSize);
      if (!NewSize)
        NewSize = CopyPartOf(O.data(), O.size(), Data, Size);
      break;
    case 2:
      NewSize = CopyPartOf(O.data(), O.size(), Data, Size);
      break;
    default: assert(0);
  }
  assert(NewSize > 0 && "CrossOver returned empty unit");
  assert(NewSize <= MaxSize && "CrossOver returned overisized unit");
  return NewSize;
}

void MutationDispatcher::StartMutationSequence() {
  CurrentMutatorSequence.clear();
  CurrentDictionaryEntrySequence.clear();
  LastChangedIdx = 0;
  op_log_tainted = 0;
}

// Copy successful dictionary entries to PersistentAutoDictionary.
void MutationDispatcher::RecordSuccessfulMutationSequence() {
  for (auto DE : CurrentDictionaryEntrySequence) {
    // PersistentAutoDictionary.AddWithSuccessCountOne(DE);
    DE->IncSuccessCount();
    assert(DE->GetW().size());
    // Linear search is fine here as this happens seldom.
    if (!PersistentAutoDictionary.ContainsWord(DE->GetW()))
      PersistentAutoDictionary.push_back(*DE);
  }
}

void MutationDispatcher::PrintRecommendedDictionary() {
  std::vector<DictionaryEntry> V;
  for (auto &DE : PersistentAutoDictionary)
    if (!ManualDictionary.ContainsWord(DE.GetW()))
      V.push_back(DE);
  if (V.empty()) return;
  Printf("###### Recommended dictionary. ######\n");
  for (auto &DE: V) {
    assert(DE.GetW().size());
    Printf("\"");
    PrintASCII(DE.GetW(), "\"");
    Printf(" # Uses: %zd\n", DE.GetUseCount());
  }
  Printf("###### End of recommended dictionary. ######\n");
}

void MutationDispatcher::PrintMutationSequence(bool Verbose) {
  Printf("MS: %zd ", CurrentMutatorSequence.size());
  size_t EntriesToPrint =
      Verbose ? CurrentMutatorSequence.size()
              : std::min(kMaxMutationsToPrint, CurrentMutatorSequence.size());
  for (size_t i = 0; i < EntriesToPrint; i++)
    Printf("%s-", CurrentMutatorSequence[i].Name);
  if (!CurrentDictionaryEntrySequence.empty()) {
    Printf(" DE: ");
    EntriesToPrint = Verbose ? CurrentDictionaryEntrySequence.size()
                             : std::min(kMaxMutationsToPrint,
                                        CurrentDictionaryEntrySequence.size());
    for (size_t i = 0; i < EntriesToPrint; i++) {
      Printf("\"");
      PrintASCII(CurrentDictionaryEntrySequence[i]->GetW(), "\"-");
    }
  }
}

std::string MutationDispatcher::MutationSequence() {
  std::string MS;
  for (auto M : CurrentMutatorSequence) {
    MS += M.Name;
    MS += "-";
  }
  return MS;
}

int MutationDispatcher::MutationSequenceSize() {
  return CurrentMutatorSequence.size();
}

void MutationDispatcher::TestSyscallMutateImpl(uint8_t *Data, size_t Size,
                                      size_t MaxSize) {
    printf("--- start test ---\n");
    uint8_t* DataCopy = (uint8_t*)malloc(Size);
    uint8_t* DataCopy2 = (uint8_t*)malloc(Size+100);
    Printf("Original Data:");
    for(int i =0; i<Size; i++) {
        if(i%16 ==0)
            Printf("\nDD: ");
        Printf("%02x ", Data[i]);
    }
    Printf("\n");
    for (auto& e : OurBaseII->InputSyscalls)
    {
        Printf("StatsSC Id %ld Start %ld Length %ld N_Cfu: %ld\n", e->id,
                e->start, e->len, e->n_copy_from_user);
    }
    memcpy(DataCopy, Data, Size);
    int i =0;
    while(i++ < 5000) {
        CurrentMutatorSequence.clear();
        memcpy(DataCopy2, DataCopy, Size);
        // size_t newsize = SyscallMutateImpl(DataCopy2, Size, Size+100);
        size_t newsize = VmcsMutateImpl(DataCopy2, Size, Size+100);
        Printf("Mutated Data:");
        PrintMutationSequence();
        for(int i =0; i<newsize; i++) {
            if(i%16 ==0)
                Printf("\nDD: ");
            Printf("%02x ", DataCopy2[i]);
        }
        Printf("\n");
        
    }
    exit(0);
}

size_t MutationDispatcher::Mutate(uint8_t *Data, size_t Size, size_t MaxSize) {
    static void *UseVmcsMutators = getenv("MUTATE_VMCS");
    if (UseVmcsMutators) {
		    // TestSyscallMutateImpl(Data, Size, MaxSize);
        return VmcsMutateImpl(Data, Size, MaxSize);
    }else {
        return MutateImpl(Data, Size, MaxSize, Mutators);
    }
}

size_t MutationDispatcher::DefaultMutate(uint8_t *Data, size_t Size,
                                         size_t MaxSize) {
  return MutateImpl(Data, Size, MaxSize, DefaultMutators);
}

//RemoveOp-InsertOpBytes-malloc
// Mutates Data in place, returns new size.
size_t MutationDispatcher::MutateImpl(uint8_t *Data, size_t Size,
                                      size_t MaxSize,
                                      std::vector<Mutator> &Mutators) {
  assert(MaxSize > 0);
  // Some mutations may fail (e.g. can't insert more bytes if Size == MaxSize),
  // in which case they will return 0.
  // Try several times before returning un-mutated data.
  for (int Iter = 0; Iter < 100; Iter++) {
    auto M = Mutators[Rand(Mutators.size())];
    size_t NewSize = (this->*(M.Fn))(Data, Size, MaxSize);
    if (NewSize && NewSize <= MaxSize) {
      if (Options.OnlyASCII)
        ToASCII(Data, NewSize);
      CurrentMutatorSequence.push_back(M);
      return NewSize;
    }
  }
  *Data = ' ';
  return 1;   // Fallback, should not happen frequently.
}

// Mask represents the set of Data bytes that are worth mutating.
size_t MutationDispatcher::MutateWithMask(uint8_t *Data, size_t Size,
                                          size_t MaxSize,
                                          const std::vector<uint8_t> &Mask) {
  size_t MaskedSize = std::min(Size, Mask.size());
  // * Copy the worthy bytes into a temporary array T
  // * Mutate T
  // * Copy T back.
  // This is totally unoptimized.
  auto &T = MutateWithMaskTemp;
  if (T.size() < Size)
    T.resize(Size);
  size_t OneBits = 0;
  for (size_t I = 0; I < MaskedSize; I++)
    if (Mask[I])
      T[OneBits++] = Data[I];

  if (!OneBits) return 0;
  assert(!T.empty());
  size_t NewSize = Mutate(T.data(), OneBits, OneBits);
  assert(NewSize <= OneBits);
  (void)NewSize;
  // Even if NewSize < OneBits we still use all OneBits bytes.
  for (size_t I = 0, J = 0; I < MaskedSize; I++)
    if (Mask[I])
      Data[I] = T[J++];
  return Size;
}

void MutationDispatcher::AddWordToManualDictionary(const Word &W) {
  ManualDictionary.push_back(
      {W, std::numeric_limits<size_t>::max()});
}

/* =============== VMCS Fuzzer Mutation =================== */
/* TODO: fix minor systematic bug in mutations that modify input length
 * MutateAndTestOne() takes a seed, then mutates and runs it until new coverage is obtained
 * where AddToCorpus() is called, and InputInfo->InputOps metadata is updated.
 * If the mutations do not find new coverage, the metadata is not updated
 * although the ops' lengths and indexes are being changed by the mutations.
 *
 * Potential Solutions: 
 * 1. Call UpdateOpLog() every mutation, but this requires re-parsing the entire input
 * 2. Hardcode logic to fix the indexes and lens for each mutation
 *    (subtract from current op_idx's len, and subtract from subsequent op_idx's start_idx and dma_start)
 * 3. Ignore this, as it may potentially be only a minor issue overall
 */
size_t MutationDispatcher::Mutate_RemoveOp(uint8_t *Data, size_t Size,
                                                  size_t MaxSize) {
    if(!OurBaseII || !OurBaseII->InputOps.size()) {
        return 0;
    }
    int n_ops = OurBaseII->InputOps.size();
    if(n_ops < 2)
        return 0;
    int remove = Rand(n_ops);

    size_t Idx = OurBaseII->InputOps[remove].start;
    size_t N = OurBaseII->InputOps[remove].len;

    if(Size < Idx + N)
        return 0;
    memmove(Data + Idx, Data + Idx + N, Size - Idx - N);

    return Size - N;
}

size_t MutationDispatcher::Mutate_InsertOp(uint8_t *Data, size_t Size,
                                                  size_t MaxSize) {
    size_t Idx;
    size_t N = MaxSize - Size;
    if(N < 5)
        return 0;
    if(OurBaseII && OurBaseII->InputOps.size()) {
        int n_ops = OurBaseII->InputOps.size();
        int insert = biased_rand(n_ops + 1, 5, Rand);
        // If 0, insert the syscall before everything else
        if(insert == 0) {
            Idx = 0;
        } else {
            insert--;
            Idx = OurBaseII->InputOps[insert].start + OurBaseII->InputOps[insert].len;
        }
    } else {
        Idx = Rand(Size);
    }
    if(MaxSize < Idx+N)
        return 0;
    memmove(Data + Idx + N, Data + Idx, Size - Idx);

    uint8_t Byte = Rand(256);
    size_t i = Idx ? 4 : 0;
    for (; i < N; i++) {
        Data[Idx + i] = Rand(256);
    }

    if(Idx) {
        memcpy(Data + Idx, SEPARATOR, 4);
    } else {
        memcpy(Data + N - 4, SEPARATOR, 4);
    }

    size_t NewSize = Size + N;
    return NewSize;
}

size_t MutationDispatcher::Mutate_RemoveOpBytes(uint8_t *Data, size_t Size,
                                                  size_t MaxSize) {
    if(!OurBaseII || !OurBaseII->InputOps.size()) {
        return 0;
    }
    int n_ops = OurBaseII->InputOps.size();
    int op_idx = biased_rand(n_ops, 5, Rand); // favour removing from the last op

    size_t op_len = OurBaseII->InputOps[op_idx].len;
    if (OurBaseII->InputOps[op_idx].dma_start)
        op_len = OurBaseII->InputOps[op_idx].dma_start - OurBaseII->InputOps[op_idx].start;
    size_t Idx_offset = biased_rand(op_len, 3, Rand);
    if (Idx_offset && Idx_offset == op_len - 1) 
        Idx_offset--; // we won't be able to remove any bytes if the last index is chosen
    size_t Idx = OurBaseII->InputOps[op_idx].start + Idx_offset;
    // don't bias the number of bytes removed
    size_t N = biased_rand(op_len - (Idx - OurBaseII->InputOps[op_idx].start), 1, Rand);
    if (N == 0) N++; // if N == 0, this mutation does not do anything
    
    if(Size < Idx + N)
        return 0;
    
    memmove(Data + Idx, Data + Idx + N, Size - Idx - N);

    return Size - N;
}

size_t MutationDispatcher::Mutate_InsertOpBytes(uint8_t *Data, size_t Size,
                                                  size_t MaxSize) {
    if(!OurBaseII || !OurBaseII->InputOps.size()) {
        return 0;
    }
    if (MaxSize <= Size)
        return 0;
    int n_ops = OurBaseII->InputOps.size();
    int op_idx = biased_rand(n_ops, 5, Rand);
    
    size_t Idx_offset = biased_rand(OurBaseII->InputOps[op_idx].len, 3, Rand);
    size_t Idx = OurBaseII->InputOps[op_idx].start 
        + Rand(OurBaseII->InputOps[op_idx].len);
    size_t N = Rand(MaxSize-Size);
    if (N == 0) N++; // if N == 0, this mutation does nothing
    
    if(MaxSize < Idx + N)
        return 0;
    
    if(Size <= Idx)
        return 0;
    
    memmove(Data + Idx + N, Data + Idx, Size - Idx);

    for(int i =0; i< N; i++){
        Data[Idx + i] = Rand(256);
    }
    return Size + N;
}

size_t MutationDispatcher::Mutate_MutateOpBytes(uint8_t *Data, size_t Size,
                                                  size_t MaxSize) {
    enum { OP_IN, OP_OUT, OP_READ, OP_WRITE, OP_VMCALL };
    if(!OurBaseII || !OurBaseII->InputOps.size()) {
        return 0;
    }
    // Pick an op (towards the end)
    int n_ops = OurBaseII->InputOps.size();
    int op_idx = biased_rand(n_ops, 5, Rand);

    auto op = OurBaseII->InputOps[op_idx];

    size_t BeginMutate = op.start;
    size_t MutateLen = op.len;
    uint8_t opType = op.op;

    if(MaxSize < BeginMutate + MutateLen)
        return 0;

    switch (opType % 5) {
      case OP_IN:
      case OP_OUT:
      case OP_READ:
      case OP_WRITE:
          if (op.dma_start) // mutate the op and the dma section separately
              MutateLen = op.dma_start - op.start;
          break;
      case OP_VMCALL:
          if (MutateLen > 5) {
            // do not mutate the op and 4 byte VMCALL bitmap
            BeginMutate += 5;
            MutateLen -= 5;
          }
          break;
    }

    // if there is DMA section, mutate it separately from the OP
    for (int dma = 0; dma < (op.dma_start ? 2 : 1); dma++) {
        int iters = Rand(3) + 1;
        int start = dma ? op.dma_start : BeginMutate;
        int len = dma ? op.dma_len : MutateLen;
        for (int i = 0; i < iters; i++) {
            switch (Rand() % 4) {
            case 0:
                Mutate_ShuffleBytes(Data + start, len, len);
                break;
            case 1:
                Mutate_ChangeByte(Data + start, len, len);
                break;
            case 2:
                Mutate_ChangeBit(Data + start, len, len);
                break;
            case 3:
                Mutate_ChangeBinaryInteger(Data + start, len, len);
                break;
            }
        }
    }
    return Size;
}

// Does not change the size of the input
size_t MutationDispatcher::Mutate_CrossOverOps(uint8_t *Data, size_t Size,
                                                  size_t MaxSize) {
    return 0; // TODO: consider whether to implement corpus of ops, or any custom crossover
}

size_t MutationDispatcher::VmcsMutateImpl(uint8_t *Data, size_t Size,
                                      size_t MaxSize) {
    assert(MaxSize > 0);
    // Some mutations may fail (e.g. can't insert more bytes if Size == MaxSize),
    // in which case they will return 0.
    // Try several times before returning un-mutated data.
    //
    if(op_log_tainted == 0 && Rand(3) > 0) {
        for (int Iter = 0; Iter < 100; Iter++) {
            auto M = VmcsMutators[Rand(VmcsMutators.size())];
            uint8_t old_data[4096];
            size_t old_size = Size;
            memcpy(old_data, Data, old_size);

            size_t NewSize = (this->*(M.Fn))(Data, Size, MaxSize);
            if (NewSize && NewSize <= MaxSize) {
                CurrentMutatorSequence.push_back(M);
                return NewSize;
            }
        }
    }
    for (int Iter = 0; Iter < 100; Iter++) {
        auto M = DestructiveMutators[Rand(DestructiveMutators.size())];
        size_t NewSize = (this->*(M.Fn))(Data, Size, MaxSize);
        if (NewSize && NewSize <= MaxSize) {
            op_log_tainted = 1;
            CurrentMutatorSequence.push_back(M);
            return NewSize;
        }
    }


    *Data = ' ';
    return 1;   // Fallback, should not happen frequently.
}

}  // namespace fuzzer
