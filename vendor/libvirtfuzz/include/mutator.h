#ifndef MUTATOR_H
#define MUTATOR_H

#include <cstdint>
#include <random>

#include "messages.pb.h"
#include "common.h"

// Function pointer type for mutating a message sequence
using SequenceMutatorFunc = void (*)(virtfuzz::MessageSequence&, std::mt19937&);

size_t select_sequence_mutator(std::mt19937& rng);

enum MutatorGroup {
    BASIC_MUTATION,
    MESSAGE_INSERTION,
    MESSAGE_REMOVAL,
    MESSAGE_REORDERING,
    NUM_MUTATOR_GROUPS
};

struct Mutator {
    SequenceMutatorFunc func;
    const char* name;
    MutatorGroup group;
};

extern Mutator mutators[];

#endif // MUTATOR_H
