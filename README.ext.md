# Extend HyperPill

HyperPill can be extended in four ways:

1. Adding different input generators and mutators
2. Adding different bug oracles
3. Adding more proof of concepts as unit tests
4. Adding hardware-level migitations 

## Input Generation and Mutation

Vanilla HyperPill uses [libfuzzer-ng](./vendor/libfuzzer-ng/) to generate and
mutator inputs.

We plan to support Hyper-Cube, ViDeZZo, and Truman (first). Export `INPUT_GEN`
to `vanilla` (default), `hypercube`, `videzzo`, or `truman` and then recompile
HyperPill to enable the corresponding input generator and mutator.

## Bug Oracles

## PoC Benchmark

## Hardware-Software Co-design
