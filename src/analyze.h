// @file analyze.h -- analyze input file for statistics
//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other
// contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//==================================================================================
#ifndef SRC_ANALYZE_H_
#define SRC_ANALYZE_H_

#include <string>
#include <vector>

class Variable {
public:
  Variable();
  std::string in_fname;
  bool new_flag;
  unsigned int n_tot;
  unsigned int n_inputs;
  unsigned int n_in1_bits;
  unsigned int n_in2_bits;
  unsigned int n_out1_bits;
  std::vector<unsigned int> high_water;
  std::vector<unsigned int> low_water;
  std::vector<unsigned int> life;
  std::vector<unsigned int> fan_in;
  std::vector<unsigned int> fan_out;
};

using FuncCall_t = uint64_t; // replace with with an enum

class Function {
public:
  Function();
  std::string in_fname;
  uint64_t n_tot;
  std::vector<std::string> call_list;
  std::vector<std::vector<unsigned int>> in_list;
  std::vector<std::vector<unsigned int>> out_list;
  unsigned int n_and;
  unsigned int n_or;
  unsigned int n_xor;
  unsigned int n_not;
  unsigned int n_eq;
  unsigned int n_eqw;
  std::vector<std::string> names;
};

class Analysis {
public:
  Analysis();
  ~Analysis();
  Variable variables;
  Function functions;
};

// function declaration
Analysis analyze_bristol(std::string in_fname, bool gen_fan_flag,
                         bool new_flag);

#endif
