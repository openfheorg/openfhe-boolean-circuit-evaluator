// @file gate.h -- encrypted circuit gate object
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2020, New Jersey Institute of Technology (NJIT)
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef GATE_H
#define GATE_H

#include "wire.h"
#include <algorithm>
#include <deque>
#include <map>
#include <string>
#include <vector>

// using ReadyList = std::map<std::string, bool>;
using ReadyList = std::vector<bool>;
using CipherTextList = std::vector<CipherText>;
using BitList = std::vector<unsigned int>;

enum class GateEnum { INPUT, OUTPUT, NOT, AND, OR, XOR, DFF, LUT3, LUT4 };

class GateEvalParams {
 public:
  GateEvalParams();
  ~GateEvalParams();
  bool plaintext_flag;
  bool encrypted_flag;
  bool verify_flag;

  lbcrypto::BinFHEContext cc;
  lbcrypto::LWEPrivateKey sk;
};

class Gate {
 public:
  Gate();
  ~Gate();
  void Reset(void);
  void Evaluate(const GateEvalParams &);
  std::string name;  // note can be an integer
  GateEnum op;
  NameList inWireNames;
  ReadyList ready;
  NameList outWireNames;
  CipherTextList encin;
  BitList plainin;
  CipherTextList encout;
  BitList plainout;
};

#endif
