// @file wire.cpp -- wire object for encrypted circuit evaluation object
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
#include "wire.h"

#include <iostream>

Wire::Wire(){};
Wire::~Wire(){};
void Wire::setName(std::string n) { this->name = n; }
std::string Wire::getName(void) { return this->name; }
void Wire::setValue(bool b) { this->value = b; }
bool Wire::getValue(void) { return this->value; }
void Wire::setCipherText(CipherText ct) { this->ct = ct; }
CipherText Wire::getCipherText(void) { return this->ct; }
void Wire::setFanoutGates(NameList f) { this->fanoutGates = f; }
NameList Wire::getFanoutGates(void) { return this->fanoutGates; }
unsigned int Wire::getNumberFanoutGates(void) {
  return this->fanoutGates.size();
}

void Wire::updateFanoutGates(std::string gateToRemove) {
  auto w = std::find(this->fanoutGates.begin(), this->fanoutGates.end(),
                     gateToRemove);

  if (w != this->fanoutGates.end()) {
    this->fanoutGates.erase(w);
    // remove w
  } else {
    std::cout << "error, trying to remove node " << gateToRemove
              << " from fanoutGates and it isn;t there" << std::endl;
  }
}
