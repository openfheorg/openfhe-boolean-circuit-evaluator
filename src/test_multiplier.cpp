// @file test_multiplier.cpp -- runs and tests encrypted multiplier circuits
//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

#include "utils.h"
#include <algorithm>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>

#include "circuit.h"
#include "test_multiplier.h"

/////

//
// test program to run circuits for
// various multiplier operations provided at
// <https://homes.esat.kuleuven.be/~nsmart/MPC/>
// Initial development was funded under DARPA MARSHAL
//
// Converted from matlab code originally written for DARPA Proceed
// Version History:
//   original matlab  started 12/12/2012 by D. Cousins
//   current version started 7/20/2012 by D. Cousins dcousins@njit.edu
// Known Issues:
//   only tested for old style bristol ckts
// List of Authors:
//    original David Bruce Cousins, dcousins@bbn.com now of njit.edu

// Description:
// This testbed  takes an assembled circuit description program for the ECE and
// tests it in a loop. It scans the input file, determines I/O.  It then
// generates a random input set, and computes the appropriate output. It then
// runs the program through the ECE and compares results. the first pass through
// always sets the two inputs to each other in order to test equality filename
// containing lteq triggers <= compare otherwise < is computed
//
// Input
//   inFname = input filename containing the program
//   numTestLoops = number of times to test program
// Output
//   passed = if true then all tests passed
//
// Version History:
//   v01 matlab started 12/06/2012 by D. Cousins
//   c++ port started 7/28/2020
// Known Issues:
//   None.
//

bool test_multiplier(std::string inFname, unsigned int numTestLoops,
                     lbcrypto::BINFHE_PARAMSET set,
                     lbcrypto::BINFHE_METHOD method) {
  // BLU_test_multiplier: tests BLU with multiplier programs
  std::cout << "Opening file " << inFname << " for test_multiplier parameters"
            << std::endl;

  // open the program file to determine some parameters for tests
  std::ifstream inFile;
  // Set exceptions to be thrown on failure
  inFile.exceptions(std::ifstream::failbit | std::ifstream::badbit);

  try {
    inFile.open(inFname.c_str());
  } catch (std::system_error &e) {
    std::cerr << e.code().message() << std::endl;
    exit(-1);
  }

  std::string tline;

  unsigned int max_n_reg;
  std::vector<unsigned int> n_in_bits(2);
  std::vector<unsigned int> n_out_bits(1);
  unsigned int n_p_passed(0);
  unsigned int n_e_passed(0);

  //  get input and output statistics from file
  try {
    while (std::getline(inFile, tline)) {
      if (tline.find("# Assembler statistics") != std::string::npos) {
        std::getline(inFile, tline); // skip 3 lines
        std::getline(inFile, tline);
        std::getline(inFile, tline);
        std::getline(inFile, tline);

        sscanf(tline.c_str(), "# %ul registers used\n", &max_n_reg);
        std::cout << "using " << max_n_reg << " registers" << std::endl;

      } else if (tline.find("# number input") != std::string::npos) {
        // note hardwired for two inputs
        unsigned int tmp;
        sscanf(tline.c_str(), "# number input1 bits %d\n", &tmp);
        n_in_bits[0] = tmp;
        std::cout << "using " << n_in_bits[0] << " bits for input 1"
                  << std::endl;

        std::getline(inFile, tline);

        sscanf(tline.c_str(), "# number input2 bits %d\n", &tmp);
        n_in_bits[1] = tmp;
        std::cout << "using " << n_in_bits[1] << " bits for input 2"
                  << std::endl;

      } else if (tline.find("# number output") != std::string::npos) {
        // note hardwired for one output

        unsigned int tmp;
        sscanf(tline.c_str(), "# number output1 bits %d\n", &tmp);
        n_out_bits[0] = tmp;
        std::cout << "using " << n_out_bits[0] << " bits for output 1"
                  << std::endl;
      }
    }
  } catch (std::system_error &e) {
    std::cout << "end of file" << std::endl;
  }
  try {
    inFile.close();
  } catch (std::system_error &e) {
    std::cerr << e.code().message() << std::endl;
    exit(-1);
  }

  Circuit circ(set, method);
  bool success = circ.ReadFile(inFname);
  if (!success) {
    std::cerr << "error parsing file " << inFname << std::endl;
  }

  // circ.dumpNetList();

  //  loop over tests
  bool passed = true;

  // preallocate input and output
  if (n_in_bits[0] != n_in_bits[1]) {
    std::cout << "two inputs are not the same length" << std::endl;
    exit(-1);
  }
  std::vector<unsigned int> in1(n_in_bits[0]);
  std::vector<unsigned int> in2(n_in_bits[1]);

  Inputs inputs;
  std::cout << "testing " << numTestLoops << " iterations" << std::endl;
  for (uint test_ix = 0; test_ix < numTestLoops; test_ix++) {
    std::cout << "test " << test_ix << std::endl;

    // generate random inputs
    srand(test_ix); // set the random number generator to a known seed
    std::cout << " input 1:  ";
    inputs.resize(2); // clear inputs
    inputs[0].resize(0);
    inputs[1].resize(0);
    for (uint ix = 0; ix < n_in_bits[0]; ix++) {
      in1[ix] = rand() % 2;
      inputs[0].push_back(in1[ix]);
      in2[ix] = rand() % 2;
      inputs[1].push_back(in2[ix]);
    }

    for (int ix = n_in_bits[0] - 1; ix >= 0; ix--) {
      std::cout << in1[ix];
    }

    std::cout << std::endl;

    std::cout << " input 2:  ";
    for (int ix = n_in_bits[1] - 1; ix >= 0; ix--) {
      std::cout << in2[ix];
    }
    std::cout << std::endl;

    // generate the test output (mult)

    std::vector<unsigned int> out(n_out_bits[0], 0);

    uint32_t a(0);
    uint32_t b(0);
    uint64_t c(0);
    // build the inputs
    for (uint ix = 0; ix < n_in_bits[0]; ix++) {
      a |= in1[ix] << ix;
      b |= in2[ix] << ix;
    }
    c = uint64_t(a) * uint64_t(b);
    std::cout << a << " * " << b << " = " << c << std::endl;

    for (uint ix = 0; ix < n_out_bits[0]; ix++) {
      out[ix] = (unsigned long)((c & (1ULL << ix)) >> ix);
    }

    std::cout << " output : ";
    for (int ix = n_out_bits[0] - 1; ix >= 0; ix--) {
      std::cout << out[ix];
    }
    std::cout << std::endl;
    auto out_good = out;

    //  execute program in circuit

    std::cout << "executing circuit" << std::endl;
    circ.Reset();
    circ.setPlaintext(true);
    circ.setEncrypted(false);
    circ.setVerify(false);
    circ.SetInput(inputs);
    Outputs outputs = circ.Clock();
    std::cout << "program done" << std::endl;
    if (test_ix == 0)
      circ.dumpGateCount();

    auto out_plain = out;
    // note curently only one valid output register
    for (auto outreg : outputs) {
      unsigned int bit_ix = 0;
      for (auto outbit : outreg) {
        out_plain[bit_ix] = outbit;
        bit_ix++;
      }
    }

    //  compare plaintect output with known good answer
    if (out_plain == out_good) {
      std::cout << "output match " << std::endl;
      n_p_passed++;
      passed = passed & true;
    } else {
      std::cout << "plain computed  out: ";
      for (int ix = n_out_bits[0] - 1; ix >= 0; ix--) {
        std::cout << out_plain[ix];
      }
      std::cout << std::endl;
      std::cout << "output does not match" << std::endl;
      passed = passed & false;
    }
    //  execute program in encrypted circuit evaluator

    std::cout << "executing encrypted circuit" << std::endl;
    circ.Reset();
    circ.setPlaintext(false);
    circ.setEncrypted(true);
    circ.setVerify(true);
    circ.SetInput(inputs);
    outputs = circ.Clock();
    // circ.dumpGateCount();
    std::cout << "program done" << std::endl;
    auto out_enc = out;
    // map output registers
    for (auto outreg : outputs) {
      unsigned int bit_ix = 0;
      for (auto outbit : outreg) {
        out_enc[bit_ix] = outbit;
        bit_ix++;
      }
    }
    //  compare plaintext output with known good answer
    if (out_enc == out_good) {
      std::cout << "output match " << std::endl;
      passed = passed & true;
      n_e_passed++;
    } else {
      std::cout << "enc computed  out: ";
      for (int ix = n_out_bits[0] - 1; ix >= 0; ix--) {
        std::cout << out_enc[ix];
      }
      std::cout << std::endl;
      std::cout << "output does not match" << std::endl;
      passed = passed & false;
    }
  } // for test_ix
  std::cout << "# tests total: " << numTestLoops << std::endl;
  std::cout << "# passed plaintext: " << n_p_passed << std::endl;
  std::cout << "# passed encrypted: " << n_e_passed << std::endl;

  return passed;
}
