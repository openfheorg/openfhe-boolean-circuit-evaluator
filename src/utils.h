// @file utils.h -- utility code for encrypted circuit evaluator
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

#ifndef SRC_UTILS_H_
#define SRC_UTILS_H_

#include <string>
#include <vector>
#include <iostream>

#include "binfhecontext.h"

/**
 * Helper function to insure files exists
 *
 * If the file doesn't exist it will print out a error message and give
 * information on the likely way to fix the issue before EXITING program
 * execution.
 *
 * @param filename string
 *
 * @note This was added because many circuits don't have version controlled .out
 * files which are needed for a number of the TB's.
 */
inline void insureFileExists(std::string filename) {
  std::ifstream ifile(filename.c_str());
  if (ifile.fail()) {
    std::cerr << "[ERROR] The file " << filename
              << " doesn't exits, and is required!" << std::endl
              << "\t *** To correct this use the \"-z\" parameter ***" << std::endl;
    std::exit(EXIT_FAILURE);
  }
}

// function declaration
bool contains(std::string s1, std::string s2);

std::vector<unsigned int> HexStr2UintVec(std::string inhex);
std::vector<unsigned int> BinStr2UintVec(std::string inbin);

std::string UintVec2str(std::vector<unsigned int> in);

void parse_inputs(int argc, char **argv, bool *assemble_flag,
                  bool *gen_fan_flag, bool *analyze_flag, bool *verbose,
                  lbcrypto::BINFHEPARAMSET *set, lbcrypto::BINFHEMETHOD *method,
                  unsigned int *n_cases, unsigned int *num_test_loops);

#endif  // SRC_UTILS_H_
