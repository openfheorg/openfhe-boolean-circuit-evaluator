// @file analyze.cpp -- analyze input file for statistics
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
#include "analyze.h"

#include <algorithm>
#include <cstring>
#include <functional>
#include <iostream>

Variable::Variable(void){

};
Function::Function(void){

};

Analysis::Analysis(void){

};
Analysis::~Analysis(void){

};

Analysis analyze_bristol(std::string in_fname, bool gen_fan_flag,
                         bool new_flag) {
  //  Code to analyze a Bristol Fasion circuit file and generate a
  //  processeed variable and function list for further processing
  //  by assemble()
  //
  // List of Authors:
  //     David Bruce Cousins, currently dcousins@njit.edu
  // Description:
  //
  //  Example Bristol Fasion Circuits:
  //  see http://www.cs.bris.ac.uk/Research/CryptographySecurity/MPC/
  //  https://github.com/AarhusCrypto/TinyLEGO/tree/master/test/data
  //  and
  //  the circuit is preprocessed in to a list of variables and functions by
  //  this function.
  //  For every line in the circuit description file
  //  the code keeps track of highwater, lowwater, fan in and fan out for every
  //  circuit node.  it also tokenizes the function calls.
  //
  //  Input
  //    A file to parse.
  //    gen_fan_flag if true, generate fan_in and fan out statistics
  //  Output
  //    the circuit is preprocessed in to a list of variables and functions by
  //    the analyze() function.

  //    Analysis.variable = variable structure from analyze.m
  //    Analysis.func = function structure from analyze.m
  //
  //  Version History:
  //    matlab version v01 started 12/06/2012 by D. Cousins for PROCEED
  //    current CPP version  v01 started 7/22/2020 by D. Cousins at njit
  //
  //  Known Issues:
  //    None.
  //
  //
  // note this file was translated from matlab which uses C file IO

  // //  open the file name
  FILE *fid = fopen(in_fname.c_str(), "r");

  std::cout << "analyzing file " << in_fname << std::endl;
  if (fid == NULL) {
    std::cout << "error opening file.. exiting!" << std::endl;
  }

  //  parse the header of the file.

  //  the first line for two variables
  std::cout << "Analysis Report for input file " << in_fname << std::endl;
  std::cout << "Parsing circuit i/o" << std::endl;
  char *remain;
  char *token;
  int buffsize = 256;
  char buff[buffsize];

  remain = fgets(buff, sizeof buff, fid);
  token = std::strtok(remain, " ");
  unsigned int n_tot_func;
  sscanf(token, "%ul", &n_tot_func);
  token = std::strtok(NULL, " ");
  unsigned int n_tot_var;
  sscanf(token, "%d", &n_tot_var);
  std::cout << "Total number of nodes: " << n_tot_var << std::endl;

  unsigned int n_inputs;
  unsigned int n_in1_var(0);
  unsigned int n_in2_var(0);
  unsigned int n_outputs;
  unsigned int n_out1_var(0);

  if (new_flag) {
    std::cout << "new" << std::endl;
    n_inputs = 2;
    n_outputs = 1;
    // new "bristol fashion" files have slightly different header

    // parse the second line for three variables
    remain = fgets(buff, sizeof buff, fid);
    token = std::strtok(remain, " ");
    sscanf(token, "%ul", &n_inputs);

    token = std::strtok(NULL, " ");
    sscanf(token, "%ul", &n_in1_var);

    token = std::strtok(NULL, " ");
    sscanf(token, "%d", &n_in2_var);

    remain = fgets(buff, sizeof buff, fid);
    token = std::strtok(remain, " ");

    sscanf(token, "%d", &n_outputs); // always 1

    token = std::strtok(NULL, " ");
    sscanf(token, "%d", &n_out1_var);

    // parse the fourth line for a blank
    char *blank;
    blank = fgets(buff, sizeof buff, fid);
    (void)blank;

  } else {
    std::cout << "old" << std::endl;
    n_inputs = 2;
    n_outputs = 1;
    // use the old format
    // parse the second line for three variables
    remain = fgets(buff, sizeof buff, fid);
    token = std::strtok(remain, " ");

    sscanf(token, "%ul", &n_in1_var);
    token = std::strtok(NULL, " ");

    sscanf(token, "%d", &n_in2_var);
    token = std::strtok(NULL, " ");
    ;

    sscanf(token, "%d", &n_out1_var);
    // parse the third line for a blank
    char *blank;
    blank = fgets(buff, sizeof buff, fid);
    (void)blank;
  }
  std::cout << "number bits input 1 = " << n_in1_var << std::endl;
  if (n_inputs == 2) {
    std::cout << "number bits input 2 = " << n_in2_var << std::endl;
  }
  std::cout << "number bits output 1 = " << n_out1_var << std::endl;

  //  parse remaining lines for functions
  std::cout << "Total number of function calls " << n_tot_func << std::endl;
  // count of each function type
  unsigned int n_xor = 0;
  unsigned int n_and = 0;
  unsigned int n_not = 0;
  unsigned int n_eq = 0;
  unsigned int n_eqw = 0;

  // variable counters
  std::vector<unsigned int> var_high_water(n_tot_var, 0);
  std::vector<unsigned int> var_low_water(n_tot_var, 0);
  std::vector<unsigned int> var_life(n_tot_var, 0);
  std::vector<unsigned int> var_fan_in(n_tot_var, 0);
  std::vector<unsigned int> var_fan_out(n_tot_var, 0);

  // resulting function call list.
  std::vector<std::string> func_call_list(n_tot_func);
  std::vector<std::string> func_names(5);
  unsigned int xor_ix = 0;
  unsigned int and_ix = 1;
  unsigned int not_ix = 2;
  unsigned int eq_ix = 3;
  unsigned int eqw_ix = 4;
  func_names[xor_ix] = "XOR";
  func_names[and_ix] = "AND";
  func_names[not_ix] = "NOT";
  func_names[eq_ix] = " EQ";
  func_names[eqw_ix] = "EQW";

  // //  parse function call lines
  std::cout << "Parsing function calls" << std::endl;

  std::vector<std::vector<unsigned int>> func_in_list(n_tot_func);
  std::vector<std::vector<unsigned int>> func_out_list(n_tot_func);

  for (uint ix = 0; ix < n_tot_func; ix++) {
    std::vector<unsigned int> inlist;  // list of input nodes
    std::vector<unsigned int> outlist; // list of output nodes

    //  get # in and out nodes
    remain = fgets(buff, sizeof buff, fid);

    token = std::strtok(remain, " ");
    ;

    unsigned int nin;
    sscanf(token, "%d", &nin);
    token = std::strtok(NULL, " ");
    unsigned int nout;
    sscanf(token, "%d", &nout);

    unsigned int tmp;
    for (uint jj = 0; jj < nin; jj++) { // read list of input nodes
      token = std::strtok(NULL, " ");
      sscanf(token, "%d", &tmp);
      inlist.push_back(tmp);
    }
    for (uint jj = 0; jj < nout; jj++) { // read list of output nodes
      token = std::strtok(NULL, " ");
      sscanf(token, "%d", &tmp);
      outlist.push_back(tmp);
    }

    token = std::strtok(NULL, " ");
    ;
    // inlist = inlist+1; // indicies are starting at 1, node names at 0
    // outlist = outlist+1; // indicies are starting at 1, node names at 0
    func_in_list[ix] = inlist;
    func_out_list[ix] = outlist;

    *std::remove(token, token + strlen(token), '\n') =
        '\0'; // removes _all_ new lines.
    std::string str = std::string(token);
    for (auto &c : str)
      c = toupper(c); // convert to uppercase
    // token =  toupper(token); // parse function call
    if (str == "XOR") {
      n_xor = n_xor + 1;
      func_call_list[ix] = "XOR"; // function token for xor
    } else if (str == "AND") {
      n_and = n_and + 1;
      func_call_list[ix] = "AND"; // function token for xor
    } else if (str == "INV") {
      n_not = n_not + 1;
      func_call_list[ix] = "NOT"; // function token for inv
    } else if (str == "EQ") {
      n_eq = n_eq + 1;
      func_call_list[ix] = " EQ"; // function token for inv
      std::cout << "Cannot parse EQ!! yet failing" << std::endl;
      exit(-1);
    } else if (str == "EQW") {
      n_eqw = n_eqw + 1;
      func_call_list[ix] = "EQW"; // function token for inv
    } else {
      std::cout << "bad parse of function on line " << ix << std::endl;
    }

    // generate high and low water marks for each node
    // low water is first gate that uses the node, high water is last gate
    for (const auto &jj : inlist) { // (note node name start at 0
      if (var_low_water[jj] == 0) {
        var_low_water[jj] = ix;
      }
      var_high_water[jj] = ix;
    }
    for (const auto &jj : outlist) {
      if (var_low_water[jj] == 0) {
        var_low_water[jj] = ix;
      }
      var_high_water[jj] = ix;
    }
  } // for ix

  fclose(fid);

  std::cout << " number of and " << n_and << std::endl;
  std::cout << " number of xor " << n_xor << std::endl;
  std::cout << " number of inv " << n_not << std::endl;
  std::cout << " number of eq " << n_eq << std::endl;
  std::cout << " number of weqw " << n_eqw << std::endl;

#if 1
  //  generate fan in and fan out lists
  if (gen_fan_flag) {
    std::cout << "parsing fan in, fan out" << std::endl;

    for (uint ix = 0; ix < n_tot_var; ix++) {
      if (ix % 100 == 0) {
        std::cout << "\r parsing node " << ix << std::flush;
      }
      for (uint jx = 0; jx < n_tot_func; jx++) {
        auto templist = func_in_list[jx];

        if (1) { // c way
          for (uint kx = 0; kx < templist.size(); kx++) {
            if (ix == templist[kx]) {
              var_fan_out[ix] = var_fan_out[ix] + 1;
            }
          }
        } else { // matlab way
          // kx = find(templist==ix);
          // var_fan_out[ix] = var_fan_out[ix] + length(kx);
        }

        templist = func_out_list[jx];
        if (1) {
          for (uint kx = 0; kx < templist.size(); kx++) {
            if (ix == templist[kx]) {
              var_fan_in[ix] = var_fan_in[ix] + 1; // should always be max 1
            }
          }
        } else {
          // kx = find(templist==ix);
          // var_fan_in[ix] = var_fan_in[ix] + length(kx);
        }
      }
    }

  } else {
    std::cout << "not parsing fan in, fan out" << std::endl;
    var_fan_in.clear();
    var_fan_out.clear();
  }
#endif
  Analysis retVal;

  retVal.variables.in_fname = in_fname;
  retVal.variables.new_flag = new_flag;
  retVal.variables.n_tot = n_tot_var;
  retVal.variables.n_inputs = n_inputs;
  retVal.variables.n_in1_bits = n_in1_var;
  retVal.variables.n_in2_bits = n_in2_var;
  retVal.variables.n_out1_bits = n_out1_var;
  retVal.variables.high_water = var_high_water;
  retVal.variables.low_water = var_low_water;

  // var_life = var_high_water-var_low_water;
  std::transform(var_high_water.begin(), var_high_water.end(),
                 var_low_water.begin(), var_life.begin(), std::minus<int>());
  retVal.variables.life = var_life;

  retVal.variables.fan_in = var_fan_in;
  retVal.variables.fan_out = var_fan_out;

  unsigned int max_fan_in = *max_element(var_fan_in.begin(), var_fan_in.end());
  unsigned int max_fan_out =
      *max_element(var_fan_out.begin(), var_fan_out.end());
  unsigned int max_life = *max_element(var_life.begin(), var_life.end());

  std::cout << "max fan in (should be 1) = " << max_fan_in << std::endl;
  std::cout << "max fan out = " << max_fan_out << std::endl;
  std::cout << "max variable life = " << max_life << std::endl;

  retVal.functions.in_fname = in_fname;
  retVal.functions.n_tot = n_tot_func;
  retVal.functions.call_list = func_call_list;
  retVal.functions.in_list = func_in_list;
  retVal.functions.out_list = func_out_list;
  retVal.functions.n_and = n_and;
  retVal.functions.n_xor = n_xor;
  retVal.functions.n_not = n_not;
  retVal.functions.n_eq = n_eq;
  retVal.functions.n_eqw = n_eq;
  retVal.functions.names = func_names;

  return retVal;
}
