Encrypted Boolean Circuit Emulator
==================================

![OpenFHE_logo](logo.png "OpenFHE")

This is a demonstration application using OPENFHE's binfhe module for
encrypted boolean logic.

The demonstration programs here read in boolean circuits using
multiple formats and will execute them in encrypted form. In general
each example program performs the following steps:

- Step 1 analyze input file for I/O and other infomation (depth etc)

- Step 2 translate the input to an intermediate "assembler" file description 

- Step 3 tests the function using C++ equivalent to generate test
  vectors, or use known test vectors if supplied

- Step 4 run the file in a Plaintext circuit evaluation mode and verify output

- Step 5 repeats with an Encrypted Circuit Evaluation. A flag can be
  thrown that allows gate by gate verification (it does a parallel
  plaintext circuit evaluation). If therre is an error, the error is
  corrected. -- Note this was added for us to debug OPENFHE's
  implementations.


Note that steps 1 and 2 only need be done once, the output is stored
in a file. This can speed up working with big circuits.

Input formats supported
-----------------------

Currently only the old bristol fashion input file is supported
https://homes.esat.kuleuven.be/~nsmart/MPC/old-circuits.html

These inputs are in `examples/old_bristol_ckts`.

Newer bristol fashion circuits are planned to be supported soon. Some might work already.

See the Todo list at the bottom of the file.

CURRENT STATUS
--------------
This code is rewrite of old Matlab code originally built by BBN/NJIT for the 
DARPA Proceed program. The port implements a different approach to circuit emulation
that allows parallel execution of encrypted gates, and dynamic memory allocation for circuit nodes (wires / registers). 

### Status as of 8/12/2020

Execution of gates now parallelized. Circuit management not
parallelized and algorithm is now a choke point (is still single thread
that generates execution tasks, and does many searches). However, for encrypted circuits the overhead is small (less than a few percent). 
Add FF and clocked circuits

### Status as of 11/2/2022

Migrated to OpenFHE.

Todo:
-----

* Note: code to analyze reuse of registers/nodes is broken. so is code
  to compute ciruit depth, as it is not needed for FHEW. may want to
  rewrite analysis/assembler/circuit code.

* Add and test new bristol fashion format
<https://homes.esat.kuleuven.be/~nsmart/MPC/>
these inputs are in `examples/new_bristol_ckts`.

and the Goldfeder circutis
<http://stevengoldfeder.com/projects/circuits/sha2circuit.html>

also we need to eventually check out 
<https://pypi.org/project/bfcl/>


* Add parser for other input file formats. 

* generalize input and output to multiple registers of arbitrary bitwidths

* allow encrypted I/O (i.e. do not decrypt by default)

* Speed up circuit management representation, possibly with linked list

* add command line flags for other parameter sets afforded by OpenFHE

* split TB_crypto into md5 and sha256 test benches, since the combined code takes extremely long
to run

Building the system
-------------------

### Build instructions for Ubuntu

Please note that we have not tried installing this on windows or
macOS. If anyone does try this, please update this file with
instructions.  It's recommended to use at least Ubuntu 18.04, and gnu g++ 7 or greater.


1. Install pre-requisites (if not already installed):
`g++`, `cmake`, `make`, and `autoconf`. Sample commands using `apt-get` are listed below. It is possible that these are already installed on your system.

```bash
$ sudo apt-get install build-essential #this already includes g++`
$ sudo apt-get install autoconf
$ sudo apt-get install make
$ sudo apt-get install cmake
```

> Note that `sudo apt-get install g++-<version>` can be used to
install a specific version of the compiler. You can use `g++
--version` to check the version of `g++` that is the current system
default.

2. Install OPENFHE on your system. This code was tested with pre-release 1.10.3. Note we have not tested the circuit emulator with the 32 bit build of OPENFHE.

Full instructions for this are to be found in the `README.md` file in the [OPENFHE repo](https://github.com/openfheorg/openfhe-development).

Run `make install` at the end to install the system to the default
location (you can change this location, but then you will have to
change the Makefile in this repo to reflect the new location).

3. Clone this repo onto your system.

4. Create the build directory

```bash
$ mkdir build
```

5. Build the system using make

```bash
cd build
cmake ..
make
```

All the examples will be in the `build/bin` directory. All input files, and resulting assembler outputs will be in various subdirectories under `build/examples`.

Running Simple Examples
=======================

There are two simple examples:

- `TB_adder_2bit` - runs a simple 2 bit adder. 4 bits in , 3 bits out
- `TB_parity` - runs a circuit twice to generate and then check parity for 8 bit input. 
				
The assembled circuit descriptions for these examples were generated by
hand and are in `examples/simple_ckts/adder/adder_2bit.out` and
`examples/simple_ckts/parity/parity.out`

Note the following command line flags are valid (defaults shown in [ ].

```
-a assemble flag (false) note, if true then analyze must be true
-f fanout generation flag (false)
-z analyze flag (false)
-c # test cases [4]
-n # test loops [10]
-s parameter set (TOY|STD128_OPT) [STD128_OPT]
-m method (AP|GINX) [GINX] 
-v verbose flag (false)

h prints this message

```

> Note that for these two simple examples the `-a -f -z -c` flags, while listed, have no effect.

It is easiest to run from your `build` directory as follows:
` cd build`

`bin/TB_adder_2bit -s STD128_OPT -m GINX -v`


Also note that OpenFHE supports other settings for parameter set,
which will be added in later releases.

Running Complicated Examples
============================
There are currently four more complex examples in order of increasing run time.

- `TB_comparators` - tests old bristol style comparator circuits
- `TB_adders` - tests old bristol style adder circuits
- `TB_multipliers` -  tests old bristol style adder circuits
- `TB_crypto` - tests old bristol style md5 and sha circuits
- `TB_aes` - tests old bristol style AES expanded and non-expanded circuits


For all examples you should run the program once with the `-a -z` flags set
in order to generate assembler output. The assembler output for input
case `foo.txt` will be `foo_FHE.out`. The FHE is to indicate that
there is no impled circuit depth limit, i.e. no explicit bootstrapping
will be needed. This is a holdover from an older SHE system design.

Note that the `-s TOY` setting can be used when assembling the
circuit, as the result is indepenent of the crypto parameter
used. `TOY` is only good for debugging and verifying functional
correctness -- it has no security!

Once these files are generated you can run that demo case with
different settings, without the `-a -z` flags set.

More details on each demo:
--------------------------

`TB_comparators` runs the following test cases: 

- `comparator_32bit_unsigned_lteq.txt` 
- `comparator_32bit_unsigned_lt.txt`
- `comparator_32bit_signed_lteq.txt`
- `comparator_32bit_signed_lt.txt`

These are combinations of 32 bit unsigned and unsigned less-than or
less-than-or-equal comparisons.

`TB_adders` runs the `adder_32bit.txt` and   `adder_64bit.txt` test cases. 

`TB_multipliers` runs the single `mult_32x32.txt` test case.

`TB_crypto` runs the `md5.txt` and `sha-256.txt` test cases. Note
these take a long time to run typically.

`TB_aes` runs the `AES-expanded.txt` and `AES-non-expanded.txt` test
cases. Note these take a VERY long time to run typically.


Note that while other crypto curciuts are in the
`examples/old_bristol_ckts/crypto` directory, we currently do not have
test vectors for any of them, so we did not build any test bench
programs.

We suggest that for these larger cases, you run on a multicore machine
with at least 8 GB ram. The encrypted circuit evaluator will evaluate
excrypted gates in parallel, up to the number of OMP threads specified
through the environment variable (the default is usually the number of
cpus on the system).

Also note that the current netlist generator is not very efficient, so
that large circuits such as the crypto circuits take a very long time
to set up. This is something on the list of things to optimize.

Acknowledgements: 
-----------------

This system has been developed with support from the DARPA MARSHALL
program. Portions of the code were based on MATLAB code previously
developed for the DARPA PROCEED program.

The port of this system to OpenFHE was funded by Duality Technologies.
