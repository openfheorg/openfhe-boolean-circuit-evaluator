# CMakeLists.txt file for sources

find_package( Boost )

# oece stands for OpenFHE Encrypted Circuit Emulated
add_library( oecelib 
    analyze.cpp 
    assemble.cpp 
    circuit.cpp 
    gate.cpp 
    utils.cpp 
    wire.cpp 
)

# oecetest stands for OpenFHE Encrypted Circuit Emulated - Test
add_library( oecetestlib 
    test_adder.cpp 
    test_aes.cpp 
    test_comparator.cpp 
    test_crypto.cpp 
    test_multiplier.cpp 
    test_parity.cpp 
)
target_link_libraries( oecelib oecetestlib )
target_link_libraries( oecetestlib oecelib )

add_executable( TB_adders TB_adders.cpp )
add_executable( TB_adder_2bit TB_adder_2bit.cpp )
add_executable( TB_aes TB_aes.cpp )
add_executable( TB_comparators TB_comparators.cpp )
add_executable( TB_crypto TB_crypto.cpp )
add_executable( TB_multipliers TB_multipliers.cpp )
add_executable( TB_parity TB_parity.cpp )

target_link_libraries( TB_adders oecelib oecetestlib )
target_link_libraries( TB_adder_2bit oecelib oecetestlib )
target_link_libraries( TB_aes oecelib oecetestlib )
target_link_libraries( TB_comparators oecelib oecetestlib )
target_link_libraries( TB_crypto oecelib oecetestlib )
target_link_libraries( TB_multipliers oecelib oecetestlib )
target_link_libraries( TB_parity oecelib oecetestlib )
