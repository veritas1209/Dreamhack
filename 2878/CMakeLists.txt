cmake_minimum_required(VERSION 3.16)
project(MTTDeploy LANGUAGES C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")

find_package(OpenSSL REQUIRED)

add_executable(mtt_server
    src/main.cpp
    src/prng.cpp
    src/crypto.cpp
    src/utils.cpp
    src/network.cpp
    src/server.cpp
    src/fips203/mlkem_native.c
    src/fips204/mldsa_native.c
)

set_source_files_properties(
    src/fips203/mlkem_native.c
    PROPERTIES COMPILE_DEFINITIONS "MLK_CONFIG_FILE=\"mtt_mlkem_config.h\""
)

set_source_files_properties(
    src/fips204/mldsa_native.c
    PROPERTIES COMPILE_DEFINITIONS "MLD_CONFIG_FILE=\"mtt_mldsa_config.h\""
)

target_include_directories(mtt_server PRIVATE
    src
    src/fips203
    src/fips204
)

target_link_libraries(mtt_server PRIVATE OpenSSL::Crypto)
