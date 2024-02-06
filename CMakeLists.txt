cmake_minimum_required(VERSION 3.12)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_TRY_COMPILE_TARGET_TYPE "STATIC_LIBRARY")

project(openssl-aes CXX C ASM)

# Set Release build type if not specified
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# General compiler optimization flags
set(CMAKE_CXX_FLAGS "-Wall -Wextra")
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")  # Highest level of optimization

# Processor-specific optimizations
include(CheckCXXCompilerFlag)

# Function to add a compiler flag if supported
function(add_cxx_compiler_flag flag)
  string(FIND "${CMAKE_CXX_FLAGS}" "${flag}" flag_already_set)
  if(flag_already_set EQUAL -1)
    check_cxx_compiler_flag("${flag}" flag_supported)
    if(flag_supported)
      set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${flag}" PARENT_SCOPE)
    endif()
  endif()
endfunction()

# Add flags here if supported
add_cxx_compiler_flag("-march=native")  # Optimize for the local machine's architecture
add_cxx_compiler_flag("-flto")          # Enable Link Time Optimization
add_cxx_compiler_flag("-funroll-loops") # Enable loop unrolling

include_directories (
	${CMAKE_SOURCE_DIR}/src
)

add_library(
	openssl-aes 
	src/aes_core.c
	src/aes_misc.c
	src/aes_cbc.c
)