cmake_minimum_required(VERSION 3.21)
project(virtfuzz)

# Set Clang as the compiler
set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Default to release build if not specified
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Set the build type options
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_CXX_FLAGS_LOG "-O3 -DSTATISTICS")
set(CMAKE_CXX_FLAGS_STATISTICS "-O3 -DSTATISTICS -DNDEBUG")

# Add AddressSanitizer flags only for Debug build
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address")
  set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fsanitize=address")
endif()

find_package(Protobuf 3.20 REQUIRED)
include_directories(${Protobuf_INCLUDE_DIRS})

set(PROTO_FILES ${CMAKE_CURRENT_SOURCE_DIR}/messages.proto ${CMAKE_CURRENT_SOURCE_DIR}/device.proto)
protobuf_generate(
    LANGUAGE cpp
    PROTOS ${PROTO_FILES}
    OUT_VAR PROTO_SRCS
)

# Include directories
include_directories(${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Source files
set(SRC src/generator.cpp src/mutator.cpp src/virtfuzz.cpp src/device.cpp src/common.cpp src/statistics.cpp ${PROTO_SRCS})

# Create a shared library
add_library(virtfuzz STATIC ${SRC})

# Link against protobuf library and conditionally link AddressSanitizer for Debug build
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  target_link_libraries(virtfuzz protobuf::libprotobuf -fsanitize=address)
else()
  target_link_libraries(virtfuzz protobuf::libprotobuf)
endif()

# Install target and headers
install(TARGETS virtfuzz DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)
