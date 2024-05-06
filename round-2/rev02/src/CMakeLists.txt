cmake_minimum_required(VERSION 3.15)  # CMake version check
project(arxelerated)               # Create project "simple_example"

set(CMAKE_CXX_STANDARD 23)            # Enable c++20 standard

# Set linker script for machine target
set(LINKER_SCRIPT "${PROJECT_SOURCE_DIR}/linker.ld")
include(board.cmake)

# Add main.cpp file of the project root directory as a source file
set(SOURCE_FILES
        main.c
        coprocessor.c
)

# Add executable target with source files listed in SOURCE_FILES variable
add_executable(firmware ${SOURCE_FILES})
target_include_directories(
        firmware
        PUBLIC
        include
)

# ARM CMSIS
add_subdirectory(CMSIS)
target_link_libraries(firmware cmsis)

# LuminaryMicro Board Support Package
add_subdirectory(LuminaryMicro)
target_link_libraries(firmware drivers)
