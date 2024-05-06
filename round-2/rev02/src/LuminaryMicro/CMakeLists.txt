cmake_minimum_required(VERSION 3.15)

add_library(drivers STATIC
        ustdlib.c
        osram128x64x4.c
)

target_include_directories(drivers
    PUBLIC ./
)

target_link_libraries(drivers
        ${CMAKE_CURRENT_LIST_DIR}/arm-none-eabi-gcc/libdriver.a
        ${CMAKE_CURRENT_LIST_DIR}/arm-none-eabi-gcc/libgr.a)
