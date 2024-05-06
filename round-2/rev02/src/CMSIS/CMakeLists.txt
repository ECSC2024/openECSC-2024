cmake_minimum_required(VERSION 3.15)

add_library(cmsis STATIC
        Device/ARM/ARMCM3/Source/startup_ARMCM3.c
        Device/ARM/ARMCM3/Source/system_ARMCM3.c
)
target_include_directories(cmsis PUBLIC
        Device/ARM/ARMCM3/Include
        Core/Include
)