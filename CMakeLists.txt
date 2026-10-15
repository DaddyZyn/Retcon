cmake_minimum_required(VERSION 3.20)
project(Retcon LANGUAGES CXX ASM_MASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(
        $<$<COMPILE_LANGUAGE:CXX>:/W4>
        $<$<COMPILE_LANGUAGE:CXX>:/permissive->
        $<$<COMPILE_LANGUAGE:CXX>:/utf-8>
        $<$<COMPILE_LANGUAGE:CXX>:/wd4324>
        $<$<COMPILE_LANGUAGE:CXX>:/wd4201>
    )
endif()

# Core static library
add_library(retcon STATIC
    src/retcon.cpp
    src/retcon_asm.asm
)

target_include_directories(retcon PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(retcon PUBLIC
    ntdll
    kernel32
)

# Test & verification harness
add_executable(retcon_test
    test/main.cpp
)

target_link_libraries(retcon_test PRIVATE
    retcon
)
