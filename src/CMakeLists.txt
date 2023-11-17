cmake_minimum_required(VERSION 3.0)

project(rdma_tracer)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_COMPILER "clang")

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_COMPILER "clang++")
add_compile_options(-g -O2 -static)

include_directories(${CMAKE_BINARY_DIR})
file(GLOB_RECURSE CPP_SOURCES "*.cpp")
add_executable(rdma_tracer ${CPP_SOURCES})

include_directories(
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_BINARY_DIR}/include 
    ${CMAKE_BINARY_DIR}/src/libbpf/include/uapi 
    ${CMAKE_SOURCE_DIR}/uprobe-headers
    )

add_dependencies(rdma_tracer uprobe_skel)

# Create a library from uprobe.bpf.c
add_library(uprobe_bpf OBJECT ${CMAKE_SOURCE_DIR}/src/uprobe.bpf.c)
target_compile_options(uprobe_bpf PRIVATE -target bpf -D__TARGET_ARCH_x86)
set_target_properties(uprobe_bpf PROPERTIES COMPILE_FLAGS "-xc")
add_dependencies(uprobe_bpf libbpf uprobe_bpf_program)
add_custom_target(uprobe_bpf_program DEPENDS ${CMAKE_SOURCE_DIR}/src/uprobe.bpf.c)

# Generate uprobe.skel.h from uprobe.bpf.o
add_custom_command(
    OUTPUT ${CMAKE_SOURCE_DIR}/src/uprobe.skel.h
    COMMAND cp $<TARGET_OBJECTS:uprobe_bpf> /tmp/uprobe.bpf.o
    COMMAND ${CMAKE_BINARY_DIR}/bpftool gen skeleton /tmp/uprobe.bpf.o > ${CMAKE_SOURCE_DIR}/src/uprobe.skel.h
    COMMAND rm /tmp/uprobe.bpf.o
    DEPENDS uprobe_bpf uprobe_bpf_program bpftool
)

target_link_libraries(
    rdma_tracer 
    ${CMAKE_BINARY_DIR}/lib64/libbpf.a 
    elf 
    z 
    pthread)

add_custom_target(uprobe_skel DEPENDS ${CMAKE_SOURCE_DIR}/src/uprobe.skel.h)

# Download and build libbpf
include(ExternalProject)
set(LIBBPF_ROOT ${CMAKE_BINARY_DIR}/src/libbpf)
set(LIBBPF_LIB_DIR ${LIBBPF_ROOT}/lib)
set(LIBBPF_INCLUDE_DIR ${LIBBPF_ROOT}/include)

set(LIBBPF_MAKE cd ${LIBBPF_ROOT}/src && make -j8 BUILD_STATIC_ONLY=1)
set(LIBBPF_INSTALL cd ${LIBBPF_ROOT}/src && make PREFIX=${CMAKE_BINARY_DIR} install)
ExternalProject_Add(libbpf
    GIT_REPOSITORY https://github.com/libbpf/libbpf.git
    GIT_TAG v1.2.0
    PREFIX ${CMAKE_BINARY_DIR}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ${LIBBPF_MAKE}
    INSTALL_COMMAND ${LIBBPF_INSTALL}
)
add_dependencies(rdma_tracer libbpf)

# Download and build bpftool 
include(ExternalProject)
set(BPFTOOL_ROOT ${CMAKE_BINARY_DIR}/src/bpftool)
set(BPFTOOL_MAKE cd ${BPFTOOL_ROOT}/src && make -j8)
set(BPFTOOL_INSTALL cd ${BPFTOOL_ROOT}/src && make -j8 && cp bpftool ${CMAKE_BINARY_DIR}/bpftool)
ExternalProject_Add(bpftool
    GIT_REPOSITORY https://github.com/libbpf/bpftool.git
    GIT_TAG v6.7.0
    PREFIX ${CMAKE_BINARY_DIR}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ${BPFTOOL_MAKE}
    INSTALL_COMMAND ${BPFTOOL_INSTALL}
)
add_dependencies(bpftool libbpf)



# add_custom_target(vmlinux.h DEPENDS ${CMAKE_SOURCE_DIR}/src/vmlinux.h)
# add_custom_command(
    # OUTPUT ${CMAKE_SOURCE_DIR}/src/vmlinux.h
    # COMMAND bpftool btf dump file /sys/kernel/btf/vmlinux format c > ${CMAKE_SOURCE_DIR}/src/vmlinux.h
# )

# set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
