cmake_minimum_required(VERSION 3.16)
project(ebpf_test C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ========== 基础配置 ==========
set(BPFTOOL_EXECUTABLE "/usr/local/bin/bpftool")
set(CLANG_EXECUTABLE "clang")

# ========== 查找依赖 ==========
find_path(LIBBPF_INCLUDE_DIR
  NAMES bpf/libbpf.h
  PATHS /usr/local/bpf/include /usr/include
  DOC "libbpf include directory"
)
find_library(LIBBPF_STATIC_LIB
  NAMES libbpf.a
  PATHS /usr/local/bpf/lib64 /usr/lib /usr/lib64
  DOC "libbpf static library"
)
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Libbpf
  REQUIRED_VARS LIBBPF_INCLUDE_DIR LIBBPF_STATIC_LIB BPFTOOL_EXECUTABLE
)
if(Libbpf_FOUND)
  message(STATUS "Found libbpf: ${LIBBPF_STATIC_LIB}")
  message(STATUS "Found bpftool: ${BPFTOOL_EXECUTABLE}")
endif()

find_library(LIBELF elf REQUIRED)
find_library(LIBZ z REQUIRED)
find_library(LIBPTHREAD pthread REQUIRED)
find_library(LIBM m REQUIRED)

# ========== 生成 vmlinux.h ==========
set(VMLINUX_H ${CMAKE_BINARY_DIR}/include/vmlinux.h)

add_custom_command(
  OUTPUT ${VMLINUX_H}
  COMMAND /bin/bash -c "mkdir -p ${CMAKE_BINARY_DIR}/include && ${BPFTOOL_EXECUTABLE} btf dump file /sys/kernel/btf/vmlinux format c > ${VMLINUX_H}"
  COMMENT "Generating vmlinux.h from BTF"
  VERBATIM
)

# ========== 公共头文件路径 ==========
set(EBPF_INCLUDE_DIRS
  ${CMAKE_BINARY_DIR}/include
  ${CMAKE_SOURCE_DIR}/include
  ${LIBBPF_INCLUDE_DIR}
)

# ========== eBPF 编译宏 ==========
#
# 使用方式:
#   ebpf_add_program(
#     NAME hello                    # 程序名（不含扩展名）
#     SRC hello.bpf.c              # BPF源码文件
#     USER_SRC hello.c             # 用户态源码文件（可选）
# )
#
macro(ebpf_add_program NAME)
  cmake_parse_arguments(ARG "" "NAME;SRC;USER_SRC" "" ${ARGN})

  set(BPF_SRC ${ARG_SRC})
  set(BPF_NAME ${ARG_NAME})
  set(USER_SRC ${ARG_USER_SRC})

  if(NOT BPF_SRC)
    message(FATAL_ERROR "ebpf_add_program: SRC is required")
  endif()

  if(NOT BPF_NAME)
    get_filename_component(BPF_NAME ${BPF_SRC} NAME_WE)
  endif()

  # 设置输出路径
  set(BPF_BYTECODE ${CMAKE_BINARY_DIR}/${BPF_NAME}.bpf.o)
  set(SKEL_HEADER ${CMAKE_BINARY_DIR}/${BPF_NAME}.skel.h)

  # 1. 编译 BPF 程序
  add_custom_command(
    OUTPUT ${BPF_BYTECODE}
    DEPENDS ${CMAKE_SOURCE_DIR}/${BPF_SRC} ${VMLINUX_H}
    COMMAND ${CLANG_EXECUTABLE} -g -O2 -target bpf -D__TARGET_ARCH_x86
            -I${CMAKE_BINARY_DIR}/include
            -I${CMAKE_SOURCE_DIR}/include
            -I${LIBBPF_INCLUDE_DIR}
            -c ${CMAKE_SOURCE_DIR}/${BPF_SRC}
            -o ${BPF_BYTECODE}
    COMMENT "Compiling BPF bytecode: ${BPF_SRC} → ${BPF_NAME}.bpf.o"
    VERBATIM
  )

  # 2. 生成 skeleton 头文件
  add_custom_command(
    OUTPUT ${SKEL_HEADER}
    DEPENDS ${BPF_BYTECODE}
    COMMAND ${BPFTOOL_EXECUTABLE} gen skeleton ${BPF_BYTECODE} > ${SKEL_HEADER}
    COMMENT "Generating skeleton: ${BPF_NAME}.skel.h"
    VERBATIM
  )

  # 添加依赖
  add_custom_target(generate_${BPF_NAME} ALL DEPENDS ${SKEL_HEADER})

  # 3. 编译用户态程序（如果指定）
  if(USER_SRC)
    set(USER_TARGET ${BPF_NAME})
    add_executable(${USER_TARGET} ${CMAKE_SOURCE_DIR}/${USER_SRC})

    target_include_directories(${USER_TARGET} PRIVATE
      ${CMAKE_BINARY_DIR}/include
      ${CMAKE_BINARY_DIR}
      ${CMAKE_SOURCE_DIR}/include
      ${LIBBPF_INCLUDE_DIR}
    )

    target_link_libraries(${USER_TARGET} PRIVATE
      ${LIBBPF_STATIC_LIB}
      ${LIBELF}
      ${LIBZ}
      ${LIBPTHREAD}
      ${LIBM}
    )

    target_compile_options(${USER_TARGET} PRIVATE -Wall -Wextra)

    add_dependencies(${USER_TARGET} generate_${BPF_NAME})

    # 安装用户态程序
    install(TARGETS ${USER_TARGET} RUNTIME DESTINATION bin)
    install(FILES ${BPF_BYTECODE} DESTINATION share/ebpf)

    message(STATUS "Added eBPF program: ${BPF_NAME}")
  else()
    message(STATUS "Added eBPF bytecode: ${BPF_NAME}")
  endif()
endmacro()

# ========== 添加 eBPF 程序 ==========

# hello 程序
ebpf_add_program(
  NAME hello
  SRC src/hello.bpf.c
  USER_SRC src/hello.c
)

# kprobe_unlink 程序
ebpf_add_program(
  NAME kprobe_unlink
  SRC src/kprobe_unlink.bpf.c
  USER_SRC src/kprobe_unlink.c
)

ebpf_add_program(
  NAME uprobe_add
  SRC src/uprobe_add.bpf.c
  USER_SRC src/uprobe_add.c
)
add_executable(uprobe_add_target src/uprobe_add_target.c)

# user_space_map - 直接测试 BPF map，不依赖 skel.h
add_executable(user_space_map src/user_space_map.c)
target_include_directories(user_space_map PRIVATE
  ${LIBBPF_INCLUDE_DIR}
)
target_link_libraries(user_space_map PRIVATE
  ${LIBBPF_STATIC_LIB}
  ${LIBELF}
  ${LIBZ}
  ${LIBPTHREAD}
  ${LIBM}
)

ebpf_add_program(
  NAME kernel_and_user_map
  SRC src/kernel_and_user_map.bpf.c
  USER_SRC src/kernel_and_user_map.c
)