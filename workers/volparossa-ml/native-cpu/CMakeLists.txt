# SPDX-License-Identifier: GPL-3.0-only
cmake_minimum_required(VERSION 3.25)
project(volparossa_llama_cpu LANGUAGES C CXX)
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" OR NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
  message(FATAL_ERROR "This explicit backend is Linux amd64 only")
endif()
if(NOT DEFINED VP_LLAMA_SOURCE)
  message(FATAL_ERROR "A verified local source checkout is required")
endif()
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_STANDARD 17)
option(VP_NATIVE_TESTS "Build bounded inert native ABI/upstream tensor checks" OFF)
option(VP_NATIVE_SANITIZE "Instrument source-only check artifacts, never provision them" OFF)
if(VP_NATIVE_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()
set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
foreach(flag BUILD_SHARED_LIBS LLAMA_BUILD_COMMON LLAMA_BUILD_TESTS LLAMA_BUILD_TOOLS
    LLAMA_BUILD_EXAMPLES LLAMA_BUILD_SERVER LLAMA_BUILD_APP LLAMA_BUILD_UI
    LLAMA_OPENSSL LLAMA_SUBPROCESS LLAMA_LLGUIDANCE LLAMA_USE_SYSTEM_GGML
    GGML_NATIVE GGML_BACKEND_DL GGML_CPU_ALL_VARIANTS GGML_OPENMP GGML_OPENMP_FETCH
    GGML_BLAS GGML_CUDA GGML_HIP GGML_METAL GGML_VULKAN GGML_SYCL GGML_RPC
    GGML_CPU_KLEIDIAI GGML_CPU_HBM GGML_CPU_REPACK GGML_CCACHE
    GGML_SSE42 GGML_BMI2 GGML_AVX_VNNI GGML_AVX512
    GGML_AVX512_VBMI GGML_AVX512_VNNI GGML_AVX512_BF16 GGML_AMX_TILE GGML_AMX_INT8 GGML_AMX_BF16)
  set(${flag} OFF CACHE BOOL "Explicit fixed CPU build" FORCE)
endforeach()
set(GGML_AVX ON CACHE BOOL "" FORCE)
set(GGML_AVX2 ON CACHE BOOL "" FORCE)
set(GGML_FMA ON CACHE BOOL "" FORCE)
set(GGML_F16C ON CACHE BOOL "" FORCE)
set(GGML_LLAMAFILE ON CACHE BOOL "" FORCE)
set(GGML_CPU ON CACHE BOOL "" FORCE)
add_subdirectory("${VP_LLAMA_SOURCE}" llama EXCLUDE_FROM_ALL)
# Keep the pinned checkout pristine. Only this exact source is replaced, and
# build_llama_cpu.py verifies its digest and actual compilation-database entry.
if(NOT IS_ABSOLUTE "${VP_LLAMA_MODEL_LOADER}" OR NOT EXISTS "${VP_LLAMA_MODEL_LOADER}")
  message(FATAL_ERROR "The verified staged model loader is required")
endif()
get_target_property(llama_source_dir llama SOURCE_DIR)
get_target_property(llama_sources llama SOURCES)
set(effective_sources)
set(loader_replacements 0)
foreach(source IN LISTS llama_sources)
  if(NOT IS_ABSOLUTE "${source}")
    get_filename_component(source "${source}" ABSOLUTE BASE_DIR "${llama_source_dir}")
  endif()
  if(source STREQUAL "${VP_LLAMA_SOURCE}/src/llama-model-loader.cpp")
    list(APPEND effective_sources "${VP_LLAMA_MODEL_LOADER}")
    math(EXPR loader_replacements "${loader_replacements} + 1")
  else()
    list(APPEND effective_sources "${source}")
  endif()
endforeach()
if(NOT loader_replacements EQUAL 1)
  message(FATAL_ERROR "Expected exactly one original model loader")
endif()
set_property(TARGET llama PROPERTY SOURCES "${effective_sources}")
set_source_files_properties("${VP_LLAMA_MODEL_LOADER}" TARGET_DIRECTORY llama
    PROPERTIES SKIP_UNITY_BUILD_INCLUSION ON)
add_library(volparossa_llama_cpu SHARED adapter.cpp)
target_link_libraries(volparossa_llama_cpu PRIVATE llama)
target_compile_options(volparossa_llama_cpu PRIVATE -Wall -Wextra -Werror)
target_link_options(volparossa_llama_cpu PRIVATE -static-libstdc++ -static-libgcc
    "-Wl,--exclude-libs,ALL" "-Wl,-z,defs" "-Wl,-z,relro,-z,now")
set_target_properties(volparossa_llama_cpu PROPERTIES BUILD_RPATH "" INSTALL_RPATH "")
if(VP_NATIVE_TESTS)
  add_executable(vp-native-abi-smoke abi-smoke.cpp)
  target_compile_options(vp-native-abi-smoke PRIVATE -UNDEBUG)
  target_link_libraries(vp-native-abi-smoke PRIVATE volparossa_llama_cpu)
  # Launch/join statements are extracted from the exact staged loader. This
  # exercises real ggml validation on tiny F32 arrays, never loads a model.
  add_executable(vp-native-loader-validation loader-validation.cpp)
  get_filename_component(loader_overlay_dir "${VP_LLAMA_MODEL_LOADER}" DIRECTORY)
  target_include_directories(vp-native-loader-validation PRIVATE "${loader_overlay_dir}")
  target_compile_options(vp-native-loader-validation PRIVATE -UNDEBUG)
  target_link_libraries(vp-native-loader-validation PRIVATE ggml)
  # Unchanged upstream test, generated toy tensors only. No model files or CLI.
  add_executable(vp-upstream-tensor-tests "${VP_LLAMA_SOURCE}/tests/test-quantize-fns.cpp")
  target_link_libraries(vp-upstream-tensor-tests PRIVATE ggml ggml-cpu)
  # Separate BF16/F32-only proof; never replaces the all-type target above.
  add_executable(vp-native-bf16-tensors bf16-tensors.cpp)
  target_compile_definitions(vp-native-bf16-tensors PRIVATE
      VP_UPSTREAM_TEST_FILE="${VP_LLAMA_SOURCE}/tests/test-quantize-fns.cpp")
  target_link_libraries(vp-native-bf16-tensors PRIVATE ggml ggml-cpu)
endif()
