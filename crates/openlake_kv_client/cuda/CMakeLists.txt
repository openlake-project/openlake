cmake_minimum_required(VERSION 3.22)

project(OpenLakeKvCudaCodec VERSION 0.1.0 LANGUAGES CXX CUDA)

find_package(CUDAToolkit 12.0 REQUIRED)

if(NOT DEFINED CMAKE_CUDA_ARCHITECTURES)
  set(CMAKE_CUDA_ARCHITECTURES 80 89 90)
endif()

add_library(openlake_kv_cuda_codec STATIC
  src/kv_compression.cu
)

target_include_directories(openlake_kv_cuda_codec
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(openlake_kv_cuda_codec
  PUBLIC
    CUDA::cudart
)

target_compile_features(openlake_kv_cuda_codec PUBLIC cxx_std_17)

target_compile_options(openlake_kv_cuda_codec
  PRIVATE
    $<$<COMPILE_LANGUAGE:CUDA>:--expt-relaxed-constexpr>
    $<$<COMPILE_LANGUAGE:CUDA>:-lineinfo>
)

set_target_properties(openlake_kv_cuda_codec PROPERTIES
  CUDA_STANDARD 17
  CUDA_STANDARD_REQUIRED ON
  POSITION_INDEPENDENT_CODE ON
)

option(OPENLAKE_CUDA_CODEC_BUILD_TESTS "Build the CUDA codec GPU smoke test" ON)
option(OPENLAKE_EXPANS_BUILD "Build the optional lossless ExpANS codec" OFF)

if(OPENLAKE_CUDA_CODEC_BUILD_TESTS)
  include(CTest)
endif()

if(OPENLAKE_EXPANS_BUILD)
  set(NVCOMP_ROOT "" CACHE PATH "Path to nvCOMP")
  find_package(nvcomp REQUIRED CONFIG PATHS
    "${NVCOMP_ROOT}/lib/cmake/nvcomp"
    "${NVCOMP_ROOT}/lib64/cmake/nvcomp"
  )

  add_library(openlake_expans SHARED
    src/expans_codec.cu
  )
  target_include_directories(openlake_expans
    PUBLIC
      ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}/src
  )
  target_link_libraries(openlake_expans
    PRIVATE
      CUDA::cudart
      nvcomp::nvcomp
  )
  target_compile_features(openlake_expans PUBLIC cxx_std_17)
  target_compile_options(openlake_expans PRIVATE
    $<$<COMPILE_LANGUAGE:CUDA>:--expt-relaxed-constexpr>
  )
  set_target_properties(openlake_expans PROPERTIES
    CUDA_STANDARD 17
    CUDA_STANDARD_REQUIRED ON
  )

  if(OPENLAKE_CUDA_CODEC_BUILD_TESTS)
    add_executable(openlake_expans_test tests/expans_codec_test.cu)
    target_link_libraries(openlake_expans_test PRIVATE openlake_expans CUDA::cudart)
    set_target_properties(openlake_expans_test PROPERTIES
      CUDA_STANDARD 17
      CUDA_STANDARD_REQUIRED ON
    )
    add_test(NAME openlake_expans_test COMMAND openlake_expans_test)
  endif()
endif()

if(OPENLAKE_CUDA_CODEC_BUILD_TESTS)
  add_executable(openlake_kv_cuda_codec_smoke
    tests/kv_compression_smoke.cu
  )
  target_link_libraries(openlake_kv_cuda_codec_smoke
    PRIVATE
      openlake_kv_cuda_codec
      CUDA::cudart
  )
  target_compile_features(openlake_kv_cuda_codec_smoke PRIVATE cxx_std_17)
  set_target_properties(openlake_kv_cuda_codec_smoke PROPERTIES
    CUDA_STANDARD 17
    CUDA_STANDARD_REQUIRED ON
  )
  add_test(NAME openlake_kv_cuda_codec_smoke COMMAND openlake_kv_cuda_codec_smoke)
endif()
