# Copyright 2021 Qiying Wang. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# using the following command to install benchmark library
# apt install libbenchmark-dev
find_package(benchmark REQUIRED)

set(CMAKE_BUILD_TYPE "Debug")

add_executable(bench_main
    main.cc
    hash_table_bench.cc
)

target_link_libraries(bench_main
    benchmark
    benchmark_main
    benchhash
    ${LIBRARIES}
)

add_custom_target(bench
    COMMAND ./bench_main
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR} # build/bench/
)
