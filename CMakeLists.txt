cmake_minimum_required(VERSION 2.8)

project(hashtable)

#add_definitions(-std=c++17)

# generating build/compile_commands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_definitions(-march=native)
# add_definitions(-DENABLE_BLOOM_FILTER)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release")
    message(STATUS "No CMAKE_BUILD_TYPE selected, defaulting to ${CMAKE_BUILD_TYPE}")
endif()
set(CMAKE_C_FLAGS_DEBUG "$ENV{CFLAGS} -O0 -Wall -g -ggdb")
set(CMAKE_C_FLAGS_RELEASE "$ENV{CFLAGS} -O3 -Wall")
set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g -ggdb")
set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

set(ENV{PKG_CONFIG_PATH} "/usr/local/lib/x86_64-linux-gnu/pkgconfig")

find_package(PkgConfig)

message(STATUS "PKG_CONFIG_FOUND: ${PKG_CONFIG_FOUND}")
message(STATUS "PKG_CONFIG_VERSION_STRING: ${PKG_CONFIG_VERSION_STRING}")

pkg_search_module(DPDK libdpdk)

if (DPDK_FOUND) # DPDK >= 20.11
    message(STATUS "DPDK_INCLUDE_DIRS: ${DPDK_INCLUDE_DIRS}")
    set(CFLAGS ${CFLAGS} ${DPDK_CFLAGS})
    # set(LIBRARIES ${LIBRARIES} ${DPDK_LIBRARIES})
else()
    # DPDK include directory. Locating rte_config.h does not work on some systems.
    # Example: it may be kept in /usr/include/x86_64-linux-gnu/, and symlinked
    # from the real DPDK include directory (/usr/include/dpdk/).
    find_path(DPDK_INCLUDE_DIRS NAMES rte_ethdev.h PATH_SUFFIXES dpdk)
    if (DPDK_INCLUDE_DIRS)
        set(DPDK_LIBRARIES -Wl,--whole-archive dpdk -Wl,--no-whole-archive)
        message(STATUS "DPDK include directory = ${DPDK_INCLUDE_DIRS}")
    else()
        message(FATAL_ERROR "DPDK include directory not found. Please install DPDK.")
    endif()
endif()

add_definitions(-DENABLE_XXH3_64bits)

option(BENCH_ALWAYS_INLINE "Enable always inline" ON)
if (BENCH_ALWAYS_INLINE)
    message(STATUS "BENCH_ALWAYS_INLINE enabled")
    add_definitions(-DBENCH_ALWAYS_INLINE)
endif()

set(PUBLIC_HEADERS
    hashtable/dpdk.h
    hashtable/libcuckoo.h
    hashtable/unordered_map.h
)

set(LIBRARIES ${LIBRARIES} ${DPDK_LIBRARIES} xxhash pthread dl rt m numa yaml-cpp)

include_directories(${PROJECT_SOURCE_DIR})
set(SRCS
    hashtable/fsring.c
    hashtable/dpdk_hash.c
    hashtable/libcuckoo_hash.cc
    hashtable/libcuckoo_hash_nolock.cc
    hashtable/unordered_map_hash.cc
)

add_library(hashtable SHARED ${SRCS})
set_target_properties(hashtable PROPERTIES PUBLIC_HEADER "${PUBLIC_HEADERS}")
set_target_properties(hashtable PROPERTIES VERSION 1.0 SOVERSION 1)

add_library(hashtable_static STATIC ${SRCS})
set_target_properties(hashtable_static PROPERTIES OUTPUT_NAME "hashtable")
set_target_properties(hashtable_static PROPERTIES PUBLIC_HEADER "${PUBLIC_HEADERS}")

include(GNUInstallDirs)
install(TARGETS hashtable hashtable_static
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/hashtable)

# -DENABLE_TESTING=ON
option(ENABLE_TESTING "Enable make test" ON)
if (ENABLE_TESTING)
    # apt install libgtest-dev
    enable_testing()
    add_subdirectory(tests)
endif()

# -DENABLE_BENCH=ON
option(ENABLE_BENCH "Enable make bench" ON)
if (ENABLE_BENCH)
    # using the following command to install benchmark library
    # apt install libbenchmark-dev
    add_subdirectory(bench)
endif()
