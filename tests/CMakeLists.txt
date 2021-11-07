# using the following command to install gtest library
# apt install libgtest-dev
find_package(GTest REQUIRED)

set(CMAKE_BUILD_TYPE "Debug")

include_directories(${GTEST_INCLUDE_DIRS})

set(GTEST_LIBS ${GTEST_BOTH_LIBRARIES} pthread)

set(CMAKE_C_FLAGS "$ENV{CFLAGS} -Wno-incompatible-pointer-types")

add_executable(test_main test_main.cc)
set_target_properties(test_main PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(test_main ${GTEST_LIBS})

gtest_discover_tests(test_main)
