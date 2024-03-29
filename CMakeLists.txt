cmake_minimum_required(VERSION 3.24)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(BOOST_INCLUDE_LIBRARIES describe type_index endian algorithm variant)
set(BOOST_ENABLE_CMAKE ON)

set(GTEST_LINK GTest::gtest_main GTest::gmock_main)

option(MAKE_TEST_EXE "Run GTests" ON)

project(PE-Parser VERSION 0.1 LANGUAGES CXX)

#if dependencies don't exist or are outdated - get them from github
include(cmake/UpdateSubmodules.cmake)

#has to be after updateSubmodules
add_subdirectory(dependencies)

#has to be after add_subdirectory(dependencies)
list(TRANSFORM BOOST_INCLUDE_LIBRARIES PREPEND "Boost::")

#Set Parser Source and Include directories
set(SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/source)
set(INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

#Get cpp files to add to Parser
file(GLOB_RECURSE SRC_FILES ${SOURCE_DIR}/*.cpp)

if(MAKE_TEST_EXE)
	include(CTest)
	add_subdirectory(tests)
endif()

#Create .dll
add_library(PE-Parser SHARED ${SRC_FILES})
set_target_properties(PE-Parser PROPERTIES VERSION ${PROJECT_VERSION})

#add all selected boost libraries
target_link_libraries(PE-Parser PRIVATE ${GTEST_LINK} ${BOOST_INCLUDE_LIBRARIES})

#add include folder to includes of library
target_include_directories(PE-Parser PUBLIC ${INCLUDE_DIR})

#cmake -B build -S . -G "MinGW Makefiles" && cd build && make && cd ..
#cmake -B build -S . -G "MinGW Makefiles" && cd build && make && cd tests && export GTEST_COLOR=1 && ./Tester.exe