cmake_minimum_required(VERSION 3.14)

project(PE-Parser VERSION 0.1 LANGUAGES CXX)

option(RUN_TESTS "Run GTests" ON)

include(cmake/UpdateSubmodules.cmake)

add_subdirectory(dependencies)

#Set Source and Include directories
set(SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/source)
set(INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

#Get cpp files to add to.dll
file(GLOB SRC_FILES ${SOURCE_DIR}/*.cpp)

if(RUN_TESTS)
	include(CTest)
	add_subdirectory(tests)
endif()

#Create .dll
add_library(PE-Parser SHARED ${SRC_FILES})

set_target_properties(PE-Parser PROPERTIES VERSION ${PROJECT_VERSION})

#add include folder to includes of library
target_include_directories(PE-Parser PUBLIC ${INCLUDE_DIR})

#cmake -B build -S . -G "MinGW Makefiles" && cd build && make && cd ..
#cmake -B build -S . -G "MinGW Makefiles" && cd build && make && cd tests && export GTEST_COLOR=1 && ./Tester.exe
