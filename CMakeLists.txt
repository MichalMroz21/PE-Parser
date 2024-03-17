cmake_minimum_required(VERSION 3.24)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

#Some libraries are header-only and some require building, this separation is required as boost is added both with find_package and submodules
#As described here: https://www.boost.org/doc/libs/1_84_0/more/getting_started/windows.html#header-only-libraries
#The name has to be BOOST_INCLUDE_LIBRARIES!
set(BOOST_INCLUDE_LIBRARIES algorithm describe type_index endian)
set(BOOST_BUILD_LIBRARIES)
set(BOOST_ENABLE_CMAKE ON)

#Set Parser Source and Include directories
set(CMAKE_DIR ${CMAKE_CURRENT_LIST_DIR}/cmake)
set(INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/source)

option(MAKE_TEST_EXE "Run GTests" ON)

project(PE-Parser VERSION 0.1 LANGUAGES CXX)

#if dependencies don't exist or are outdated - get them from github
include(${CMAKE_DIR}/UpdateSubmodules.cmake)

#Boost and GTest can be downloaded via git submodules
find_package(Boost 1.81 COMPONENTS ${BOOST_BUILD_LIBRARIES})
find_package(GTest)

#has to be after updateSubmodules
add_subdirectory(dependencies)

#Transform library names into proper form for linking
list(TRANSFORM BOOST_BUILD_LIBRARIES PREPEND "Boost::")
list(TRANSFORM BOOST_INCLUDE_LIBRARIES PREPEND "Boost::")

#Combine 2 lists into one
list(APPEND BOOST_LIBRARIES ${BOOST_BUILD_LIBRARIES})
list(APPEND BOOST_LIBRARIES ${BOOST_INCLUDE_LIBRARIES})

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
target_link_libraries(PE-Parser PRIVATE ${GTEST_LINK} ${BOOST_LIBRARIES})

#add include folder to includes of library
target_include_directories(PE-Parser PUBLIC ${INCLUDE_DIR})

if(${Boost_FOUND})
    target_include_directories(PE-Parser PUBLIC ${Boost_INCLUDE_DIRS})
endif()

#cmake -B build -S . -G "MinGW Makefiles" && cd build && make && cd ..
#cmake -B build -S . -G "MinGW Makefiles" && cd build && make && cd tests && export GTEST_COLOR=1 && ./Tester.exe