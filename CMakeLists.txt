cmake_minimum_required(VERSION 3.24)

project(PE-Parser VERSION 0.1 LANGUAGES CXX)

set(Boost_USE_STATIC_RUNTIME ON)
set(Boost_COMPILER "mgw9")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(BOOST_ENABLE_CMAKE ON)

set(MAKE_TEST_EXE OFF CACHE BOOL "Make test executable & download/update GoogleTest via git submodule" FORCE)

set(BOOST_COMPONENTS date_time)

#if dependencies don't exist or are outdated - get them from github
include(cmake/UpdateSubmodules.cmake)

#Boost has to be installed on operating system
find_package(Boost REQUIRED COMPONENTS ${BOOST_COMPONENTS})

if(MAKE_TEST_EXE)
	set(GTEST_LINK gtest_main gmock_main)
	list(TRANSFORM GTEST_LINK PREPEND "GTest::")
	find_package(GTest)
endif()

#has to be after updateSubmodules
add_subdirectory(dependencies)

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
add_library(${PROJECT_NAME} SHARED ${SRC_FILES})
set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${PROJECT_VERSION})

#add all selected boost libraries
target_include_directories(${PROJECT_NAME} PUBLIC ${Boost_INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME} PUBLIC ${Boost_LIBRARIES})

#add include folder to includes of library
target_include_directories(${PROJECT_NAME} PUBLIC
		$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
		$<INSTALL_INTERFACE:include>
)

install(TARGETS ${PROJECT_NAME}
		EXPORT "${PROJECT_NAME}Targets"
		LIBRARY DESTINATION "lib"
		ARCHIVE DESTINATION "lib"
		RUNTIME DESTINATION "bin"
)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
		DESTINATION "include/"
)

install(EXPORT "${PROJECT_NAME}Targets"
		FILE "${PROJECT_NAME}Targets.cmake"
		NAMESPACE ${PROJECT_NAME}::
		DESTINATION "lib/cmake/${PROJECT_NAME}"
)

# Generate config file
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
		"${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
		VERSION ${PROJECT_VERSION}
		COMPATIBILITY AnyNewerVersion
)
configure_file("cmake/PE-ParserConfig.cmake.in"
		"${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
		@ONLY
)
install(FILES
		"${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
		"${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
		DESTINATION "lib/cmake/${PROJECT_NAME}"
)

#Building
#cmake -B build -S . -G "MinGW Makefiles" && cd build && make && cd ..

#Installing
#cmake --install build

#Building & Testing
#cmake -B build -S . -G "MinGW Makefiles" && cd build && make && cd tests && export GTEST_COLOR=1 && ./Tester.exe