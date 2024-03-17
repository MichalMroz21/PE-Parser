if(BUILD_TESTING)
	enable_testing()

	file(GLOB_RECURSE TEST_FILES ${CMAKE_CURRENT_LIST_DIR}/*.cpp)

	add_executable(Tester ${TEST_FILES} ${SRC_FILES})

	target_include_directories(Tester PUBLIC ${INCLUDE_DIR})

    if(${Boost_FOUND})
        target_include_directories(Tester PUBLIC ${Boost_INCLUDE_DIRS})
    endif()

    #test also requires boost libraries, since it uses Parser
	target_link_libraries(Tester PRIVATE ${GTEST_LINK} ${BOOST_LIBRARIES})

	include(GoogleTest)

	gtest_discover_tests(Tester)
endif()
