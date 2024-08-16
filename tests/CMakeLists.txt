if(BUILD_TESTING)
	enable_testing()

	file(GLOB_RECURSE TEST_FILES ${CMAKE_CURRENT_LIST_DIR}/*.cpp)

	add_executable(Tester ${TEST_FILES} ${SRC_FILES})

	target_include_directories(Tester PRIVATE ${Boost_INCLUDE_DIRS})
	target_link_libraries(Tester PRIVATE ${GTEST_LINK} ${Boost_LIBRARIES})

	target_include_directories(Tester PUBLIC ${INCLUDE_DIR})

    #test also requires boost libraries, since it uses Parser
	target_link_libraries(Tester PRIVATE ${GTEST_LINK})

	include(GoogleTest)

	gtest_discover_tests(Tester)
endif()