if(${Boost_FOUND})
    set(BOOST_INCLUDE_LIBRARIES "" PARENT_SCOPE)
else()
    update_submodule("${CMAKE_CURRENT_LIST_DIR}/boost")
    add_subdirectory(boost)
endif()

if(${GTest_FOUND})
    set(GTEST_LINK gtest_main gmock_main PARENT_SCOPE)
else()
    update_submodule("${CMAKE_CURRENT_LIST_DIR}/googletest")
    add_subdirectory(googletest)
    set(GTEST_LINK GTest::gtest_main GTest::gmock_main PARENT_SCOPE)
endif()