#include <gtest/gtest.h>

#include <iostream>
#include <vector>
#include <windows.h>

int main(int argc, char** argv) {
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}