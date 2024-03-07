#include <gtest/gtest.h>

#include <iostream>

int GetMeaningOfLife() {
	return 42;
}

TEST(TestTopic, TrivialEquality) {
	EXPECT_EQ(GetMeaningOfLife(), 42);
}

TEST(TestTopic, MoreEqualityTests) {
	ASSERT_EQ(GetMeaningOfLife(), 0);
}

int main(int argc, char** argv) {
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}