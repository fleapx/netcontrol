#include "gtest/gtest.h"
int main(int argc, char** argv)
{
    testing::InitGoogleTest(&argc, argv);
    printf("Start run test unit.\n");
    return RUN_ALL_TESTS();
}
