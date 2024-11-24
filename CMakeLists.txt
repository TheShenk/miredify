cmake_minimum_required(VERSION 3.0)
project(miredify)

set(CMAKE_CXX_STANDARD 23)

add_executable(miredify main.cpp)

find_package(Boost)
find_package(fmt)
target_link_libraries(miredify boost::boost fmt::fmt)
