cmake_minimum_required(VERSION 3.0)
project(miredify)

set(CMAKE_CXX_STANDARD 23)

add_executable(miredify main.cpp)
target_include_directories(miredify PRIVATE include)

find_package(Boost)
target_link_libraries(miredify boost::boost)
