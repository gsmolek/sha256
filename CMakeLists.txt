cmake_minimum_required(VERSION 3.0)
project(sha256)

add_library(sha256 src/sha256.cpp)
target_include_directories(sha256 PUBLIC include/)