cmake_minimum_required(VERSION 3.25)
project(rfc1035 C)

set(CMAKE_C_STANDARD 11)

include_directories(include)

add_executable(rfc1035 src/main.c include/rfc1035.h src/rfc1035.c)
