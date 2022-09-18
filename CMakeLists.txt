cmake_minimum_required(VERSION 3.10)

project(capstone-tricore-test VERSION 1.0) 

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(SRCS src/main.cpp)

include_directories(capstone/include)
include_directories(pe-parse/pe-parser-library/include)

add_subdirectory(capstone)
add_subdirectory(pe-parse) 

add_executable(capstone-tricore-test ${SRCS})
target_link_libraries(capstone-tricore-test capstone-static pe-parse::pe-parse) 
