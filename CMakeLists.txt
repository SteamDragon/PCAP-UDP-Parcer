cmake_minimum_required(VERSION 2.8)

project(PCAP-UDP-Parcer)
add_executable(${PROJECT_NAME} "main.cpp")
set(HEADER "optionparser.h")
SET(GCC_LIBRARIES_LINK_FLAGS    "-lpcap")
add_definitions(${GCC_LIBRARIES_LINK_FLAGS})
SET( CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} ${GCC_LIBRARIES_LINK_FLAGS}" )
target_link_libraries(${PROJECT_NAME} pcap)

