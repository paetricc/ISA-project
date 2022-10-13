CMAKE_MINIMUM_REQUIRED(VERSION 3.12)
PROJECT(ISA-project VERSION 1.0.0)

SET(CMAKE_CXX_STANDARD 14)

ADD_EXECUTABLE(run flow.cpp)

include(FindPCAP.cmake)

ADD_LIBRARY(libs SHARED pcap.cpp arguments.cpp udp-client.cpp)
TARGET_LINK_LIBRARIES(run libs)
target_link_libraries(run ${PCAP_LIBRARY})