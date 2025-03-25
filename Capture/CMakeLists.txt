cmake_minimum_required(VERSION 3.15)
project(CATPURE_DEMO)

# Add include directories for ACE
include_directories(/usr/local/include)

# Link against the ACE library
link_directories(/usr/local/lib)

add_executable(main PacketSniffer.cpp)
add_executable(mainLive packetSnifferLive.cpp)

find_package(libpcap REQUIRED)
find_package(cnats REQUIRED)

target_link_libraries(main libpcap::libpcap)
target_link_libraries(main cnats::nats_static)
target_link_libraries(main ACE)
target_link_libraries(mainLive libpcap::libpcap)
target_link_libraries(mainLive ACE)
target_link_libraries(mainLive cnats::nats_static)
