cmake_minimum_required(VERSION 3.15)
project(CATPURE_DEMO)

# Add include directories for ACE
include_directories(/usr/local/include)

# Link against the ACE library
link_directories(/usr/local/lib)

# Include directory for headers
include_directories(${CMAKE_SOURCE_DIR}/include)

add_executable(packetSniffer src/PacketSniffer.cpp)
add_executable(packetSnifferLive src/packetSnifferLive.cpp)
add_executable(jsSubscriber src/parserSubscriber.cpp)

find_package(libpcap REQUIRED)
find_package(cnats REQUIRED)

target_link_libraries(packetSniffer libpcap::libpcap cnats::nats_static)
target_link_libraries(packetSniffer ACE)
target_link_libraries(packetSnifferLive libpcap::libpcap cnats::nats_static)
target_link_libraries(packetSnifferLive ACE)
target_link_libraries(jsSubscriber cnats::nats_static)
