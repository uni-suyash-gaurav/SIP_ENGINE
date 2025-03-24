cmake_minimum_required(VERSION 3.15)
project(CATPURE_DEMO)

# Add include directories for ACE
include_directories(/usr/local/include)

# Link against the ACE library
link_directories(/usr/local/lib)

add_executable(main PacketSniffer.cpp)

find_package(libpcap REQUIRED)

target_link_libraries(main libpcap::libpcap)
target_link_libraries(main ACE)
