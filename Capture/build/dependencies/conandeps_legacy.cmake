message(STATUS "Conan: Using CMakeDeps conandeps_legacy.cmake aggregator via include()")
message(STATUS "Conan: It is recommended to use explicit find_package() per dependency instead")

find_package(libpcap)
find_package(cnats)

set(CONANDEPS_LEGACY  libpcap::libpcap  cnats::nats_static )