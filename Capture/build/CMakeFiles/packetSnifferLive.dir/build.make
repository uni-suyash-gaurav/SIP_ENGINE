# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.28

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = "/mnt/c/Users/102151/OneDrive - UNIPHORE SOFTWARE SYSTEMS PVT LTD/Documents/SIP_ENGINE/Capture"

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = "/mnt/c/Users/102151/OneDrive - UNIPHORE SOFTWARE SYSTEMS PVT LTD/Documents/SIP_ENGINE/Capture/build"

# Include any dependencies generated for this target.
include CMakeFiles/packetSnifferLive.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/packetSnifferLive.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/packetSnifferLive.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/packetSnifferLive.dir/flags.make

CMakeFiles/packetSnifferLive.dir/src/packetSnifferLive.cpp.o: CMakeFiles/packetSnifferLive.dir/flags.make
CMakeFiles/packetSnifferLive.dir/src/packetSnifferLive.cpp.o: /mnt/c/Users/102151/OneDrive\ -\ UNIPHORE\ SOFTWARE\ SYSTEMS\ PVT\ LTD/Documents/SIP_ENGINE/Capture/src/packetSnifferLive.cpp
CMakeFiles/packetSnifferLive.dir/src/packetSnifferLive.cpp.o: CMakeFiles/packetSnifferLive.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir="/mnt/c/Users/102151/OneDrive - UNIPHORE SOFTWARE SYSTEMS PVT LTD/Documents/SIP_ENGINE/Capture/build/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/packetSnifferLive.dir/src/packetSnifferLive.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/packetSnifferLive.dir/src/packetSnifferLive.cpp.o -MF CMakeFiles/packetSnifferLive.dir/src/packetSnifferLive.cpp.o.d -o CMakeFiles/packetSnifferLive.dir/src/packetSnifferLive.cpp.o -c "/mnt/c/Users/102151/OneDrive - UNIPHORE SOFTWARE SYSTEMS PVT LTD/Documents/SIP_ENGINE/Capture/src/packetSnifferLive.cpp"

CMakeFiles/packetSnifferLive.dir/src/packetSnifferLive.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/packetSnifferLive.dir/src/packetSnifferLive.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E "/mnt/c/Users/102151/OneDrive - UNIPHORE SOFTWARE SYSTEMS PVT LTD/Documents/SIP_ENGINE/Capture/src/packetSnifferLive.cpp" > CMakeFiles/packetSnifferLive.dir/src/packetSnifferLive.cpp.i

CMakeFiles/packetSnifferLive.dir/src/packetSnifferLive.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/packetSnifferLive.dir/src/packetSnifferLive.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S "/mnt/c/Users/102151/OneDrive - UNIPHORE SOFTWARE SYSTEMS PVT LTD/Documents/SIP_ENGINE/Capture/src/packetSnifferLive.cpp" -o CMakeFiles/packetSnifferLive.dir/src/packetSnifferLive.cpp.s

# Object files for target packetSnifferLive
packetSnifferLive_OBJECTS = \
"CMakeFiles/packetSnifferLive.dir/src/packetSnifferLive.cpp.o"

# External object files for target packetSnifferLive
packetSnifferLive_EXTERNAL_OBJECTS =

packetSnifferLive: CMakeFiles/packetSnifferLive.dir/src/packetSnifferLive.cpp.o
packetSnifferLive: CMakeFiles/packetSnifferLive.dir/build.make
packetSnifferLive: /home/suyashgaurav72/.conan2/p/b/libpc91d53db0e773f/p/lib/libpcap.a
packetSnifferLive: /home/suyashgaurav72/.conan2/p/b/cnats383ef0346a326/p/lib/libnats_static.a
packetSnifferLive: /home/suyashgaurav72/.conan2/p/b/opens88671bfd44ecd/p/lib/libssl.a
packetSnifferLive: /home/suyashgaurav72/.conan2/p/b/opens88671bfd44ecd/p/lib/libcrypto.a
packetSnifferLive: /home/suyashgaurav72/.conan2/p/b/zlibcd619084bcee8/p/lib/libz.a
packetSnifferLive: CMakeFiles/packetSnifferLive.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir="/mnt/c/Users/102151/OneDrive - UNIPHORE SOFTWARE SYSTEMS PVT LTD/Documents/SIP_ENGINE/Capture/build/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable packetSnifferLive"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/packetSnifferLive.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/packetSnifferLive.dir/build: packetSnifferLive
.PHONY : CMakeFiles/packetSnifferLive.dir/build

CMakeFiles/packetSnifferLive.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/packetSnifferLive.dir/cmake_clean.cmake
.PHONY : CMakeFiles/packetSnifferLive.dir/clean

CMakeFiles/packetSnifferLive.dir/depend:
	cd "/mnt/c/Users/102151/OneDrive - UNIPHORE SOFTWARE SYSTEMS PVT LTD/Documents/SIP_ENGINE/Capture/build" && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" "/mnt/c/Users/102151/OneDrive - UNIPHORE SOFTWARE SYSTEMS PVT LTD/Documents/SIP_ENGINE/Capture" "/mnt/c/Users/102151/OneDrive - UNIPHORE SOFTWARE SYSTEMS PVT LTD/Documents/SIP_ENGINE/Capture" "/mnt/c/Users/102151/OneDrive - UNIPHORE SOFTWARE SYSTEMS PVT LTD/Documents/SIP_ENGINE/Capture/build" "/mnt/c/Users/102151/OneDrive - UNIPHORE SOFTWARE SYSTEMS PVT LTD/Documents/SIP_ENGINE/Capture/build" "/mnt/c/Users/102151/OneDrive - UNIPHORE SOFTWARE SYSTEMS PVT LTD/Documents/SIP_ENGINE/Capture/build/CMakeFiles/packetSnifferLive.dir/DependInfo.cmake" "--color=$(COLOR)"
.PHONY : CMakeFiles/packetSnifferLive.dir/depend

