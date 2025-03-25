########## MACROS ###########################################################################
#############################################################################################

# Requires CMake > 3.15
if(${CMAKE_VERSION} VERSION_LESS "3.15")
    message(FATAL_ERROR "The 'CMakeDeps' generator only works with CMake >= 3.15")
endif()

if(cnats_FIND_QUIETLY)
    set(cnats_MESSAGE_MODE VERBOSE)
else()
    set(cnats_MESSAGE_MODE STATUS)
endif()

include(${CMAKE_CURRENT_LIST_DIR}/cmakedeps_macros.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/cnatsTargets.cmake)
include(CMakeFindDependencyMacro)

check_build_type_defined()

foreach(_DEPENDENCY ${cnats_FIND_DEPENDENCY_NAMES} )
    # Check that we have not already called a find_package with the transitive dependency
    if(NOT ${_DEPENDENCY}_FOUND)
        find_dependency(${_DEPENDENCY} REQUIRED ${${_DEPENDENCY}_FIND_MODE})
    endif()
endforeach()

set(cnats_VERSION_STRING "3.9.2")
set(cnats_INCLUDE_DIRS ${cnats_INCLUDE_DIRS_RELEASE} )
set(cnats_INCLUDE_DIR ${cnats_INCLUDE_DIRS_RELEASE} )
set(cnats_LIBRARIES ${cnats_LIBRARIES_RELEASE} )
set(cnats_DEFINITIONS ${cnats_DEFINITIONS_RELEASE} )


# Only the last installed configuration BUILD_MODULES are included to avoid the collision
foreach(_BUILD_MODULE ${cnats_BUILD_MODULES_PATHS_RELEASE} )
    message(${cnats_MESSAGE_MODE} "Conan: Including build module from '${_BUILD_MODULE}'")
    include(${_BUILD_MODULE})
endforeach()


