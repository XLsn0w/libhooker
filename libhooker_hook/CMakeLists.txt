cmake_minimum_required(VERSION 3.7)
project(libhooker)

set(CMAKE_C_STANDARD 99)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include (CheckSymbolExists)
check_symbol_exists("__arm__" "" LH_ARM)
check_symbol_exists("__x86_64__" "" LH_AMD64)
check_symbol_exists("__i386__" "" LH_X86)

if(LH_X86 OR LH_AMD64)
	set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake-modules/")
	if(NOT CAPSTONE_INCLUDE_DIRS AND NOT CAPSTONE_LIBRARIES)
		find_package(CAPSTONE REQUIRED)
	endif()
include_directories(${CAPSTONE_INCLUDE_DIRS})
endif()

include_directories(include)

if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Debug)
endif()

if(NOT LH_TARGET)
	set(LH_TARGET linux)
else()
	string(TOLOWER "${LH_TARGET}" LH_TARGET)
endif()

add_definitions(-DSLJIT_CONFIG_AUTO -DSLJIT_DEBUG=0)

if(LH_TARGET STREQUAL linux)
	add_definitions(-DPLATFORM_LINUX)
	add_definitions(-D_GNU_SOURCE)
	add_definitions(-DLH_JUMP_ABS)
else()
	message(FATAL_ERROR "Platform ${LH_TARGET} Not supported")
endif()

include (CheckIncludeFiles)
check_include_files(alloca.h HAVE_ALLOCA_H)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

# GCC or Clang
add_definitions(-include ${CMAKE_CURRENT_BINARY_DIR}/config.h)

macro(lh_basemod target)
	target_link_libraries(${target} lh_common lh_basemod)
endmacro()

macro(lh_injmod target)
	lh_basemod(${target})
	target_link_libraries(${target} lh_injmod)
endmacro()

macro(lh_lgmod target)
	lh_basemod(${target})
	target_link_libraries(${target} lh_lgmod)
endmacro()

macro(lh_sljitmod target)
	lh_basemod(${target})
	target_link_libraries(${target} lh_sljitmod)
endmacro()

add_subdirectory(src)
add_subdirectory(modules)
