add_library(lh_ifcpu cpu_common.c)
target_link_libraries(lh_ifcpu lh_common)

if(LH_ARM)
	add_subdirectory(arm)
	target_link_libraries(lh_ifcpu libcpu_arm)
endif()

if(LH_MIPS)
	add_subdirectory(mips)
	target_link_libraries(lh_ifcpu libcpu_mips)
endif()

if(LH_X86 OR LH_AMD64)
	add_subdirectory(intel)
	target_link_libraries(lh_ifcpu libcpu_intel)
endif()

add_subdirectory(sljit)
