add_library(lh_linux inject_linux.c)
add_library(lh_preload inject_preload.c)
target_link_libraries(lh_linux
	lh_ifcpu
	lh_elf
	${CAPSTONE_LIBRARIES}
)
target_link_libraries(lh_preload SHARED lhm_ext)