add_executable(needle needle.c)
target_link_libraries(needle
	lh_common
	lh_ifcpu
	# Hardcoded, only supported platform atm
	lh_linux
)
