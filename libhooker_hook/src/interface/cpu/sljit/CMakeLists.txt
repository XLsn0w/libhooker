add_library(lh_sljitmod
	sljitLir.c
)
target_include_directories(lh_sljitmod
	PUBLIC
	${CMAKE_SOURCE_DIR}/include/sljit
)