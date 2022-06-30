#ifndef __INTERFACE_OS_H
#define __INTERFACE_OS_H

#if _WIN32
	#define PACK( __Declaration__ ) __pragma( pack(push, 1) ) __Declaration__ __pragma( pack(pop) )
#elif __GNUC__
	#define PACK( __Declaration__ ) __Declaration__ __attribute__((__packed__))
#endif

#endif
