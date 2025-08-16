// 3/25/19: rust cannot currently define extern C variadic functions so were
// stuck with this shit
//
// TODO when rust supports extern variadic functions, replace all of this
// with var args versions
//
// 4/18/19 so because were stuck with this shit right now we spend a lot of
// time inside vsnprintf, only to discard the formatted results. We'll hack
// around this by not doing shit on release builds.
#include <stdio.h>
#include <stdarg.h>

#include "bochs.h"


logfunctions::logfunctions(void) {}
logfunctions::~logfunctions(void) {}

void logfunctions::error(const char *fmt, ...) {
#ifndef RUST_CC_RELEASE
	char buf[0x1000];

	va_list args;
	va_start(args, fmt);
	vsnprintf(buf, sizeof buf, fmt, args);
	va_end(args);

    printf("[ERROR] %s\n", buf);
#endif
}

void logfunctions::fatal1(const char *fmt, ...) {
#ifndef RUST_CC_RELEASE
	char buf[0x1000];

	va_list args;
	va_start(args, fmt);
	vsnprintf(buf, sizeof buf, fmt, args);
	va_end(args);
    printf("[FATAL] %s\n", buf);

#endif
}

void logfunctions::info(const char *fmt, ...) {
#ifndef RUST_CC_RELEASE
	// char buf[0x1000];

	// va_list args;
	// va_start(args, fmt);
	// vsnprintf(buf, sizeof buf, fmt, args);
	// va_end(args);
    
    // printf("[INFO] %s\n", buf);

#endif
}

void logfunctions::ldebug(const char *fmt, ...) {
#ifndef RUST_CC_RELEASE
	// char buf[0x1000];

	// va_list args;
	// va_start(args, fmt);
	// vsnprintf(buf, sizeof buf, fmt, args);
	// va_end(args);

    // printf("[LDEBUG] %s\n", buf);
#endif
}

void logfunctions::panic(const char *fmt, ...) {
#ifndef RUST_CC_RELEASE
	char buf[0x1000];

	va_list args;
	va_start(args, fmt);
	vsnprintf(buf, sizeof buf, fmt, args);
	va_end(args);

    printf("[PANIC] %s\n", buf);
#endif
}

void logfunctions::put(const char *p, const char *q) {}
void logfunctions::put(const char *p) {}

BOCHSAPI class logfunctions *genlog = NULL;
