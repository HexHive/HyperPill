#ifndef DEBUG_H
#define DEBUG_H

#ifdef NDEBUG
    #define DEBUG_PRINT(x) do {} while (0)
#else
    #define DEBUG_PRINT(x) std::cout << x << std::endl
#endif

#endif // DEBUG_H
