/**
 * @brief Misc. utility functions
 */

#ifndef _UTIL_H_
#define _UTIL_H_

/**
 * Returns static number of elements array/characters in a string
 */
#define COUNT_OF(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))

#endif
