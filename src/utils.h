//
// Created by urv on 5/19/21.
//

#ifndef _UTILS_H
#define _UTILS_H

#include <string.h>

#define MEMZERO(x)	memset(&(x), 0, sizeof (x));

double stopwatch(char* label, double timebegin);

#endif // _UTILS_H
