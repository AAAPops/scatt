//
// Created by urv on 5/19/21.
//
#include <stdio.h>
#include <sys/time.h>

double stopwatch(char* label, double timebegin) {
    struct timeval tv;

    if( timebegin == 0 ) {
      if (label)
        fprintf(stderr, "%s: Start stopwatch... \n", label);
      else
        fprintf(stderr, "Start stopwatch... \n");


      gettimeofday(&tv, NULL);
      double time_begin = ((double) tv.tv_sec) * 1000 +
                        ((double) tv.tv_usec) / 1000;
      return time_begin;

    } else {
      gettimeofday(&tv, NULL);
      double time_end = ((double)tv.tv_sec) * 1000 + ((double)tv.tv_usec) / 1000 ;

      fprintf(stderr, "%s: Execute time = %f(ms) \n",
              label, time_end - timebegin);

      return 0;
    }
}