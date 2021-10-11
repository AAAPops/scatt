#!/bin/bash

_max_requests=23

for (( i = 1; i <= $_max_requests; i++ ));
do 
	#sleep $(echo "scale=3; 1/$_max_requests" | bc -l)
	sleep 0.2
	echo 'get-srv-time.sh' | /home/urv/CLionProjects/scatt-salsa/src/build/scatt-stdin-to-ip -t 10 -d1 127.0.0.1:32005 &> answers_$i &

done

#sleep 3    

#cat $(pwd)/answers
#rm $(pwd)/answers &> /dev/null
