#`g++ -Wall -O3 -fsanitize=address -I./ gcm_bench.cpp -fsanitize=address -lcrypto`
`g++ -Wall -O3 -I./ gcm_bench.cpp -lcrypto`
`g++ -Wall -O3 -I./ -I/usr/local/include cityh_bench.cpp -L/usr/local/lib -lcityhash -lcrypto -o city.out`
