all:
	gcc *.c ../elf-reader/elf-reader.c -o main -lpthread
	sudo setcap 'CAP_NET_RAW,CAP_NET_ADMIN+eip' main
run:
	./main

perf:
	sudo perf record -e kvm:kvm_* --cpu 12-15 ./main vcpu 4 pcpu 4

rperf:
	sudo chown prakhar:prakhar perf.data
	perf script > perf.out

get_app_defn:
	scp prakhar@10.16.70.240:/home/prakhar/data/code/f4/app_defn.h .
