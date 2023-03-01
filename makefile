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
