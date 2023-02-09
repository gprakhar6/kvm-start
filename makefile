all:
	gcc *.c ../elf-reader/elf-reader.c -o main -lpthread
	sudo setcap 'CAP_NET_RAW,CAP_NET_ADMIN+eip' main
run:
	taskset --cpu-list 12 ./main
