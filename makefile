all:
	gcc *.c ../elf-reader/elf-reader.c -o main -lpthread -lm
	sudo setcap 'CAP_NET_RAW,CAP_NET_ADMIN+eip' main
run:
	./main

perf:
	sudo perf record -e 'sched:*' -e 'irq:*' -e 'kvm:*' --cpu 12 ./main vcpu 1 pcpu 1
#	sudo perf record -e kvm:kvm_* --cpu 12-15 ./main vcpu 4 pcpu 4

rperf:
	sudo chown prakhar:prakhar perf.data
	perf script > perf.out

get_app_defn:
	scp prakhar@10.16.70.240:/home/prakhar/data/code/f4/app_defn.h .

# awk '//{cpu=int(substr($3,2,3));} /kvm:kvm_exit/{exit_t[cpu]=$4;} /kvm:kvm_entry/{d[cpu]=$4-exit_t[cpu]; if((cpu == 12) && (d[12] > 0.004)) {print NR}}' perf.out
