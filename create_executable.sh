#!/bin/bash

prefix="tmp/";
suffix=".elf";
case $# in
    1)
	fail=1;
	if [[ ($1 == *.o) ]]; then # should have .o in end
	    if [[ -z ${1#*.o} ]]; then # to mitigate .o.o case
	        stripped_file=${1##*/};
		filename=${stripped_file%.o};
		elf_file="${prefix}"${filename}".elf";
		map_file="${prefix}"${filename}".map";
		fail=0;
	    fi;
	fi;

	if [[  ${fail} -eq 1 ]]; then
	    echo "Supply object file, supplied was $1"
	    exit -1;			    
	fi;
    ;;
    *)
    ;;
esac;

#echo ${map_file}, ${elf_file}
ld -nostdlib -Map=${map_file} -Ttmp/linker.script $1 -o ${elf_file}
exit 0;



