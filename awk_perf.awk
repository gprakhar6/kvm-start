#// {
#    cpu=int(substr($3,2,3));
#}
#/kvm:kvm_exit: vcpu 0 reason io rip 0x4ad5/ {
#    exit_t[cpu]=$4;
#    f=1;
#  }
#/kvm:kvm_entry: vcpu 0, rip 0x4ad7/ {
#    if(f==1) {
#	d[cpu]=$4-exit_t[cpu];
#	if((cpu == 12) && (d[12] > 0.000020)) {
#	    printf "%-16.6f %-10d\n",d[12],NR;
#	}
#	f=0;
#    }
#}
// {
    cpu=int(substr($3,2,3));
}
/kvm:kvm_entry/ {
    entry_t[cpu]=$4;
    f=1;
  }
/kvm:kvm_exit/ {
    if(f==1) {
	d[cpu]=$4-entry_t[cpu];
	if((cpu == 12) && (d[12] > 0.000010)) {
	    printf "%-16.6f %-10d\n",d[12],NR;
	}
	f=0;
    }
}
