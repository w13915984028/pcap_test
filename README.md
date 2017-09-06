# pcap_test
test_pcap


compile:
    gcc -o tst test-libpcap.c -lpcap

RUN:

usage:
    ./xxx packet_count interface_name filter_condition
    
eg:
    ./tst 30 lo
    ./tst 20 em1 "dst host 10.221.118.127 and dst port 22"   
