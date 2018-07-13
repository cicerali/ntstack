CC=gcc
DPDK_DIR=/home/cicerali/fastpath/dpdk/x86_64-native-linuxapp-gcc
DPDK_CFLAGS= -Wall -g -std=c99 -include ${DPDK_DIR}/include/rte_config.h
DPDK_CFLAGS+= -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3
DPDK_CFLAGS+= -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2
DPDK_CFLAGS+= -DRTE_COMPILE_TIME_CPUFLAGS=RTE_CPUFLAG_SSE,RTE_CPUFLAG_SSE2,RTE_CPUFLAG_SSE3,RTE_CPUFLAG_SSSE3,RTE_CPUFLAG_SSE4_1,RTE_CPUFLAG_SSE4_2
DPDK_CFLAGS+= -I${DPDK_DIR}/include -I.

CFLAGS+= ${DPDK_CFLAGS}
LDFLAGS+= -g -rdynamic -Wl,--whole-archive -L/home/cicerali/fastpath/dpdk/x86_64-native-linuxapp-gcc/lib
LDLIBS+= \
-lrte_ethdev \
-lrte_eal \
-lrte_mempool \
-lrte_pci \
-lrte_bus_pci \
-lrte_pmd_e1000 \
-lrte_pmd_vmxnet3_uio \
-lrte_mbuf \
-lrte_ring \
-lrte_mempool_ring \
-lrte_hash \
-lrte_ip_frag \
-lrte_lpm \
-Wl,--no-whole-archive -lnuma -lpthread -ldl -lm -lrt

NT_STACK_SOURCES = \
nt_main.c \
nt_config.c \
nt_packet.c \
nt_ipv4.c \
nt_arp.c \
nt_icmp.c \
nt_udp.c \
nt_socket.c

NT_STACK_OBJECTS=$(NT_STACK_SOURCES:.c=.o)

NT_STACK_LIB=libntdpdk.a

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS) $(LDFLAGS) $(LDLIBS)

all: $(NT_STACK_SOURCES) $(NT_STACK_LIB)

$(NT_STACK_LIB): $(NT_STACK_OBJECTS)
	ar ru $@ $^
	ranlib $@
	
clean:
	rm -rf $(NT_STACK_OBJECTS) $(NT_STACK_LIB)
