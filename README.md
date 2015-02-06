Description
====
This is the linux device driver for the next generation of NIC under the development for the [NetFPGA](http://netfpga.org/) platform. The NIC includes a new DMA engine that is capable of general-purpose communication between host and FPGA, in addition to 10GbE packet communication. To this end, the DMA engine itself is Ethernet-agnostic using a phyiscally contiguous buffer as a transport in general. So, the engine delivers a transmitted or received buffer between host and 10GbE MAC IP core, before which a buffer is (de)segmentized from/to each Ethernet packet. On this DMA, the role of software for host-to-FPGA data transfer (e.g., network transmission) is to allocate a physically contiguous buffer, fill it with one or more data chunks (packets in the case of Ethernet) with a pre-defined format, and let DMA know the address and length of the buffer. For FPGA-to-host (e.g., network reception), the driver also allocates a physically contiguous buffer, prepares it to the DMA engine in advance of data arrival, and segmentizes each packet from the buffer once notified of data reception.

The kernel-level device driver basically does two things: 1) supporting legacy network applications that use the BSD socket interface, and 2) enabling a user-level application to directly access DMA in data plane. For the legacy application support, the driver uses `sk_buff` to communicate with kernel protocol layer and is in charge of moving a packet with `sk_buff` to/from the physically contiguous buffer that is used for host-FPGA communication. For the kernel bypassing support, the driver allows a user process to map DMA-related metadata and pre-allocated buffers to its virtual address space, so that it can directly control DMA without kernel intervention. To ease programmability, a user-level driver is provided as a library (in *lib* directory).

Build
====
#### 1. Drivers
To compile the drivers,
```
# make
```
Baiscally, `make` does the compilation of kernel device driver (**nf10.ko**) and user device driver (**lib/liblbufnet.so**).
The `make` has some options depending on different configurations of hardware.

1. `CONFIG_PHY_INIT`: if =y, the driver initializes the PHY chip on NetFPGA by itself when loaded.
2. `CONFIG_NO_TIMESTAMP`: if =y, DMA adds 8-byte timestamp for each received packet. This feature is used by the [OSNT](http://osnt.org/) project.
3. `CONFIG_NR_PORTS`: =1 to 4, a development prototype usually uses a single port, but NetFPGA-related projects can use up to four ports.
4. `CONFIG_PROFILE`: if =y, it measures cycles elapsed for performance-critical parts (see CONFIG_PROFILE in `nf10_lbuf.c`)

We provide a shortcut of each project (now for NAAS and OSNT).

```
# make NAAS=y	# it initializes PHY by itself and only enables a single port without timestamp
# make OSNT=y	# it doesn't initialize PHY and enables four ports with timestamp
```
To enable debugging messages, add DEBUG=y. After loading the driver, what type of message is enabled can be controlled by `ethtool -s nf0 msglvl <flag>`).
Note that the compilation of the user-level driver (`liblbufnet.so`) inherits the configurations, since both driver should be consistent for hardware configurations. If DEBUG=y, debugging messages are turned on for both drivers.
For the performance test, you should turn off the debugging messages.

To install the compiled drivers,
```
# make install
```
The user driver, `liblbufnet.so`, should be installed when using the sample applications in `apps/`.
If the kernel driver is installed, it is located in `/lib/modules/<kernel version>/extra/nf10/` and automatically loaded at booting once the board is probed.

#### 2. Applications
A number of applications that use the user-level driver are provided in `apps/` directory.
To compile them,
```
# make -C apps
```
Note that the compilation needs the user-level driver, `lib/liblbufnet.so`.

Usage
====
#### 1. Loading kernel driver
To load the kernel driver,
```
# insmod nf10.ko
or
# modprobe nf10		# if installed
```
Since Linux kernel 3.12, PCI bus reset is supported, so you can safely unload/reload the driver.

To get an interface up,
```
# ifconfig nf0 up
# ifconfig nf1 up
# ifconfig nf2 up
# ifconfig nf3 up
```
Note that the number of interfaces is determined when the driver is compiled via CONFIG_NR_PORTS.
Also note that NAAS=y names physical nf3 port (farthest from a PCI slot) nf0, so you should carefully connect a cable to nf3 and use it as nf0 in software.

If the module is compiled with DEBUG=y, you can selectively enable some types of debugging messages.
```
# ethtool -s nf0 msglvl 0xffff	# all messages
# ethtool -s nf0 msglvl 0x0100	# tx_queued
# ethtool -s nf0 msglvl 0x0200	# intr (interrupt)
# ethtool -s nf0 msglvl 0x0800	# rx_status

## See the list,
enum {
	NETIF_MSG_DRV           = 0x0001,
	NETIF_MSG_PROBE         = 0x0002,
	NETIF_MSG_LINK          = 0x0004,
	NETIF_MSG_TIMER         = 0x0008,
	NETIF_MSG_IFDOWN        = 0x0010,
	NETIF_MSG_IFUP          = 0x0020,
	NETIF_MSG_RX_ERR        = 0x0040,
	NETIF_MSG_TX_ERR        = 0x0080,
	NETIF_MSG_TX_QUEUED     = 0x0100,
	NETIF_MSG_INTR          = 0x0200,
	NETIF_MSG_TX_DONE       = 0x0400,
	NETIF_MSG_RX_STATUS     = 0x0800,
	NETIF_MSG_PKTDATA       = 0x1000,
	NETIF_MSG_HW            = 0x2000,
	NETIF_MSG_WOL           = 0x4000,
};
```
Once the interfaces are up, they are ready to be used by legacy network applications.

#### 2. Running sample applications
The applicatons in `apps/` directory are relying on the user-level driver, `lib/liblbufnet.so`, which is a shared library.
Currently, there are four sample applications:

1. `lbuf_rx`: Packet receiver simply counting the number and size of recieved packets and measuring reception throughput.
2. `lbuf_tx`: Packet sender generating packets in a maximum achievable rate and reporting transmission throughput.
3. `lbuf_ping`: Ping/pong program for latency test using ICMP.
4. `lbuf_gen`: Benchmark tool for host-to-FPGA transfer rate without regard to Ethernet network.

To learn how to use each of them, use `-h` option. For example,
```
# apps/lbuf_rx -h
```

Here are some examples performance-sensitive parameters commonly used by all applications.
```
# apps/lbuf_rx -f 2 -p		# on one machine
# apps/lbuf_tx -l 60 -n 1000000 -f 2 -p		# on the other machine connected to the first one
```
* `-f 2` enables an application to run in a busy-wait mode without sleeping and IRQ.
* `-p` enables an application to directly write to registers to submit the buffers without using `ioctl`.

The two options allow the highest performance for all the applications, but the busy-wait needs much higher CPU consumption and the direct register access needs to trust the applications.

`lbuf_ping` is a user-level ping/pong implementation, which also works with a legacy ICMP echo server on the other side.
But, if you want to use `lbuf_ping` on the sender communicating with a legacy server, ARP table should be set in advance on the both sides, since `lbuf_ping` does not include ARP protocol.
If you want to use `lbuf_ping` on the both sides, you don't need to set up ARP table.
The option `-m` decides if `lbuf_ping` works as a pinger (client, `-m 0`) or a ponger (server, `-m 1`).
Likewise, the lowest latency can be achieved with `-f 2` and `-p` for both ping and pong.
In addition, `-c 0` disables ICMP checksum and can be used to minimize software latency. Note that disabling the checksum should be used for the both sides.
```
# apps/lbuf_ping -m 1 -f 2 -p -c 0	# ponger on a server machine
# apps/lbuf_ping -m 0 -s 192.168.234.2 -S 64:d1:0d:53:0f:00 \
                      -d 192.168.234.4 -D 00:1b:21:8f:19:fc \
                      -f 2 -p -c 0	# pinger on a client machine
```

Performance tuning
====
Unlike kernel-bypassing applications, legacy applications on top of socket interface and kernel TCP/IP accompany non-trivial software overheads, maybe leading to suboptimal performance. Our NIC currently does not have TSO/LRO/Checksum offloadings, hence more software overheads over modern NICs. In addition, more copying needed between buffer and sk_buff and our RX-side polling adds overheads. Fortunately, we can relieve such overheads by taking advantage of GSO/GRO, which are purely software-based optimizations. However, old kernel versions enforce the dependencies of such optimizations on checksum offloadings, which we do not have. So, we found that the driver could not use GSO/GRO properly in the kernel 2.6.35, whereas they are used well in 3.14. Once using GSO/GRO, it saves significant CPU consumption. Therefore, if you want better performance of legacy applications (e.g., *iperf*), use a recent Linux kernel.

To check if those optimizations,
```
# ethtool -k nf0
Offload parameters for nf0:
rx-checksumming: off
tx-checksumming: off
scatter-gather: on
tcp-segmentation-offload: off
udp-fragmentation-offload: off
generic-segmentation-offload: on  # GSO on
generic-receive-offload: on       # GRO on
large-receive-offload: off
rx-vlan-offload: off
tx-vlan-offload: off
ntuple-filters: off
receive-hashing: off
```
The above scatter-gather, which is on, is an emulated feature by software to take advantage of GSO, which relies on the scatter-gather feature.

Another performance tuning is for RX-side throughput of legacy TCP/IP applications (e.g., *iperf* server). If you cannot have line-rate RX throughput, it may be related to either high-rate IRQ or interference between the NAPI RX handler and application threads. Our DMA engine also supports IRQ coalescing feature, which mitigates IRQ rate. The default IRQ period is 30us, which is relatively for low latency.
To increase this period to further mitigate IRQ rate,
```
# ethtool -C nf0 rx-usecs 300
```

If the performance is still suboptimal, some interference between the NAPI RX handler and the application threads may be an issue.
One solution is to try to segregate IRQ affinity and process affinity.
For example,
```
# irqnr=`grep nf10 /proc/interrupts | awk '{print $1}' | sed 's/://g'`
# echo 1 > /proc/irq/$irqnr/smp_affinity	# direct IRQ to core 0
# taskset 2 iperf -s				# run application on core 1
```
In the setup (Intel(R) Core(TM) i7-4770 CPU @ 3.40GHz and Linux kernel 3.14), we have iperf server (RX) and client (TX) performance of around 9.4Gbps (RX-side was tuned as above).
In a lower-performance CPU (Intel(R) Core(TM) i7 CPU 960 @ 3.20GHz and Linux kernel 3.14), we have iperf server and client performance of around 8.8Gbps and 9.3Gbps.
But, in the latter setup with Linux kernel 2.6.35 thus without GSO/GRO, we have performance of only around 4-5Gbps throughput; in the higher-performance CPU (i7-4770), 8-9Gbps is achieved even without GSO/GRO.

Under the hood of drivers
====
#### 1. Overview
The kernel driver files are organized as follows:

1. `nf10_main.c`: The main body of the driver maintained in a hardware (DMA)-independent manner
2. `nf10_lbuf.c`: Large buffer (lbuf) DMA implementation (hardware-dependent)
3. `nf10_user.c`: A glue layer between kernel and user drivers
4. `nf10_ethtool.c`: Support for ethtool commands
5. `ael2005_conf.c`: PHY configuration, which is enabled by CONFIG_PHY_INIT=y
6. `nf10_lbuf_api.h`: Lbuf DMA-specfic header file shared between kernel and user

The driver is designed in a way that FPGA-based DMA/NIC could be changed or extended by others, so DMA-specific implementations would be good to be separated from a general part.  So, the general part (e.g., PCI-related configurations, IRQ top-half, NAPI, etc.) is included in `nf10_main.c`. Our DMA implementation designed and implemented by [Marco Forconesi](https://github.com/forconesi) is named **lbuf** DMA, since it uses a large contiguous buffer as a transport regardless of any adapter-specific transport (e.g., Ethernet MTU). The lbuf DMA implementation is included in `nf10_lbuf.c`.

In order to link the general part with a DMA-specific one, `nf10_hw_ops` is defined as follows:
```
struct nf10_hw_ops {
	int             (*init)(struct nf10_adapter *adapter);
	void            (*free)(struct nf10_adapter *adapter);
	int             (*init_buffers)(struct nf10_adapter *adapter);
	void            (*free_buffers)(struct nf10_adapter *adapter);
	void            (*process_rx_irq)(struct nf10_adapter *adapter, int *work_done, int budget);
	netdev_tx_t     (*start_xmit)(struct sk_buff *skb, struct net_device *dev);
	int             (*clean_tx_irq)(struct nf10_adapter *adapter);
	unsigned long   (*ctrl_irq)(struct nf10_adapter *adapter, unsigned long cmd);
	int             (*set_irq_period)(struct nf10_adapter *adapter);
};
```
If you want to implement your own DMA engine, implement all these functions in a separate file as `nf10_lbuf.c` does, link them with its own nf10_hw_ops struct (e.g., *lbuf_hw_ops*), and assign the struct to *adapter->hw_ops* (e.g., via *nf10_lbuf_set_hw_ops*). The role of each function is as follows:

* `init`: called when DMA is initialized (from *nf10_probe*)
* `free`: called when DMA is freed (from *nf10_remove*)
* `init_buffers`: called when DMA-related buffers are allocated (currently from *nf10_up* when the first interface is brought up)
* `free_buffers`: called when DMA-related buffers are freed (currently from *nf10_down* when the last interface is brought down)
* `process_rx_irq`: called when any data is received from FPGA (from *nf10_poll*, which is a NAPI-based IRQ handler)
* `start_xmit`: called when any data is ready to be transmitted from kernel layer (from *nf10_start_xmit*, which is invoked by kernel protocol layer via *ndo_start_xmit*)
* `clean_tx_irq`: called when any transferred data is drained from memory to FPGA (from *nf10_poll* right before *process_rx_irq* when IRQ is raised)
* `ctrl_irq`: called when IRQ is controlled (from *nf10_enable_irq* and *nf10_disable_irq*)
* `set_irq_period`: called when IRQ period is set for IRQ coalescing (from *nf10_set_coalesce* via `ethtool -C`)

#### 2. Kernel driver for lbuf DMA engine
As mentioned, packets are delivered in a way that individual packets are packed in a physically contiguous buffer, which we call *lbuf*. So, packet batching is done in this way. The DMA engine provides a set of registers for the driver to inform the DMA engine of the address and length of a lbuf. Once a lbuf is ready on the driver side, its information is sent by writing it to the registers, so that the DMA engine starts processing with the lbuf. The DMA engine allows the driver to submit multiple lbufs by providing multiple register sets. We call each set as a *slot* and each slot owns two registers for a lbuf. So, the driver keeps track of the current slot to submit a lbuf correctly. For now, the driver provides two slots for TX and RX each. Originally, the two registers of a slot are 64bit address and 32bit length of a lbuf to be submitted. However, the RX logic of the current DMA engine requires a fixed length (2MB) of an RX lbuf and thus the second register is just for letting the DMA engine know the readiness of the lbuf. In the future, various size of RX lbuf could be supported by allowing the driver to write the length of the lbuf to the second register; however, the need of various size for RX is not essential unlike TX. The current slot registers are illustrated as follows:
```
RX
    index                    Slot
          +----------------------------+-----------------+
        0 |         address (64b)      | readiness (32b) |
          +----------------------------+-----------------+
        1 |         address (64b)      | readiness (32b) |
          +----------------------------+-----------------+
nf10_lbuf_prepare_rx() submits a lbuf to be used for RX via this slot interface.

TX
    index                    Slot
          +----------------------------+-----------------+
        0 |         address (64b)      |   length (32b)  |
          +----------------------------+-----------------+
        1 |         address (64b)      |   length (32b)  |
          +----------------------------+-----------------+
lbuf_xmit() submits a lbuf to be transferred via this slot interface.
```

##### 1) Reception
For RX, the driver should prepare available lbufs in advance of data arrival properly not lagging behind DMA reception rate. Currently, the DMA engine fixes the size of an RX lbuf as 2MB, so the driver should submit two 2MB lbufs by writing to the registers of each slot at an initialization time (*nf10_lbuf_prepare_rx_all*). After properly submitting the RX lbufs, the driver can be notified of packet reception when any packet arrives at hardware. For RX, the DMA engine sequentially writes received packets into a prepared lbuf with a pre-defined format, by which the driver can parse and fetch each packet from the lbuf. This format is acutally defined by the hardware and software should comply with the format. The current format of an RX lbuf is like the following.
```
 RX lbuf layout

                    DWORD (32b, 4B)
                  +------------------+
                0 |     HEADER 1     | =  nr_qwords (32b)
                  +------------------+    +-----------+-----------------------+-----------+-------------+
                1 |     HEADER 2     | =  | unused(8b)|     nr_drop (16b)     | unused(7b)|is_closed(1b)|
                  +------------------+    +-----------+-----------------------+-----------+-------------+
                  |                  |
                  |       ...        |   
               31 |     RESERVED     |
                  +------------------+ <- see LBUF_RX_RESERVED_DWORDS
               32 |     METADATA1    | =  encoded port number (see LBUF_PKT_PORT_NUM)
                  +------------------+
               33 |       LEN1       | =  actual data length
                  +------------------+ <- if CONFIG_NO_TIMESTAMP=n, 8B timestamp is additionally placed here after LEN
               34 |       DATA1      |
                  |        ...       |
                  |                  |
                  +------------------+ -> QWORD(64bit, 8B)-aligned, but if MAC timeout occurs, this should be 128B-aligned
 ALIGN(34+LEN1,8) |     METADATA2    |
                  +------------------+
                  |       LEN2       |
                  +------------------+
                  |       DATA2      |
```
As shown, an RX lbuf has a reserved header space (128B, 32DWORDS). This header, so-called *lbuf header*, indicates the current status of the lbuf by which the driver can decide to correctly fetch each packet. The 128B reserved space is due to the requirement of PCIe packet alignment. The DMA engine is allowed to send a PCIe write request to a 128B-aligned address. As you can see in the format, from 128B offset, each packet is placed in a compact way. In this format, the driver can decide the location of a next packet by adding the length of the current packet to the current offset. Since the DMA engine restricts the start offset of each packet to 8B-aligned address (due to 64bit internal bus), the address of the next packet is calculated by ALIGN(cur_offset+cur_pkt_len, 8).

One important thing is that the current hardware does not support per-packet reception status for simplicity and efficiency reducing metadata-related PCIe traffic. To enable the driver to determine per-packet status of reception, it exploits the fact that an RX lbuf is written sequentially by the DMA engine. In detail, the driver submits a zeroed RX lbuf to the DMA engine and uses non-zero value of packet length as an indicator of packet arrival. In this way, the driver can determine that current packet starts being received by observing non-zero length of the current packet. But, this observation does not ensure that this packet is completely received and ready to be delivered to upper protocol layer. As the driver knows the valid length of the current packet, it can also locate the offset of the next packet. Then the driver can use the non-zero length of the next packet as an indicator of the completion of the current packet reception, since the non-zero length of the next packet means that the current packet is being completely written (received).

This simple tracking does not always work due to the two reasons: 1) packets are not always packed in 128B PCIe packets. and 2) a lbuf may not have available space for receiving a next packet. Actually, the simple tracking works well if a stream of packets are received back-to-back in a high rate, thereby compactly packing Ethernet packets in 128B PCIe packets. But, what if no more packet is received with the last PCIe packet being partially filled with the tail of the last packet (i.e., < 128B)? In this case, we cannot exploit the next packet length to determine the point at which to consume the current packet, since no next packet arrives. The DMA engine tries to pack received Ethernet packets into a series of 128B PCIe packets as much as possible. To determine if no more packet is received, the hardware has a *MAC timeout*. If this timeout expires, the DMA engine sends the current PCIe packet, which is likely to be partially filled (< 128B). The rest of the last PCIe packet is filled with zero. Such partial PCIe packet delivery also happens when a lbuf does not have sufficient space to accommodate a next packet. The two situations make the driver observe always-zero length of wrongfully-pointed next packet for good.

The issue now is how the driver identifies this MAC timeout and the end of lbuf, so the lbuf header comes. On the DMA engine side, whenever it sends a partially filled PCIe packet (caused by one of the two situations), it sends the current hardware offset to *nr_qwords* (in HEADER 1). In addition, if the partial packet reception is caused by the end of lbuf (i.e., insufficient space), the DMA engine sets the flag of *is_closed* (in HEADER 2). So, the driver can realize that one of these two situations happens by comparing the current offset maintained by the driver and nr_qwords in the lbuf header. In other words, the driver can ensure that **no MAC timeout/end-of-lbuf occurs if nr_qwords is less than the current offset**, so making itself continue polling on next packet length. Otherwise (i.e., nr_qwords >= current offset), one of the two situations has occured. In either case of the MAC timeout or end-of-lbuf, the current packet is believed to be entirely received, so that it can be safely consumed. Then, the driver first checks if is_closed bit is set and if so it moves to the first offset of a next prepared lbuf and keeps polling. If it is not the end of lbuf, the MAC timeout happens. When the hardware experiences the MAC timeout, it moves the pointer to 128B-aligned address for a next coming packet due to the PCIe requirement. According to this hardware logic, the driver moves the current offset to 128B-aligned address to properly locate the next coming packet.

This reception logic is implemented in *nf10_lbuf_process_rx_irq()* in `nf10_lbuf.c`.

##### 2) Transmission
The transmission logic itself is similar to and a bit simpler than reception, but additionally needs the notification of transmission completion. The completion of transmission basically means that a requested lbuf has been drained from the host memory to the DMA enigne. This notification is used for software to free or reuse the buffer memory for further transmission. First, look at a TX lbuf layout.
```
 TX lbuf layout

                    DWORD (32b, 4B)
                  +------------------+ <- 4KB-aligned
                0 |     METADATA1    | =  encoded port number (see LBUF_PKT_PORT_NUM)
                  +------------------+
                1 |       LEN1       | =  actual data length
                  +------------------+
                2 |       DATA1      |
                  |        ...       |
                  |                  |
                  +------------------+ -> QWORD(64bit, 8B)-aligned
  ALIGN(2+LEN1,8) |     METADATA2    |
                  +------------------+
                  |       LEN2       |
                  +------------------+
                  |       DATA2      |
```
The TX lbuf format is the same as the RX one except no lbuf header. Once the driver fills the packets to be transmitted in a TX lbuf, it can submit it via the slot interface. How many packets are packed inside a single lbuf is determined by software; so, packing multiple packets in a lbuf before transmission is a way of TX packet batching. One important restriction enforced by the DMA engine is that the start address of a lbuf should be 4KB-aligned.

Whenever the driver is about to submit a TX lbuf through slot registers, it should check if the slot is available for TX submission. While the DMA engine is requesting PCIe memory read requests for the lbuf of a slot, the slot remains unavailable. So, it becomes available right after the DMA engine has sent all the PCIe read requests for the slot, since its lbuf information is no longer needed. To let the driver know such slot availability, the DMA engine needs the driver to provide the area in which slot availability is notified. The following structure represents this area and is called *tx_completion* area. This area is a physically contiguous and DMA-coherent memory region defined as follows:
```
                      TX completion area
   +----------------------------+----------------------------+
   | Slot0 availability (32bit) | Slot1 availability (32bit) |
   +----------------------------+----------------------------+
   |                   gc address (64bit)                    |
   +---------------------------------------------------------+
```

If the slot availability is non-zero, the slot is available to be used for lbuf transmission. When the driver submits a new lbuf to an available slot, it resets its slot availability to zero. Once it becomes available again, the DMA engine writes a non-zero value to it. No race condition between software and hardware exists, since hardware never touches the availability of non-submitted slots.

The *gc address* entry following the slot availablity in the area is for the notification of TX completion. The DMA engine lets the driver know the last address of the lbuf that has been completely drained from the host memory. The address points to the tail of a corresponding lbuf (i.e., lbuf's address + lbuf's length - 1). Once this address is known to the driver, it ensures that it can safely reuse (or free) the area ranging from lbuf's address to the notified address. We call this activity `garbage collection (gc)`, so call the notified address `gc address`.

The implementation of transmission could be done in various ways. Our driver uses a single pre-allocated TX lbuf as a transport between hardware and sk_buff for legacy socket-based application support; our user driver exclusively uses multiple TX lbufs. So, we call the lbuf *kernel TX lbuf*. The kernel driver cannot explicitly control TX batching, since it cannot look ahead how many packets will be sent from kernel protocol layer via sk_buff interface. So, the driver keeps copying the packets transmitted from the kernel to the TX lbuf until a next slot becomes available, at the time of which the driver sends the pending (copied) packets through this slot. In this regard, if the rate at which the kernel layer passes TX packets to the driver is faster than DMA rate, TX batching is naturally done. Cross-layer optimization or intelligent batching is possible in the future.

The driver maintains the single kernel TX lbuf as a FIFO memory flow-controlled by the gc address notified from hardware. To this end, the driver maintains three pointers:
```
                      Kernel TX lbuf
                  +-------------------+ <- 4KB-aligned
                  |   TX completed    |
                  |   (drained and    |
                  |    available)     |
           cons-> +-------------------+ <- 4KB-aligned
                  |   TX requested    |
                  | but not completed |
           prod-> +-------------------+ <- 4KB-aligned
                  |  Pending packets  |
                  |  (copied but not  |
                  |   requested yet)  |
       prod_pvt-> +-------------------+
                  |                   |
                  |     available     |
                  |                   |
                  +-------------------+
```

1. `cons` is updated when the gc address is newly notified by hardware (in *nf10_lbuf_clean_tx_irq()*).
2. `prod` is updated when pending packets are requested to the DMA engine (in *lbuf_xmit()*).
3. `prod_pvt` is updated when a packet is copied to the lbuf (in *copy_skb_to_lbuf()*).

When reqeusting pending packets, the driver submits a lbuf ranging from `prod` to `prod_pvt` and then makes `prod` point to `prod_pvt`, since all the pending ones are requested to hardware. At this point, the driver makes sure that the updated `prod` and `prod_pvt` are 4KB-aligned due to the requirement of the DMA engine. When a packet is passed from the kernel layer via sk_buff, it is copied to the lbuf at `prod_pvt`, and then increments it by its length. For flow control, before copying the packet, the driver should check if there exists available space in the lbuf to copy the packet. The `cons` guides the point to which memory is avaialble to be safely reused. This lbuf is able to be wrapped around. The reason why `cons` is also maintained as 4KB-aligned is only for simplicity when comparing `cons` and `prod` to know if there are requested-but-not-completed packets. So, `prod` == `cons` means no requested-but-not-completed packets. This can let the NAPI end the loop owing to no more gc work needed (nontheless, pending RX packets can let NAPI loop going).

##### 3) Synchronization between software and hardware
As software is allowed to block-wait for coming events by means of interrupt-driven processing, it needs to let the DMA engine know the point to which software has actually processed before going to sleep. This synchronization enables the DMA engine to know if there are some events that are pending in hardware, but not processed by software. That the hardware and software pointers are inconsistent means there are more events to be processed by software. For the synchronization, before the driver goes to sleep enabling IRQ, it writes the current software pointers to the DMA engine (see *__enable_irq()*). The software pointers to be informed include the current RX offset address in the RX lbuf and the gc address last seen by software. Once the DMA engine recognizes inconsistency between the hardware and software pointers, it asserts IRQ again to wake up software thread again (actual IRQ trigger is controlled by IRQ coalescing function).

#### 3. User-level driver for lbuf DMA engine
Although the Linux sk_buff interface is needed for legacy network applications, it has been well-known as huge software overheads for high-rate packet processing (e.g., up to 14.8Mpps for 10GbE line-rated 60B packet processing). To solve this problem, several matured and sophisticated solutions (e.g., *netmap*, *PSIO*, *Intel DPDK*, *Solarflare OpenOnload*) exist. Since netmap is vendor-independent unlike the others, a netmap-compliant driver was considered in the first place, but not simply realizable, since the DMA engine is not conventional ring-based, which is required by netmap. A more challenging thing is that location of RX and TX packet buffers is not able to be located in advance, since they become known based on the length of a previous packet. If the DMA engine supports fixed size (e.g., 2KB) of packet buffer inside a lbuf, the driver could also support netmap.

Instead, we provide a minimalistic user-level driver, `lib/liblbufnet.so`, initially developed to evaluate the pure DMA performance minimizing software overheads. The kernel-level driver allows DMA-related metadata and the lbufs allocated in the kernel to be mapped to user space, so that the user-level driver can directly control the DMA engine bypassing the kernel in data plane. Whenever the kernel driver handles pending events, it checks if the user driver is initialized and waiting. If it is, the kernel driver just forwards the control to user space not processing the events in the kernel layer (see *nf10_user_callback()*). The way the control is passed to user space is via POSIX *poll/select()* interface.

To link the DMA-dependent part (*nf10_lbuf.c*) with user-level driver support, `nf10_user_ops` is defined as follows:
```
struct nf10_user_ops {
    unsigned long  (*init)(struct nf10_adapter *adapter, unsigned long arg);
    unsigned long  (*exit)(struct nf10_adapter *adapter, unsigned long arg);
    unsigned long  (*get_pfn)(struct nf10_adapter *adapter, unsigned long arg);
    void           (*prepare_rx_buffer)(struct nf10_adapter *adapter, unsigned long size);
    int            (*start_xmit)(struct nf10_adapter *adapter, unsigned long arg);
};
```

* `init`: (optional) called when the user driver is initialized (from *nf10_ioctl* with *NF10_IOCTL_CMD_INIT*).
* `exit`: (optional) called when the user driver is terminated (from *nf10_ioctl* with *NF10_IOCTL_CMD_EXIT*).
* `get_pfn`: called when the user driver requests to map DMA-related area to its address space (from *nf10_mmap*).
* `prepare_rx_buffer`: (optional) called when the user driver prepares an available RX lbuf (from *nf10_ioctl* with *NF10_IOCTL_CMD_PREPARE_RX*).
* `start_xmit`: (optional) called when the user driver requests to send a lbuf (from *nf10_ioctl* with *NF10_IOCTL_CMD_XMIT*).

So, the DMA-specific part can implement the above functions, link them to each function pointer in nf10_user_ops, and assign the nf10_user_ops to adapter->user_ops. The only mandatory function is `get_pfn` that returns the physical page frame number (PFN), which is needed by *mmap* procedure. Which area is to be mapped is determined by the order of mmap requests using adapter->nr_user_mmap. This counter is initialized to zero when the user driver is initialized and is incremented when each mmap is succeeded. The implementation of `get_pfn` is able to locate the next area to be mapped based on nr_user_mmap. The `prepare_rx_buffer` and `start_xmit` are optional, but without these, the user driver is mandated to implement those functions by mapping PCI BAR address space to directly write lbuf information to the slot registers.

During the mmap procedure, DMA-related metadata and lbufs are mapped to user space. The current kernel driver allows the user driver to share the RX lbufs. On the TX side, however, the kernel driver allocates user-exclusive TX lbufs and maps them to user space, not sharing the kernel TX lbuf; to distinguish them, we call the user-exclusive lbufs *user TX lbufs*. The reason for the separate user TX lbufs is to satisfy the need of user-level TX optimization and to obviate the synchronization of TX-related pointers. With this support, the user driver can request multiple TX lbufs with a specific size. Once all the areas are mapped, the user driver can process any coming events on its own. The RX handling is the exactly the same as that in the kernel driver. For TX, the user driver maintains its own pointers similar to the kernel to use the user TX lbufs.

For the highest performance, the user driver is allowed to be running in a busy-wait mode. At the initialization of the user-level driver, IRQ is disabled by default, so the user driver can handle all events without IRQ and sleep/wake-up at the expense of 100% CPU consumption. If the user driver wants to favor lower CPU consumption sacrificing network performance, it can also work in a block-wait mode using *poll/select()* system calls. Before the user driver goes to sleep due to no pending event, *nf10_poll* (reached by poll/select() system call) re-enables IRQ. On IRQ delivery, the kernel NAPI handler wakes up the block-waiting user driver.

Lbufnet APIs
====
The user driver provides a set of APIs hiding all the details of the lbuf DMA engine. The current set of APIs is essentially minimal for packet processing as follows:
```
/* init and exit */
int lbufnet_init(struct lbufnet_conf *conf);
int lbufnet_exit(void);
int lbufnet_register_exit_callback(lbufnet_exit_cb cb);

/* RX */
int lbufnet_register_input_callback(lbufnet_input_cb cb);
int lbufnet_input(unsigned long nr_packets, int sync_flags);

/* TX */
int lbufnet_flush(int sync_flags);
int lbufnet_write(struct lbufnet_tx_packet *pkt);
int lbufnet_output(struct lbufnet_tx_packet *pkt);
```

#### 1. lbufnet_init
Initializing the user driver.

The argument lbufnet_conf is currently like the following:
```
struct lbufnet_conf {
    unsigned long flags;
    unsigned int tx_lbuf_size;
    unsigned int tx_lbuf_count;
    int pci_direct_access;
};
```
* `flags`: TX_ON or RX_ON or TX_ON | RX_ON. If only a single direction is specified, the other direction can be handled in the kernel driver. For example, if RX_ON is solely specified, a legacy application can transmit packets via sk_buff interface.
* `tx_lbuf_size`: The size of a user TX lbuf
* `tx_lbuf_count`: The number of user TX lbufs
* `pci_direct_access`: If 1, the user driver directly writes lbuf information to slot registers without ioctl call.

For convenience, we provide a helper macro for default configuration.
```
#define DEFAULT_LBUFNET_CONF	{        \
    .flags              = RX_ON | TX_ON, \
    .tx_lbuf_size       = 128 << 10,     \
    .tx_lbuf_count      = 16,            \
    .pci_direct_access  = 0,             \
}
#define DEFINE_LBUFNET_CONF(__conf)	struct lbufnet_conf __conf = DEFAULT_LBUFNET_CONF
```

#### 2. lbufnet_exit
Finalizing the user driver.

Note that currently this function must be called before exiting. Otherwise, another application cannot initialize the user driver again.

#### 3. lbufnet_register_exit_callback
Registering an exit callback function.

A registered exit callback function is invoked when lbufnet_exit is called. Internally, the user driver catches SIGINT to call lbufnet_exit. So, lbufnet_exit is properly called when an application is terminated by a signal. If any operation is needed on termination (e.g., performance reporting), a corresponding function can be registered. The type of the callback function is `typedef void (*lbufnet_exit_cb)(struct lbufnet_stat *stat)`. The status is passed into the callback.
```
struct lbufnet_stat {
    unsigned int nr_drops;
    unsigned long nr_polls;
};
```
It will be extended further; `nr_drops` is the number of RX packet dropped from the hardware packet buffer and `nr_polls` is the number of the polls on the next packet length in a RX loop.

#### 4. lbufnet_register_input_callback [RX]
Registering an input callback function.

Before an input loop starts, an input callback function is typically needed to handle a received packet. The type of the input callback is `typedef int (*lbufnet_input_cb)(struct lbufnet_rx_packet *pkt)`. The type of the parameter passed to the callback function is lbufnet_rx_packet:
```
struct lbufnet_rx_packet {
    void *data;                   /* packet data address */
    unsigned int len;             /* packet legnth */
    unsigned int port_num;        /* port number */
    unsigned long long timestamp; /* timestamp if CONFIG_NO_TIMESTAMP=n */
};
```

#### 5. lbufnet_input [RX]
Starting an input (RX) loop.

This function starts an input loop where a registered input callback is invoked every time a packet is received. It takes two parameters: `nr_packets` and `sync_flags`. The input loop is returned after `nr_packets` packets are processed; LBUFNET_INPUT_FOREVER(=0) means that the loop is never returned. The `sync_flags` determines how the loop waits for a coming packet and the available flags are the followings:
```
enum {
    SF_NON_BLOCK = 0,   /* return immediately if no event is found */
    SF_BLOCK = 1,       /* block-wait via poll() */
    SF_BUSY_BLOCK = 2,  /* busy-wait */
};
```
As mentioned, SF_BUSY_BLOCK is for high performance.

#### 6. lbufnet_write [TX]
Writing a packet to a user TX lbuf.

The TX APIs are provided decoupling writing a packet to a TX lbuf from flushing the pending packets to the DMA engine for the sake of packet batching. `lbufnet_write` function is to write a packet to an available TX lbuf. It takes `lbufnet_tx_packet` argument.
```
struct lbufnet_tx_packet {
    void *data;
    unsigned int len;
    unsigned int port_num;
    int sync_flags;
};
```
The first three entires are the same as `lbufnet_rx_packet` and additionally `sync_flags` is specified. If no user TX lbuf is available, the way of waiting for the lbuf to be available is determined by `sync_flags`. Note that once the size of written packets exceeds the size of a TX lbuf, they are automatically flushed (requested) to the DMA engine.

#### 7. lbufnet_flush [TX]
Flushing written packets.

Once the desired number of packets are written, this function requests the transmission of the written (pending) packets. This function also takes `sync_flags` to determine the way of waiting for slot availability. 

#### 8. lbufnet_output [TX]
Writing and flushing a packet.

This function is the helper in which `lbufnet_write` and `lbufnet_flush` are called internally. The argument is the same as in `lbufnet_write` function.

For use cases, see the example applications in `apps/` directory.
