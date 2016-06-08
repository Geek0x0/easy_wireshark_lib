# easy_wireshark_lib
Easier to use Wireshark to dissect the network packet in your program

0x1. you must call environmental initialization function  
````c
      static void init_dissect_env(void)
````
0x2. create your dissect handle  
      You will be able to parse the message into the following formats:  
      **1. pdml  2. psml  3. hex**
````c
      static packet_dissect_t *create_packet_dissetc_handle(const char *type_s) 
      /* type_s input like "psml" */
````
0x3. dissect network packet by wireshark epan module
````c
     inline static int dissect_packet_to_data(packet_dissect_t *cpd, void *pkt, 
            uint16_t pkt_len, uint32_t pkt_id, void *data, uint32_t data_size)
      /*
        cpd : your create dissect handle
        pkt : network packet data with pcap packet header
        pkt_len : packet real size
        pkt_id : this packet id
        data : used to receive the converted data
        data_size : data buffer size
      */
````
