/* -*- P4_16 -*- */
/* uc student nº 1994106227 - Jully 2023*/


#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
//#define DEBUG
/* size of timestamp (ms) */
#define TIMESTAMP_24ITS 48
/* size of flow id */
#define FLOWID_BITS 128

//define MSS_FLAG

#define MULTI_TABLE 2

#ifdef MSS_FLAG
/* size of MSS */
#define MSSID_BITS 96
#endif

/* max number of rtts to track */
const bit<32> MAX_NUM_RTTS = 1024;

/* num of timestamps to tables */
const bit<32> TABLE_SIZE = 512;

/* table to store MSS for flows*/
#ifdef MSS_FLAG
const bit<32> MSS_TABLE_SIZE = 32w1000;
#endif

/* set number of hash tables */
#ifdef MULTI_TABLE
const bit<32> NUM_TABLES = (bit<32>) MULTI_TABLE;
#else
const bit<32> NUM_TABLES = 32w1;
#endif

/* handle drop index */
const bit<32> DROP_INDX = NUM_TABLES;
/* calculate size of register of hash tables */
const bit<32> REGISTER_SIZE = TABLE_SIZE * (NUM_TABLES+1); //+1 for drop table

/* default mss */
const bit<32> DEFAULT_MSS = 32w1460;

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_ARP = 0x0806;
const bit<8> TYPE_CUSTOM = 0xFF;
const bit<8> TYPE_TCP = 0x06;
const bit<8> TYPE_UDP = 0x11;
const bit<8> TYPE_ICMP = 0x01;

const bit<8> SWITCH_PORTS_NUMBER = 4; 
const bit<8> PROTECTED_TARGET = 5; 
const bit<8> SWITCH_NUMBER =4

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header arp_t {
    bit<16>    hrd_type;
    bit<16>    proto_type;
    bit<8>     hln;
    bit<8>     pln;
    bit<16>    op;
    macAddr_t  sha;
    ip4Addr_t  spa;
    macAddr_t  tha;
    ip4Addr_t  tpa;    
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
	bit<3>  ecn;
    bit<6>  flags_ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t{   
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> udplen;
    bit<16> udpchk;
}

header icmp_t{   
    bit<8> icmp_type;
    bit<8> icmp_code;
   bit<16> icmp_checksum;
}


#ifdef MSS_FLAG
/* TCP Options */
header tcp_mss_option_t{
	bit<8> kind;
	bit<8> len;
	bit<16> mss;
}
#endif

struct digest_t {
    bit<9> malicious_port_source;
    bit<128> syn_ack_diff;
    bit<32> malicious_attack_destination;
    bit<48>number_of_syn_from_unknown_sources;
}

struct metadata {
    digest_t  syn_flood_attack_digest;

    bit<1>  blacklist_hit;
    bit<1>  forward_packet;
    bit<1>  drop_packet;
    
    // Flow id //
	bit<FLOWID_BITS> flowID;
	// Hash of flow //
	bit<32> hash_key;
	// Expected ack hash //
	bit<32> eACK;
	// Size of packet payload //
	bit<32> payload_size;

	#ifdef MSS_FLAG
	bit<MSSID_BITS> mssID;
	bit<32> mss_key;
	#endif

	#ifdef SUBSAMPLE_FLAG
	//P416 doesn't allow boolean values in header/metadata
	// flag if packet is being sampled //
	bit<1> sampled;
	#endif

    bit<3> arrived_syn;
    //bit<50> aux_timestamp;
    bit<132> reg_val;
    bit<1> tcphand_ack;
    bit<130> rttreg;
    bit<16> flow_id;
    bit<16> flow_id1;
    bit<16> flow_id2;

    bit<144> conn;
    bit<16> flow_id_bf1;
    bit<16> flow_id_bf2;
    bit<16> flow_id_bf3;
    bit<1>  target_host_hit;  
    bit<1>  source_host_hit;
    bit<1>  flow_unknown;
    bit<48> timer_count;
    bit<1> solution;
    bit<8> target_host_index; //max 256 hosts 
    bit<8> source_host_index; //max 256 hosts 
    bit<32> host_port;
    bit<32> seq_num;
    bit<16> min_num;
    bit<1> alarm;
    bit<4> retransmission_num;
}


struct drop_metadata_t {
    /*empty*/
}

struct headers {
    ethernet_t          ethernet;
    arp_t               arp;
    ipv4_t              ipv4;
    tcp_t               tcp;
    udp_t               udp;
    icmp_t              icmp;    
}   

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_ARP: parse_arp;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    
    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
        
    }
    
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
            TYPE_ICMP: parse_icmp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;        
    }   
    
    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
    
    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
const bit<4> SYN_0 = 0;
const bit<4> SYN_1 = 1;
const bit<4> SYN_2 = 2;
const bit<4> SYN_3 = 3;

//const bit<48> TIMESTAMP_24 = 0x141DD76000; // 24 horas
const bit<48> TIMESTAMP_24 = 0x23C34600;// 10min

//const bit<48> TIMESTAMP_5 = 0x11E1A300; // 5 min
const bit<48> TIMESTAMP_5 =0x7270E00; // 2 min

//The SYN-ACK threshold corresponds to the limit of acceptable failed connections, after which is considered to be under attack
//for now this this value is fixed but in future should be adapted to the reality of the network

const bit<48> SYN_ACK_THRESHOLD = 50;

const bit<48> PORT_SYN_ACK_THRESHOLD = 30;

//RTT 
const bit<48> TIMER_COUNT = 120000000;    //2 min 

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    
    bit<16> flow_id;
    bit<132> reg_value=0;
    //to set which reg, 0 or 1, to use 
    //                            0 - last_timestamp_syn_reg; 1  
    //                            1- last_timestamp_syn_reg2
    bit<1>  reg_id=0; 
  
    bit<48> aux =0;
    bit<16> auux=0;
    bit<16> auux0=0;
    bit<16> auux1=0;
    bit<16> auux2=0;
    bit<1> aa=0;
    
    register<bit<48>>(1) rtt_reg; 

    register<bit<132>>(2048) last_timestamp_syn_reg1;
    register<bit<132>>(2048) last_timestamp_syn_reg2;

    //salt for hash function
    register<bit<48>>(1) boot_timestamp_reg;

    register<bit<48>>((bit<32>)(PROTECTED_TARGET+1)) flow_reg_syn; // flow_syn = SYN counts for a specific target_host
    register<bit<48>>((bit<32>)(PROTECTED_TARGET+1)) flow_reg_ack; // flow_ack= ACK counts for a specific target_host
    
    register<bit<86>>(REGISTER_SIZE) syn_timestamp_reg; //[1-0] if SynAck arrived and from [50-2] timestamp when it happened 
    
    
    register<bit<16>>(2048) bf1_conn_3handshake_reg;
    register<bit<16>>(2048) bf2_conn_3handshake_reg;
    register<bit<16>>(2048) bf3_conn_3handshake_reg;
    
    register<bit<128>>(2048)rtt_con_reg1;
    register<bit<128>>(2048)rtt_con_reg2;

    register<bit<192>>((bit<32>)(PROTECTED_TARGET*SWITCH_PORTS_NUMBER*SWITCH_NUMBER+1)) host_3hand_reg;
    register<bit<192>>((bit<32>)(PROTECTED_TARGET*SWITCH_PORTS_NUMBER*SWITCH_NUMBER+1)) digest_reg;

    register<bit<48>>(1) pulse_24_reg;
    register<bit<48>>((bit<32>)(PROTECTED_TARGET*SWITCH_PORTS_NUMBER*SWITCH_NUMBER+1)) num_of_syn_from_unknown_sources_reg;
       
    #ifdef DEBUG
        register<bit<4>>(1) loop_number_debug;

        register<bit<32>>(4) flowID_reg_debug;
        register<bit<32>>(1) hash_debug;

        register<bit<4>>(1) loop2_number_debug;
        register<bit<48>>(1) rtt_debug;
        register<bit<48>>(3) loop3_number_debug;
        register<bit<48>>(1) maxrtt_debug;
        register<bit<132>>(1) reg_val_debug;
        register<bit<144>>(1) reg_conn_debug;
        
        register<bit<48>>(1) digest_aux_syn_timestamp_reg_debug;
        register<bit<48>>(1) digest_aux_syn_reg_debug;
        register<bit<48>>(1) digest_aux_ack_reg_debug;
        
        register<bit<48>>(1) value_aux_syn_reg_debug;
        register<bit<48>>(1) value_aux_ack_reg_debug;
        register<bit<48>>(1) current_time_reg_debug;
        register<bit<4>>(1) syn_colision_debug;
        register<bit<32>>(1) seq_debug;
        register<bit<4>>(2) retransmission_number_debug;
        register<bit<48>>(1) timer_count_debug;

        register<bit<48>>(1)reg_value_now_debug;
        register<bit<48>>(1) reg_value_interval_debug;
        register<bit<48>>(1)reg_value_last_debug;
        register<bit<32>>(1)reg_value_seq_debug;
        register<bit<1>>(1) target_host_hit_debug;
        register<bit<32>>(1) host_port_debug;
        register<bit<48>>(1) lasttimestamp_diff_debug;
        register<bit<48>>(1) interarrival_value_debug;
        register<bit<48>>(1) digest_aux_sources_reg_debug;
        register<bit<128>>(6) trash_reg_debug;
    #endif
     

    action drop(){
       mark_to_drop(standard_metadata);
    }

    action drop_blacklist(){
       meta.blacklist_hit = 1;
       mark_to_drop(standard_metadata);
    }
	
	
    
    action target_host_forward(bit<1> solution, bit<8> index) {
        meta.target_host_hit = 1;        
        meta.solution = solution;
        meta.target_host_index = index;
        //solution 0 means we want to put focus on a service or hosts right before at him, similar to a proxy
        //solution 1 means we want to put focus on a service or hosts right before entering in the network we want to protect- similar to a firewall
    }

    action source_host_forward(bit<1> solution, bit<8> index) {
        meta.source_host_hit = 1;
         #ifdef DEBUG
            target_host_hit_debug.write(0,meta.source_host_hit);
         #endif
        meta.solution=solution;
        meta.source_host_index = index;
        
    }
    action host_portindex(bit<32> pair_num){
        meta.host_port= pair_num;
    }

    action ipv4_forward(egressSpec_t port, macAddr_t dstAddr) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr=hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl =hdr.ipv4.ttl - 8w1;
    }

    action forward_arp(egressSpec_t port){
        standard_metadata.egress_spec = port;
    }
    
    
    action set_conn (bit<1> in_out, bit<1> port_extra) { //port_extra determines the final part of meta.conn related to the port that will be added.
    //flag in_out it's used to reverse the direction.
    //in-out =0 -> packets syn, ack
    //in-out =1 -> packets syn/ack
        if (in_out==0){
            if (port_extra==0){
                meta.conn=(bit<144>)(hdr.ipv4.srcAddr ++ hdr.ipv4.dstAddr ++ hdr.tcp.srcPort ++ hdr.tcp.dstPort);
            } else if (port_extra==1){
                meta.conn=(bit<144>)(hdr.ipv4.srcAddr ++ hdr.ipv4.dstAddr ++ hdr.tcp.dstPort);
             }
        }else {
            if (port_extra==0){
                meta.conn=(bit<144>)(hdr.ipv4.dstAddr ++ hdr.ipv4.srcAddr ++ hdr.tcp.dstPort ++ hdr.tcp.srcPort);
            } else if (port_extra==1){
                meta.conn=(bit<144>)(hdr.ipv4.dstAddr ++ hdr.ipv4.srcAddr ++ hdr.tcp.srcPort);              
            }
        }
        #ifdef DEBUG
            reg_conn_debug.write(0, meta.conn) ;
        #endif
    }

    action compute_flow_id(bit<48> salt) {
        hash(
            flow_id,
            HashAlgorithm.crc16,
            (bit<1>)0,
            {
            salt,
            meta.conn
            },
            (bit<16>)2048);
    }


    table ipv4_lpm {
        key = { 
            hdr.ipv4.dstAddr : lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

     table forwarding_arp{
        key = { 
            hdr.arp.tpa : exact;
        }
        actions = {
            forward_arp;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
     }
 
   
    table drop_table {
        actions = {
            // No actions
            drop;
        }        
    }

  
    action get_interarrival_time () { 

        bit<48> interarrival_value;
        bit<48> maxrtt;
        bit<48> last_timestamp;
        bit<48> current_timestamp;
        bit<32> seq;
        bit<4> retransmission_number;
        bit<3> aux2=0; //to track the number of incoming SYN packets.
        
        #ifdef DEBUG
        bit<4> aux3=0;
        bit<48> calculate=0;
        timer_count_debug.write(0,meta.timer_count);
        #endif

        rtt_reg.read(maxrtt, 0);
        current_timestamp = standard_metadata.ingress_global_timestamp;
        // The reg_value will be composed for each flow_id
        // And it will be given by the concatenation of seq_number + current_timestamp +  interarrival_value + retransmission_number
        // Which will correspond to bit<130> = bit <32>+ bit<48> ++ bit<48> ++ bit<2>
        reg_value = meta.reg_val;
        retransmission_number = reg_value[3:0]; //read first to bits that correspond to syn retransmission_number
        
        interarrival_value = reg_value[51:4]; //read between bit 3 and 50 that correspond to RTT
        last_timestamp = reg_value[99:52]; //read between  bit 51 and 98 that correspond to timestamp that the packet arrived 
        seq = reg_value[131:100];

        #ifdef DEBUG
            retransmission_number_debug.write(0,retransmission_number);
            seq_debug.write(0,seq);            
            reg_value_now_debug.write(0,current_timestamp);
            reg_value_interval_debug.write(0,reg_value[51:4]);
            reg_value_last_debug.write(0,reg_value[99:52]);
            reg_value_seq_debug.write(0,reg_value[131:100]);
        #endif      
        
        if(last_timestamp != 0){
            if (seq==hdr.tcp.seqNo){
                if (retransmission_number == SYN_1){
                    //second time the SYN arrives
                    if (((current_timestamp - last_timestamp)>= 0 )  ) { 
                        //Checks if the round-trip time (RTT) is as expected.
                        reg_value[3:0] = SYN_2;
                        reg_value[51:4] = current_timestamp - last_timestamp;
                        reg_value[99:52] = current_timestamp;
                        reg_value[131:100] = hdr.tcp.seqNo;
                        #ifdef DEBUG                        
                        aux3=1;
                        #endif
                        aux2=2;
                    } else {
                        // if the round-trip time (RTT) is not as expected drop packet
                        reg_value[3:0] = SYN_0;                       
                        reg_value[51:4] = 0;
                        reg_value[99:52] = 0;
                        reg_value[131:100] = 0;
                        #ifdef DEBUG
                        aux3=2;
                        #endif
                        aux2=2;
                    }
                    
                } else {
                    if ((retransmission_number >= SYN_2) && (retransmission_number <=14)){
                        //third time the SYN arrives                        
                        reg_value[3:0] = reg_value[3:0]+1;                        
                        reg_value[51:4] = current_timestamp - last_timestamp;
                        reg_value[99:52] = current_timestamp;
                        reg_value[131:100] = hdr.tcp.seqNo;
                        //checks if  RTO is less than RTO*2;
                        #ifdef DEBUG
                        aux3=4;                        
                        calculate =(current_timestamp - last_timestamp);
                        #endif

                        if (((current_timestamp - last_timestamp)> interarrival_value ) && ((current_timestamp - last_timestamp) <= (2 * interarrival_value))){
                            // processar normalmente
                            meta.forward_packet=1;
                            aux2=3;
                            #ifdef DEBUG
                            aux3=5;    
                            #endif                          
                            reg_value[3:0] = SYN_0;
                            reg_value[51:4] = 0 ;
                            reg_value[99:52] = 0 ;
                            reg_value[131:100] = 0;                      
                           
                            
                        } else {
                            //For cases where it's known in the switch and the flow's rtt_max is greater than the measured interval.
                            if ((meta.flow_unknown==0) && (meta.timer_count > interarrival_value)) {
                                if (((current_timestamp - last_timestamp)> interarrival_value ) && ((current_timestamp - last_timestamp) <= (2 * meta.timer_count))){
                                    meta.forward_packet=1;
                                    #ifdef DEBUG
                                    aux3=6;
                                    #endif
                                    aux2=3;
                                    reg_value[3:0] = SYN_0;
                                    reg_value[51:4] = 0 ;
                                    reg_value[99:52] = 0 ;
                                    reg_value[131:100] = 0; 
                                }
                            }
                        }

                    //In the event of retransmission_number >15
                    } else {
                        reg_value[3:0] = SYN_0;
                        reg_value[51:4] = 0;
                        reg_value[99:52] = 0;
                        reg_value[131:100] = 0;
                        #ifdef DEBUG   
                        aux3=7;
                        #endif
                        aux2=0;
                    }
                    
                }
            } else {
                //In this case, the packet will be discarded due to collision, even if it's a valid request.
                #ifdef DEBUG   
                aux3=8;
                #endif
                aux2=0;  
            }

        } else {
            // The first time a SYN arrives.                      
            reg_value[3:0] = SYN_1;
            reg_value[51:4] = 0;
            reg_value[99:52] = current_timestamp;
            reg_value[131:100] = hdr.tcp.seqNo;
            #ifdef DEBUG
            aux3=9;
            #endif
            aux2=1;
        }
        meta.arrived_syn= aux2;
        meta.reg_val = reg_value;
        meta.retransmission_num = retransmission_number + 1;

        #ifdef DEBUG
            reg_val_debug.write(0,reg_value);
            seq_debug.write(0,reg_value[131:100]);
            seq_debug.write(0,hdr.tcp.seqNo);            
            syn_colision_debug.write(0, aux3);
            lasttimestamp_diff_debug.write(0, calculate);
            interarrival_value_debug.write(0,interarrival_value);
            timer_count_debug.write(0,meta.timer_count);
        #endif       
        
    }

    // Calculate payload of tcp packet //
	action set_payload_size(){
		meta.payload_size = ((bit<32>)(hdr.ipv4.totalLen - ((((bit<16>) hdr.ipv4.ihl) + ((bit<16>)hdr.tcp.dataOffset)) * 16w4)));
	}

	// Set expected ACK //
	action set_eACK(){
		meta.eACK = hdr.tcp.seqNo + meta.payload_size +1;
	}

	// save metadata tuple //
	action set_flowID(){
		if(hdr.tcp.flags_ctrl==2){
			//syn
            meta.flowID = hdr.ipv4.srcAddr ++ hdr.ipv4.dstAddr ++ hdr.tcp.srcPort ++ hdr.tcp.dstPort ++ meta.eACK;
            meta.seq_num=meta.eACK;
		}else{
			if (hdr.tcp.flags_ctrl==18){
                //syn_ack
                meta.flowID = hdr.ipv4.dstAddr ++ hdr.ipv4.srcAddr ++ hdr.tcp.dstPort ++ hdr.tcp.srcPort ++ hdr.tcp.ackNo;
                meta.seq_num=hdr.tcp.ackNo;
            }else{
                if (hdr.tcp.flags_ctrl==16){
                    //ack
                    meta.flowID = hdr.ipv4.srcAddr ++ hdr.ipv4.dstAddr ++ hdr.tcp.srcPort ++ hdr.tcp.dstPort ++ hdr.tcp.seqNo;
                    meta.seq_num = hdr.tcp.seqNo;
                }   
            }
		}

        #ifdef DEBUG
            flowID_reg_debug.write(0,meta.flowID[31:0] );
            flowID_reg_debug.write(1,meta.flowID[63:32] );
            flowID_reg_debug.write(2,meta.flowID[95:64] );
            flowID_reg_debug.write(3,meta.flowID[127:96] );
        #endif     
	}
	
	// Hash tuple into key //
	action set_key (bit<32>auxx){
		hash(meta.hash_key,
			HashAlgorithm.crc32,
			auxx,
			{meta.flowID},
			TABLE_SIZE);
            
            #ifdef DEBUG
                hash_debug.write(0,meta.hash_key); 
            #endif
	}
    
    action do_update_syn_reg(){
        bit<48> countsyn;
        bit<48> maxrtt;
        bit<86> syn_timestamp = 0;
        bit<48> current_timestamp;
        bit<48> aux_1=0;

        set_payload_size();
		set_eACK();
		set_flowID();
		set_key(0x0);
        

        current_timestamp = standard_metadata.ingress_global_timestamp;
        
        syn_timestamp_reg.read(syn_timestamp, meta.hash_key); 
        rtt_reg.read(maxrtt, 0);
        // It updates only if the syn_timestamp value of the last arrival is 0 or if the previous packet occurred more than the switch's maxrtt or TIMESTAMP_5
        // to prevent an attack on this record. In this case, the packet will be dropped.
        if (maxrtt < TIMESTAMP_5) {
            aux_1=maxrtt;
            
        } else {
            aux_1= TIMESTAMP_5;
        }
        if (((current_timestamp-syn_timestamp[49:2])> aux_1) || (syn_timestamp[49:2]==0)) {
            syn_timestamp[1:0] = 1;
            syn_timestamp[49:2] = standard_metadata.ingress_global_timestamp;
            syn_timestamp[81:50] = meta.seq_num;
            syn_timestamp[85:82] = meta.retransmission_num;
        } else {
            meta.forward_packet=0;

        }
         
        syn_timestamp_reg.write(meta.hash_key, syn_timestamp);   

    }

     action do_update_synack_reg(){
        
		set_flowID();
		set_key(0x0);
        bit<86> syn_timestamp;        
        bit<2> aux_flag= 0;

        bit<48> maxrtt;
        bit<48> current_timestamp;
        bit<48> aux_1=0;

        current_timestamp = standard_metadata.ingress_global_timestamp;
        rtt_reg.read(maxrtt, 0);

        syn_timestamp_reg.read(syn_timestamp, meta.hash_key); 
        aux_flag = syn_timestamp[1:0];
        If the maxrtt value is too large, it can lead to issues, preventing attacks based on maxrtt.
        if (maxrtt < TIMESTAMP_5) {   
            aux_1=maxrtt;
            
        } else {
            aux_1= TIMESTAMP_5;
        }
        #ifdef DEBUG
                trash_reg_debug.write(0,(bit<128>)syn_timestamp[81:50]);
                trash_reg_debug.write(0,(bit<128>)hdr.tcp.ackNo);
                trash_reg_debug.write(0,(bit<128>)syn_timestamp[1:0]);
        #endif
        if (syn_timestamp[81:50]==hdr.tcp.ackNo){
            
            if (aux_flag==1){
                aux_flag = 3; //syn_ack
                
            }else{
                
                meta.forward_packet=0;
                if (((current_timestamp-syn_timestamp[49:2])> aux_1) || syn_timestamp[49:2]==0){
                    syn_timestamp=0;
                    aux_flag = 0;
                }                
            }   
        } else{
            
            meta.forward_packet=0;
            //Clean the register
            if (((current_timestamp-syn_timestamp[49:2])> aux_1) && syn_timestamp[49:2]!=0){
                    syn_timestamp=0;
                    aux_flag = 0;
            }                
            

        }
        syn_timestamp[1:0] = aux_flag;

        #ifdef DEBUG
                trash_reg_debug.write(0,(bit<128>)syn_timestamp[1:0]);
        #endif
        // It's not possible to update a record within a conditional.
        syn_timestamp_reg.write(meta.hash_key, syn_timestamp);     
    } 
    
    action do_update_ack_reg(){
        bit<48>maxrtt;
        bit<48>medrtt=0;
        bit<48>auxrtt=0;
        bit<32>aux_hask_key2=0;
        bit<32>aux_hask_key3=0;    
        bit<48>countrtt;
        bit<86>syn_timestamp;
        bit<48>aux3rtt = 0;
        bit<128>rtt_con_value1;
        bit<128>rtt_con_value2;
        meta.rttreg=0;

        meta.tcphand_ack=0;
		set_flowID();
        set_key(0x0);
        syn_timestamp_reg.read(syn_timestamp, meta.hash_key);  
        
        meta.retransmission_num =  syn_timestamp[85:82];

        #ifdef DEBUG
            loop3_number_debug.write(2,(bit<48>)syn_timestamp[49:2]);
            loop3_number_debug.write(1,standard_metadata.ingress_global_timestamp);
        #endif
        
        rtt_reg.read(maxrtt, 0);
                   
        
        rtt_con_reg1.read(rtt_con_value1,(bit<32>)meta.flow_id_bf1);
        rtt_con_reg2.read(rtt_con_value2,(bit<32>)meta.flow_id_bf2);

        flow_reg_ack.read(countrtt, (bit<32>)meta.target_host_index); // ack register
        
        bit <48> aux7=0;
        bit<2> aux_flag= 0;
        bit<48> current_timestamp;
        bit<48> aux_1=0;
        bit<48> aux_8=0;

        current_timestamp = standard_metadata.ingress_global_timestamp;

        #ifdef DEBUG       
            trash_reg_debug.write(0,(bit<128>)maxrtt);            
        #endif
        
        if (maxrtt < TIMESTAMP_5) { 
            aux_1 = maxrtt;            
        } else {
            aux_1= TIMESTAMP_5;
        }

        #ifdef DEBUG
            trash_reg_debug.write(0,(bit<128>)aux_1);         
            trash_reg_debug.write(1,(bit<128>)syn_timestamp[1:0]);//Indicates if before was a syn or syn_ack.
            trash_reg_debug.write(2,(bit<128>)syn_timestamp[81:50]);//hdr.tcp.seqNo
            trash_reg_debug.write(2,(bit<128>) hdr.tcp.seqNo);
            trash_reg_debug.write(3,(bit<128>)syn_timestamp[49:2]); //Arrival timestamp of the last valid SYN packet for this flow.      
        #endif
        
        if ((syn_timestamp!=0) && (syn_timestamp[81:50]==hdr.tcp.seqNo)){ 
            #ifdef DEBUG
            aux7=100;
            #endif
            aux_flag = syn_timestamp[1:0]; //Indicates if before was a syn or syn_ack.

            if (aux_flag == 3) { 
                #ifdef DEBUG
                aux7=1;
                #endif
                auxrtt =(bit<48>) syn_timestamp[49:2]; //Arrival timestamp of the last valid SYN packet for this flow. 

                if (auxrtt!=0){
                    //Round-trip time (RTT) of the current flow.
                    auxrtt = standard_metadata.ingress_global_timestamp - auxrtt;
                    #ifdef DEBUG
                    aux7=2;
                    #endif
                    
                    if (auxrtt > maxrtt){
                        maxrtt = auxrtt; // To update the maximum RTT value of a flow that has already passed through the switch.
                        #ifdef DEBUG
                        aux7=3;  
                        #endif                              
                    } 
                    // Update of RTT per connection
                    if ((rtt_con_value1!=0) || (rtt_con_value2!=0)){         
                        #ifdef DEBUG
                        aux_8=1;
                        #endif
                        if (((standard_metadata.ingress_global_timestamp-rtt_con_value1[95:48])>TIMESTAMP_24) && (hdr.ipv4.dstAddr==rtt_con_value1[127:96])){ 
                            // If more than 24 hours have elapsed, restart the analysis.
                            rtt_con_value1[47:0]= auxrtt;
                            rtt_con_value1[95:48] = standard_metadata.ingress_global_timestamp;      

                            meta.rttreg[1:0]=1; // gives which reg to use
                            meta.rttreg[129:2]=rtt_con_value1;
                            #ifdef DEBUG
                            aux_8=2;
                            #endif
                        } else {  
                            #ifdef DEBUG
                            aux_8=3;
                            #endif
                            if (((standard_metadata.ingress_global_timestamp-rtt_con_value1[95:48])<TIMESTAMP_24) && (hdr.ipv4.dstAddr==rtt_con_value1[127:96])){
                                #ifdef DEBUG
                                aux_8=4;
                                #endif
                                if (auxrtt > rtt_con_value1[47:0]){
                                    rtt_con_value1[47:0]= auxrtt;
                                    #ifdef DEBUG
                                    aux_8=5;
                                    #endif
                                }
                                rtt_con_value1[95:48] = standard_metadata.ingress_global_timestamp;      
                                meta.rttreg[1:0]=1;
                                meta.rttreg[129:2]=rtt_con_value1;
                            } else {
                                ##ifdef DEBUG
                                aux_8=6;
                                #endif
                                if (((standard_metadata.ingress_global_timestamp-rtt_con_value2[95:48])>TIMESTAMP_24) && (hdr.ipv4.dstAddr==rtt_con_value2[127:96])){ 
                                    
                                    rtt_con_value2[47:0]= auxrtt;                                            
                                    rtt_con_value2[95:48] = standard_metadata.ingress_global_timestamp;      
                                    meta.rttreg[1:0]=2;
                                    meta.rttreg[129:2]=rtt_con_value2;
                                    #ifdef DEBUG
                                    aux_8=7;
                                    #endif
                                } else {
                                    #ifdef DEBUG
                                    aux_8=8;
                                    #endif
                                    if (((standard_metadata.ingress_global_timestamp-rtt_con_value2[95:48])<TIMESTAMP_24) && (hdr.ipv4.dstAddr==rtt_con_value2[127:96])){
                                        #ifdef DEBUG
                                        aux_8=9;
                                        #endif
                                        if (auxrtt > rtt_con_value2[47:0]){
                                            rtt_con_value2[47:0]= auxrtt;
                                            #ifdef DEBUG
                                            aux_8=10;
                                            #endif
                                        }
                                        rtt_con_value2[95:48] = standard_metadata.ingress_global_timestamp;      
                                        meta.rttreg[1:0]=2; 
                                        meta.rttreg[129:2]=rtt_con_value2;
                                    } else {
                                        #ifdef DEBUG
                                        aux_8=11;
                                        #endif
                                        if (rtt_con_value1==0) {
                                            rtt_con_value1[47:0]= auxrtt;
                                            rtt_con_value1[95:48] = standard_metadata.ingress_global_timestamp;  
                                            rtt_con_value1[127:96] = hdr.ipv4.dstAddr;    
                                            meta.rttreg[1:0]=1; 
                                            meta.rttreg[129:2]=rtt_con_value1;
                                            #ifdef DEBUG
                                            aux_8=12;
                                            #endif
                                                
                                        } else{
                                            #ifdef DEBUG
                                            aux_8=13;
                                            #endif
                                            if (rtt_con_value2==0) {
                                                rtt_con_value2[47:0]= auxrtt;
                                                rtt_con_value2[95:48] = standard_metadata.ingress_global_timestamp; 
                                                rtt_con_value2[127:96] = hdr.ipv4.dstAddr;     
                                                meta.rttreg[1:0]=2; 
                                                meta.rttreg[129:2]=rtt_con_value2;
                                                #ifdef DEBUG
                                                aux_8=14;
                                                #endif

                                            } else if ((standard_metadata.ingress_global_timestamp-rtt_con_value1[95:48])>TIMESTAMP_24){
                                                rtt_con_value1[47:0]= auxrtt;
                                                rtt_con_value1[95:48] = standard_metadata.ingress_global_timestamp; 
                                                rtt_con_value1[127:96] = hdr.ipv4.dstAddr;     
                                                meta.rttreg[1:0]=1; 
                                                meta.rttreg[129:2]=rtt_con_value1;
                                                #ifdef DEBUG
                                                aux_8=15;
                                                #endif
                                            } else if ((standard_metadata.ingress_global_timestamp-rtt_con_value2[95:48])>TIMESTAMP_24){
                                                rtt_con_value2[47:0]= auxrtt;
                                                rtt_con_value2[95:48] = standard_metadata.ingress_global_timestamp; 
                                                rtt_con_value2[127:96] = hdr.ipv4.dstAddr;     
                                                meta.rttreg[1:0]=2; 
                                                meta.rttreg[129:2]=rtt_con_value2;
                                                #ifdef DEBUG
                                                aux_8=16;
                                                #endif
                                            }                                            
                                        }
                                    }
                                }
                            }                            
                        }
                    } else {
                        
                            rtt_con_value1[47:0]= auxrtt;
                            rtt_con_value1[95:48] = standard_metadata.ingress_global_timestamp;  
                            rtt_con_value1[127:96] = hdr.ipv4.dstAddr;   
                            meta.rttreg[1:0]=1;
                            meta.rttreg[129:2]=rtt_con_value1;
                            #ifdef DEBUG
                            aux_8=17;
                            #endif
                    }                
                } 
                meta.tcphand_ack=1;
                syn_timestamp = 0; //to clean the register
            }             
            // else the packet is droped
        } else {       
            bf1_conn_3handshake_reg.read(auux0,(bit<32>)meta.flow_id_bf1);                                                                        
            bf2_conn_3handshake_reg.read(auux1,(bit<32>)meta.flow_id_bf2);
            bf3_conn_3handshake_reg.read(auux2,(bit<32>)meta.flow_id_bf3); 
            
            if (((auux0>0) && (auux1>0) && (auux2>0)) && (syn_timestamp==0)){ // if tcp connection exists and syn_timestamp==0 (when 3handshake succeded)
                meta.forward_packet=1;
            }
            // Clear the record if the SYNACK has already expired
            if (((current_timestamp-syn_timestamp[49:2])> aux_1) && syn_timestamp[49:2]!=0){
                    syn_timestamp=0;
                    aux_flag = 0;
            }                                     
        }
        
        //Conditional execution in actions unsupported on this target
        //General values for the switch
        rtt_reg.write(0,maxrtt);      
        
        syn_timestamp_reg.write(meta.hash_key, syn_timestamp);  //Clear the registry that stores the 3-way handshake (cannot be updated within an if statement)
        
        #ifdef DEBUG
            loop3_number_debug.write(0,aux7);
            maxrtt_debug.write(0,maxrtt);
            rtt_debug.write(0,auxrtt);
            trash_reg_debug.write(5, (bit<128>)aux_8);
        #endif
    }
    
    action get_min_num(bit<16> a,bit<16>b,bit<16>c){
        if ((a > b) && (b > c)) {
            // c is the smallest
            meta.min_num =c;
        } else if ((a > b) && (b < c)) {
            // b is the smallest
            meta.min_num = b;
        } else if ((a < b) && (b > c)) {
            // a is the smallest
            meta.min_num = a;
        } else if ((a < b) && (b < c)) {
            // a is the smallest
            meta.min_num = a;
        } else if ((a == b) && (b > c)) {
            // a e b are equal and c is the smallest
            meta.min_num = c;
        } else if ((a == b) && (b < c)) {
            // a e b are equal and c is the smallest
            meta.min_num = c;
        } else if ((a > b) && (b == c)) {
            // a is the largest, and b and c are equal.
            meta.min_num = c;
        } else if ((a < b) && (b == c)) {
            // b and c are equal and a is the smallest
            meta.min_num = a;
        } else if ((a == c) && (b > c)) {            
        // a and c are equal and b is the biggest.
            meta.min_num = b;
        } else if ((a == c) && (b < c)) {            
        // a and c are equal and b is the smallest.
            meta.min_num = b;
        } else {
            // All numbers are equal.
            meta.min_num = a;
        }
    }

    // Define the blacklist table
    table blacklist{
        key = {
            hdr.ipv4.srcAddr : exact;
        }
        actions = {
            drop_blacklist;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }
    
    table port_blacklist{
        key = {
            standard_metadata.ingress_port:exact;
        }
        actions = {
            drop_blacklist;
            NoAction;
        }
        size = SWITCH_PORTS_NUMBER;
        default_action = NoAction;
    }


    table target_host{
        key = {
            hdr.ipv4.dstAddr:exact;
        }
        actions = {
            target_host_forward;
            NoAction;
        }
        size = PROTECTED_TARGET;
        default_action = NoAction;
    }

    table source_host{
        key = {
            hdr.ipv4.srcAddr:exact;
        }
        actions = {
            source_host_forward;
            NoAction;
        }
        size = PROTECTED_TARGET;
        default_action = NoAction;
    }

    table hostportind{
        key = {
            hdr.ipv4.dstAddr:exact;
            standard_metadata.ingress_port:exact;

        }
        actions = {
            host_portindex;
            NoAction;
        }
        size = PROTECTED_TARGET*SWITCH_PORTS_NUMBER*SWITCH_NUMBER+1;
        default_action = NoAction;
    }
    
    
    ///////////////////////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////////////

    apply {
        
        if(hdr.ipv4.isValid()){
            //Prevent Land Attack
            if (hdr.ipv4.srcAddr != hdr.ipv4.dstAddr){
                meta.forward_packet=0;
                
                bit <48> pulse_24;
                boot_timestamp_reg.read(aux,0); 
                
                if (aux == 0){
                    aux = standard_metadata.ingress_global_timestamp;
                    boot_timestamp_reg.write(0,aux);
                    pulse_24_reg.write(0,0);                         
                }
                pulse_24_reg.read(pulse_24,0);
                
                bit<48> current_time = standard_metadata.ingress_global_timestamp;
                bit<1> update_24h=0;
                
                #ifdef DEBUG                
                    current_time_reg_debug.write(0,standard_metadata.ingress_global_timestamp);
                #endif

                bit<48> value_aux_syn=0;
                bit<48> value_aux_ack=0;
                meta.source_host_hit=0;
                meta.target_host_hit=0;
                
                // If the packet comes from an IP on the blacklist or arrives at a switch port listed in the port_blacklist table due to malicious traffic indicative of a SYN Flood attack.
                if ((!blacklist.apply().hit) && (!port_blacklist.apply().hit)){ 
                    target_host.apply();
                    source_host.apply();
                    if (((meta.target_host_hit==1)) || ((meta.source_host_hit==1))){

                        bit<1> Alarm_ddos;

                        Alarm_ddos = 0;
                        meta.alarm =0;

                        // tcp protocol
                        if(hdr.ipv4.protocol==0x06){
                            hostportind.apply();

                            #ifdef DEBUG
                                host_port_debug.write(0,meta.host_port);
                            #endif 

                
                            bit<192>digest_aux;
                            digest_reg.read(digest_aux,meta.host_port);
                            
                            
                            //Create cycles of TIMESTAMP_24.
                            if ((((current_time - aux) > TIMESTAMP_24) && ((current_time - pulse_24) >=TIMESTAMP_24)) && (digest_aux==0)){
                                pulse_24_reg.write(0,current_time);
                                pulse_24=current_time;
                                //The corresponding record will be cleared when the direction is known through the TCP flags.
                                flow_reg_syn.write(0,1);
                                flow_reg_ack.write(0,1);
                                rtt_reg.write(0,0);     
                                update_24h=1;
                            } 

                            set_conn(0x0,0x1);
                            compute_flow_id(0x0);
                            meta.flow_id_bf1=flow_id;
                            
                            compute_flow_id((aux+2));
                            meta.flow_id_bf2=flow_id;
                            
                            compute_flow_id((aux+5));
                            meta.flow_id_bf3=flow_id;
                            
                            //Compute the 2 hashes for the packet.
                            set_conn(0x0,0x0);
                            
                            compute_flow_id(0x0);
                            meta.flow_id=flow_id;
                            
                            compute_flow_id((aux+2));
                            meta.flow_id1=flow_id;
                            
                            compute_flow_id((aux+5));
                            meta.flow_id2=flow_id;

                            bit<48> num_of_syn_from_unknown_sources;
                            //Clearing the counter every THRESHOLD_24h
                            if (update_24h==0) {
                                num_of_syn_from_unknown_sources_reg.read(num_of_syn_from_unknown_sources,meta.host_port);
                            } else{
                                num_of_syn_from_unknown_sources_reg.write(meta.host_port,0);
                                num_of_syn_from_unknown_sources=0;
                            }

                            bit<192> aux_port;    

                            // Check if the TCP flags indicate a SYN packet and the port is not identified as a source of malicious traffic.
                            if ((hdr.tcp.flags_ctrl == 0x02) && ((meta.target_host_hit==1))){
                                //Increments the register count_ack
                                meta.arrived_syn=4; // inializaç~ao
                                //Reset after the threshold of 24.
                                flow_reg_syn.read(value_aux_syn,0);
                                flow_reg_ack.read(value_aux_ack,0);
                                if ((value_aux_syn==1) && (value_aux_ack==1)) {
                                    flow_reg_syn.write((bit<32>)meta.target_host_index,0);
                                    flow_reg_ack.write((bit<32>)meta.target_host_index,0);    
                                }

                                flow_reg_syn.read(value_aux_syn,(bit<32>)meta.target_host_index);
                                flow_reg_ack.read(value_aux_ack,(bit<32>)meta.target_host_index);

                                //Reusing the auxiliary variables.
                                host_3hand_reg.read(aux_port,meta.host_port);                                
                                
                                ///Reset SYN and ACK counters per port every 24 hours based on the last ACK.
                                if (aux_port[95:48]< pulse_24) {                                    
                                    host_3hand_reg.write(meta.host_port, 0);

                                }
                                flow_reg_syn.read(value_aux_syn,(bit<32>)meta.target_host_index);
                                 
                                 #ifdef DEBUG
                                    value_aux_syn_reg_debug.write(0,value_aux_syn);
                                    value_aux_syn_reg_debug.write(0,0);
                                #endif

                                value_aux_syn = value_aux_syn + 1;
                                flow_reg_syn.write((bit<32>)meta.target_host_index, value_aux_syn);
                                
                                #ifdef DEBUG
                                    value_aux_syn_reg_debug.write(0,value_aux_syn);
                                #endif

                                flow_reg_ack.read(value_aux_ack,(bit<32>)meta.target_host_index);
                                
                                meta.forward_packet=1;
                                //Check if the SYN-ACK threshold has been reached.

                                if (value_aux_syn - value_aux_ack > (bit<48>)SYN_ACK_THRESHOLD)  {
                                    Alarm_ddos = 1;
                                    if ((aux_port[47:0] - aux_port[143:96]) > (bit<48>)PORT_SYN_ACK_THRESHOLD){
                                        meta.alarm =1;
                                    }                                    
                                }                            

                                // Change in analysis per port.
                                value_aux_syn = aux_port[47:0]+1;
                                value_aux_ack = aux_port[143:96];
                                
                                aux_port[47:0]=aux_port[47:0]+1;
                                aux_port[95:48]= standard_metadata.ingress_global_timestamp;
                                host_3hand_reg.write(meta.host_port, aux_port);

                                

                                if ((meta.alarm==1) && (Alarm_ddos == 1)){
                                    meta.forward_packet=0;
                                    bit<128>rtt_value_aux1;
                                    bit<128>rtt_value_aux2;
                                    bf1_conn_3handshake_reg.read(auux0,(bit<32>)meta.flow_id_bf1);                                                                                
                                    bf2_conn_3handshake_reg.read(auux1,(bit<32>)meta.flow_id_bf2);
                                    bf3_conn_3handshake_reg.read(auux2,(bit<32>)meta.flow_id_bf3);                                            
                                        
                                    if((auux0>0) && (auux1>0) && (auux2>0)) { // if conn is known by the switch 
                                        auux=0;
                                        rtt_con_reg1.read(rtt_value_aux1, (bit<32>)meta.flow_id_bf1);
                                        rtt_con_reg2.read(rtt_value_aux2, (bit<32>)meta.flow_id_bf2);
                                        if ((rtt_value_aux1[127:96]==hdr.ipv4.dstAddr)){
                                            if ((rtt_value_aux2[127:96]!=hdr.ipv4.dstAddr)){
                                                meta.timer_count = rtt_value_aux1[47:0];
                                                
                                                //New TIMESTAMP_24 cycle - resetting the counter if the last 3-way handshake passed more than TIMESTAMP_24 ago.
                                                if ((rtt_value_aux1[95:48] - pulse_24) > TIMESTAMP_24){
                                                    auux=1;
                                                    get_min_num(auux0,auux1,auux2);
                                                    auux=meta.min_num;

                                                    bf1_conn_3handshake_reg.write((bit<32>)meta.flow_id_bf1,auux0-auux+1);                                                                                    
                                                    bf2_conn_3handshake_reg.write((bit<32>)meta.flow_id_bf2,auux1-auux+1);
                                                    bf3_conn_3handshake_reg.write((bit<32>)meta.flow_id_bf3, auux2-auux+1);
                                                }

                                            } else {                                
                                                if ((rtt_value_aux2[95:48] < rtt_value_aux1[95:48])){
                                                    meta.timer_count = rtt_value_aux1[47:0];
                                                    
                                                    //New TIMESTAMP_24 cycle - counter reset
                                                    if ((rtt_value_aux1[95:48] - pulse_24) > TIMESTAMP_24){
                                                        auux=1;
                                                        get_min_num(auux0,auux1,auux2);
                                                        auux=meta.min_num;

                                                        bf1_conn_3handshake_reg.write((bit<32>)meta.flow_id_bf1,auux0-auux+1);                                                                                        
                                                        bf2_conn_3handshake_reg.write((bit<32>)meta.flow_id_bf2,auux1-auux+1);
                                                        bf3_conn_3handshake_reg.write((bit<32>)meta.flow_id_bf3, auux2-auux+1);
                                                    }

                                                } else {
                                                    meta.timer_count = rtt_value_aux2[47:0];
                                                    
                                                    if ((rtt_value_aux2[95:48] - pulse_24) > TIMESTAMP_24){
                                                        
                                                        //New cycle of TIMESTAMP_24 - counter reset
                                                        auux=1;
                                                        get_min_num(auux0,auux1,auux2);
                                                        auux=meta.min_num;

                                                        bf1_conn_3handshake_reg.write((bit<32>)meta.flow_id_bf1,auux0-auux+1);                                                                                        
                                                        bf2_conn_3handshake_reg.write((bit<32>)meta.flow_id_bf2,auux1-auux+1);
                                                        bf3_conn_3handshake_reg.write((bit<32>)meta.flow_id_bf3, auux2-auux+1);
                                                    }

                                                }
                                            }
                                        
                                        }else if ((rtt_value_aux2[127:96]==hdr.ipv4.dstAddr)){
                                            meta.timer_count = rtt_value_aux2[47:0];
                                            
                                            if ((rtt_value_aux2[95:48] - pulse_24) > TIMESTAMP_24){
                                                    //New cycle of TIMESTAMP_24 - counter reset
                                                    auux=1;
                                                    get_min_num(auux0,auux1,auux2);
                                                    auux=meta.min_num;

                                                    bf1_conn_3handshake_reg.write((bit<32>)meta.flow_id_bf1,auux0-auux+1);                                                                                        
                                                    bf2_conn_3handshake_reg.write((bit<32>)meta.flow_id_bf2,auux1-auux+1);
                                                    bf3_conn_3handshake_reg.write((bit<32>)meta.flow_id_bf3, auux2-auux+1);
                                            }


                                        } else {
                                            rtt_reg.read(meta.timer_count,0); //If the flow is unknown, then use the maximum RTT value that has passed through the switch. 
                                        }

                                    } else {
                                        rtt_reg.read(meta.timer_count,0);
                                        meta.flow_unknown=1;   

                                        num_of_syn_from_unknown_sources=num_of_syn_from_unknown_sources+1;
                                        num_of_syn_from_unknown_sources_reg.write(meta.host_port,num_of_syn_from_unknown_sources);
                                    }

                                    #ifdef DEBUG
                                        timer_count_debug.write(0,meta.timer_count);  
                                    #endif              

                                    //Sends attack information to the controller.
                                    meta.syn_flood_attack_digest.syn_ack_diff = (bit<128>)(value_aux_syn - value_aux_ack);
                                    meta.syn_flood_attack_digest.malicious_port_source = standard_metadata.ingress_port;
                                    meta.syn_flood_attack_digest.malicious_attack_destination = hdr.ipv4.dstAddr;
                                    meta.syn_flood_attack_digest.number_of_syn_from_unknown_sources = num_of_syn_from_unknown_sources;

                                    //Sends to the controller only when there is a difference of 1024 packets between SYN and ACK (per port), 
                                    //allowing it to update the port_blacklist table and thus block packets arriving at that switch port for some time
                                    bit<48> aux_diff;
                                    aux_diff= (value_aux_syn - value_aux_ack)>>10;
                                    
                                    //If previously the controller was informed that we were under attack, then after a certain threshold, verify if the attack condition still persists. 
                                    //If not, update the digest_reg and host_3hand_reg records to reflect this
                                    if(digest_aux!=0){ 
                                        #ifdef DEBUG
                                            digest_aux_syn_timestamp_reg_debug.write(0,digest_aux[47:0]);
                                            digest_aux_syn_reg_debug.write(0,digest_aux[95:48]);
                                            digest_aux_ack_reg_debug.write(0,digest_aux[143:96]);
                                            digest_aux_sources_reg_debug.write(0,digest_aux[191:144]);
                                            
                                            value_aux_syn_reg_debug.write(0,value_aux_syn);
                                            value_aux_ack_reg_debug.write(0,value_aux_ack);
                                        #endif

                                        if ((current_time - digest_aux[47:0])> TIMESTAMP_5){
                                            if (((value_aux_syn-digest_aux[95:48]) >= (value_aux_ack-digest_aux[143:96])) && ((value_aux_syn-digest_aux[95:48]) < 1024)) {
                                                digest_aux[47:0]= current_time;
                                                digest_aux[95:48]= value_aux_ack + (value_aux_syn-digest_aux[95:48]); //The difference between the previous interval and this one.
                                                digest_aux[143:96]= value_aux_ack;
                                                digest_aux[191:144]=num_of_syn_from_unknown_sources;
                                                meta.syn_flood_attack_digest.syn_ack_diff = (bit<128>) (digest_aux[95:48]-digest_aux[143:96]);
                                                meta.syn_flood_attack_digest.malicious_port_source = standard_metadata.ingress_port; // bit 9
                                                meta.syn_flood_attack_digest.malicious_attack_destination = hdr.ipv4.dstAddr;
                                                meta.syn_flood_attack_digest.number_of_syn_from_unknown_sources = num_of_syn_from_unknown_sources;
                                                //Informs the controller that the attack has not occurred in the last TIMESTAMP_5.
                                                
                                                digest(3,meta.syn_flood_attack_digest);
                                                aux_port[47:0]= digest_aux[95:48];//n of syn
                                                aux_port[143:96]= digest_aux[143:96];//n of ack
                
                                                value_aux_syn = aux_port[47:0];
                                                value_aux_ack = aux_port[143:96];
                                                aux_diff= (value_aux_syn - value_aux_ack)>>10;
                                                host_3hand_reg.write(meta.host_port, aux_port);
                                                
                                                digest_reg.write(meta.host_port,0);

                                                #ifdef DEBUG
                                                    digest_aux_syn_reg_debug.write(0,digest_aux[95:48]);
                                                    digest_aux_ack_reg_debug.write(0,digest_aux[143:96]);
                                                #endif

                                            }
                                        }
                                    }
                                    #ifdef DEBUG
                                        if(digest_aux==0){ 
                                            value_aux_syn_reg_debug.write(0,value_aux_syn);
                                            value_aux_ack_reg_debug.write(0,value_aux_ack);
                                        }
                                    #endif

                                    
                                    if ((aux_diff>0) && ((current_time - digest_aux[47:0])> TIMESTAMP_5)){    
                                        //Sends to the controller only when there is a difference of 1024 packets between SYN and ACK (per port), and if the TIMESTAMP_5 threshold has passed since the last update.

                                         if (((value_aux_syn - value_aux_ack) & 0x3FF)==0) {
                                            //Sends information to the controller indicating an ongoing attack
                                            digest(1,meta.syn_flood_attack_digest);
                                            digest_aux[95:48]= value_aux_syn;    
                                            digest_aux[47:0]= current_time;
                                            digest_aux[143:96]= value_aux_ack;
                                            digest_aux[191:144]=num_of_syn_from_unknown_sources;
                                            digest_reg.write(meta.host_port, digest_aux);
                                        }
                                    
                                    }
                                    digest_reg.read(digest_aux,meta.host_port);
                                    //If the source is unknown and the port is identified as the source of a SYN flood attack, it blocks.
                                    //If the source is known and the port is identified as the source of a SYN flood attack, it only allows through when we want to protect a specific service (solution 0).
                                    //In the case where we want to protect an entire network (e.g., our intranet), it blocks.
                                    
                                    if ((meta.flow_unknown==1) && (digest_aux!=0)){
                                        drop();

                                    
                                    } else if ((meta.flow_unknown==0) && (digest_aux!=0) && (meta.solution==1) ){ 
                                        //In the previous conditions, if the source is known and it hasn't been TIMESTAMP_24 since the last connection, it doesn't increment the number of SYN packets.
                                        if (auux==0) {//The auux variable tells us if TIMESTAMP_24 has passed since the last connection.
                                            //Don't count the SYN packets that are rejected because they are in a blocking period.
                                            flow_reg_syn.read(value_aux_syn,(bit<32>)meta.target_host_index);
                                    
                                            #ifdef DEBUG
                                                value_aux_syn_reg_debug.write(0,value_aux_syn);
                                                value_aux_syn_reg_debug.write(0,0);
                                            #endif

                                            value_aux_syn = value_aux_syn - 1;
                                            flow_reg_syn.write((bit<32>)meta.target_host_index, value_aux_syn); 
                                        }
                                        drop();
                                    } 
                                    else {

                                        bit<132> reg_value1=10;
                                        bit<132> reg_value2=10;
                                        last_timestamp_syn_reg1.read(reg_value1, (bit<32>)meta.flow_id1 );
                                        last_timestamp_syn_reg2.read(reg_value2, (bit<32>)meta.flow_id2 );
                                        if ((reg_value1 == 0) && (reg_value2 == 0)){
                                            reg_id =0;
                                            reg_value = reg_value1 ;

                                            #ifdef DEBUG
                                                loop_number_debug.write(0,1);
                                            #endif


                                        } else { // from if ((reg_value1 == 0) && (reg_value2 == 0)){
                                            if ((reg_value1 ==0) && (!(reg_value2 ==0))){
                                                if (reg_value2[131:100] == hdr.tcp.seqNo){
                                                    reg_id =1;
                                                    reg_value = reg_value2 ;
                                                    #ifdef DEBUG
                                                        loop_number_debug.write(0,2);
                                                    #endif

                                                } else{
                                                    reg_id =0;
                                                    reg_value = reg_value1 ;

                                                    #ifdef DEBUG
                                                        loop_number_debug.write(0,3);
                                                    #endif
                                                }
                                            } else{ // from if ((reg_value1 ==0) && (!(reg_value2 ==0))){
                                                if ((!(reg_value1 ==0)) && (reg_value2 ==0)){
                                                    if ((current_time - reg_value1[99:52]) >  meta.timer_count ) { //timer_max
                                                        if (reg_value1[131:100] == hdr.tcp.seqNo){
                                                            reg_id =0;
                                                            reg_value = reg_value1 ;

                                                            #ifdef DEBUG
                                                                loop_number_debug.write(0,4);
                                                            #endif

                                                        } else{
                                                            reg_id =1;
                                                            reg_value = reg_value2 ;

                                                            #ifdef DEBUG
                                                                loop_number_debug.write(0,5);
                                                                trash_reg_debug.write(0,(bit<128>)reg_value1[131:100]);
                                                            #endif

                                                        }
                                                    }    
                                                } else{ // from if ((!(reg_value1 ==0)) && (reg_value2 ==0)){
                                                    if ((!(reg_value1 ==0)) && (!(reg_value2 ==0))){
                                                        if ((reg_value1[131:100] == hdr.tcp.seqNo) && (!(reg_value2[131:100] == hdr.tcp.seqNo))){
                                                            reg_id =0;
                                                            reg_value = reg_value1 ;

                                                            #ifdef DEBUG
                                                                loop_number_debug.write(0,6);
                                                            #endif

                                                        } else{ // from if ((reg_value1[131:100] == hdr.tcp.seqNo) && (!(reg_value2[131:100] == hdr.tcp.seqNo))){
                                                            if ((!(reg_value1[131:100] == hdr.tcp.seqNo)) && (reg_value2[131:100] == hdr.tcp.seqNo)){
                                                                reg_id =1;
                                                                reg_value = reg_value2 ;

                                                                #ifdef DEBUG
                                                                    loop_number_debug.write(0,7);
                                                                #endif
                                                            
                                                            } else{ // from if ((!(reg_value1[131:100] == hdr.tcp.seqNo)) && (reg_value2[131:100] == hdr.tcp.seqNo)){
                                                            
                                                                if ((reg_value1[131:100] == hdr.tcp.seqNo) && (reg_value2[131:100] == hdr.tcp.seqNo)) {
                                                                    
                                                                    if ((reg_value1[99:52] < reg_value2[99:52]) && ((current_time - reg_value1[99:52]) >  meta.timer_count )){
        
                                                                        last_timestamp_syn_reg1.write((bit<32>)meta.flow_id1, 0 );
                                                                        
                                                                        if ((current_time - reg_value2[99:52]) <  meta.timer_count ) {
                                                                            reg_id =1;
                                                                            reg_value = reg_value2;
                                                                        } else {
                                                                            reg_id=0;
                                                                            reg_value = 0;
                                                                            last_timestamp_syn_reg2.write((bit<32>)meta.flow_id2, 0 );
                                                                        }   
                                                                                                                            
                                                                        #ifdef DEBUG
                                                                            loop_number_debug.write(0,8);
                                                                        #endif
                                                                        

                                                                    } else{
                                                                        if ((reg_value2[99:52] < reg_value1[99:52]) && ((current_time - reg_value2[99:52]) >  meta.timer_count )){                                                  

                                                                            last_timestamp_syn_reg2.write((bit<32>)meta.flow_id2, 0 );
                                                                            
                                                                                if ((current_time - reg_value1[99:52]) <  meta.timer_count ) {
                                                                                    reg_id =0;
                                                                                    reg_value = reg_value1;
                                                                                } else {
                                                                                    reg_id =0; 
                                                                                    reg_value = 0;
                                                                                    last_timestamp_syn_reg1.write((bit<32>)meta.flow_id1, 0 );
                                                                                }   

                                                                            #ifdef DEBUG
                                                                                loop_number_debug.write(0,9);
                                                                            #endif

                                                                        } else{
                                                                            if (reg_value2[99:52] < reg_value1[99:52]){
                                                                                if (((current_time - reg_value1[99:52]) <  meta.timer_count )){
                                                                                        reg_id =0;
                                                                                        reg_value = reg_value1;
                                                                                        last_timestamp_syn_reg2.write((bit<32>)meta.flow_id2, 0 );

                                                                                } else {
                                                                                            reg_id =1;
                                                                                            reg_value = reg_value2;
                                                                                            last_timestamp_syn_reg1.write((bit<32>)meta.flow_id1, 0 );
                                                                                        
                                                                                }    
                                                                                #ifdef DEBUG
                                                                                    loop_number_debug.write(0,10);
                                                                                #endif
                                                                            } else {
                                                                                if (reg_value1[99:52] < reg_value2[99:52]){
                                                                                    if ((current_time - reg_value2[99:52]) <  meta.timer_count ) {
                                                                                        reg_id =1;
                                                                                        reg_value = reg_value2;
                                                                                        #ifdef DEBUG
                                                                                            loop_number_debug.write(0,11);
                                                                                        #endif
                                                                                        last_timestamp_syn_reg1.write((bit<32>)meta.flow_id1, 0 );
                                                                                    } else {
                                                                                        reg_id =0;
                                                                                        reg_value = reg_value1;
                                                                                        last_timestamp_syn_reg2.write((bit<32>)meta.flow_id2, 0 );
                                                                                    }
                                                                                    #ifdef DEBUG                                                                                    
                                                                                        loop_number_debug.write(0,11);
                                                                                    #endif
                                                                                }                                                                                   
                                                                            } 
                                                                        }
                                                                    }
                                                                } else {
                                                                   //The sequence number doesn't match. 
                                                                    if ((!(reg_value1[131:100] == hdr.tcp.seqNo)) && (!(reg_value2[131:100] == hdr.tcp.seqNo))){
                                                                        if (reg_value1[99:52] < reg_value2[99:52]) {
                                                                            if ((current_time - reg_value1[99:52]) >  meta.timer_count ) {
                                                                                reg_id =0;
                                                                                reg_value = 0;
                                                                                last_timestamp_syn_reg1.write((bit<32>)meta.flow_id1, 0 );
                                                                            } else {
                                                                                if ((current_time - reg_value2[99:52]) >  meta.timer_count ){
                                                                                    reg_id =1;
                                                                                    reg_value = 0;
                                                                                    last_timestamp_syn_reg2.write((bit<32>)meta.flow_id2, 0 );
                                                                                } else {
                                                                                    
                                                                                    drop();
                                                                                }
                                                                            }
                                                                            
                                                                            
                                                                        } else {
                                                                            
                                                                            if ((reg_value2[99:52] < reg_value1[99:52]) ){
                                                                                if ((current_time - reg_value2[99:52]) >  meta.timer_count ){ 
                                                                                    reg_id =1;
                                                                                    reg_value = 0;
                                                                                    last_timestamp_syn_reg2.write((bit<32>)meta.flow_id2, 0 );
                                                                                } else {
                                                                                    if ((current_time - reg_value1[99:52]) >  meta.timer_count ){
                                                                                        reg_id =0;
                                                                                        reg_value = 0;
                                                                                        last_timestamp_syn_reg1.write((bit<32>)meta.flow_id1, 0 );
                                                                                    } else {
                                                                                        
                                                                                        drop();
                                                                                    }
                                                                                }

                                                                            } else {
                                                                                if ((reg_value2[99:52]== reg_value1[99:52]) ){
                                                                                if ((current_time - reg_value1[99:52]) >  meta.timer_count ){ 
                                                                                        reg_id =0;
                                                                                        reg_value = 0;
                                                                                        last_timestamp_syn_reg1.write((bit<32>)meta.flow_id1, 0 );
                                                                                        last_timestamp_syn_reg2.write((bit<32>)meta.flow_id2, 0 );

                                                                                } else {
                                                                                    
                                                                                    drop();
                                                                                }
                                                                                }
                                                                                
                                                                            } 
                                                                        } 
                                                                    }
                                                                } 
                                                            }
                                                        }
                                                    }
                                                }

                                            }

                                        }
                                        meta.reg_val = reg_value;
                                        get_interarrival_time(); //( return reg_value);
                                        reg_value = meta.reg_val;

                                        if (reg_id == 0) {
                                            last_timestamp_syn_reg1.write((bit<32>)meta.flow_id1, reg_value );
                                        } else {
                                            last_timestamp_syn_reg2.write((bit<32>)meta.flow_id2, reg_value );
                                        }
                                    }

                                } else{
                                    meta.forward_packet=1;                                    
                                }

                                if ((meta.arrived_syn==4) || (meta.arrived_syn==3)){
                                    do_update_syn_reg();
                                }


                            } else {                   // from if(hdr.tcp.flags_ctrl == syn)
                                
                                // Check if the TCP flags indicate a ACK packet.
                                if (((hdr.tcp.flags_ctrl == 0x10) && ((meta.target_host_hit==1)))){
                                    //increments the register count_ack
                                    bit<32> payload_size;
                                    payload_size = ((bit<32>)(hdr.ipv4.totalLen) - ((((bit<32>)hdr.ipv4.ihl) + ((bit<32>)hdr.tcp.dataOffset)) * 32w4));
                                    if (payload_size ==0) {
                                        
                                        flow_reg_syn.read(value_aux_syn,0);
                                        flow_reg_ack.read(value_aux_ack,0);
                                        //Clean register
                                        if ((value_aux_syn==1) && (value_aux_ack==1)) {
                                            flow_reg_syn.write((bit<32>)meta.target_host_index,1);
                                            flow_reg_ack.write((bit<32>)meta.target_host_index,0);      
                                        }
                                        flow_reg_syn.read(value_aux_syn,(bit<32>)meta.target_host_index);
                                        flow_reg_ack.read(value_aux_ack,(bit<32>)meta.target_host_index);

                                        do_update_ack_reg();

                                        #ifdef DEBUG
                                            trash_reg_debug.write(0,(bit<128>)meta.rttreg[1:0]);
                                            trash_reg_debug.write(0,(bit<128>)meta.rttreg[129:2]);
                                            trash_reg_debug.write(0,(bit<128>)meta.tcphand_ack);            
                                        #endif

                                        //Updates the RTT value for a flow.
                                        if(meta.rttreg[1:0]==1){
                                            rtt_con_reg1.write((bit<32>)meta.flow_id_bf1, meta.rttreg[129:2]);
                                        } else if (meta.rttreg[1:0]==2){
                                            rtt_con_reg2.write((bit<32>)meta.flow_id_bf2, meta.rttreg[129:2]);   
                                        }
                                        
                                        if (meta.tcphand_ack==1) {  
                                            host_3hand_reg.read(aux_port, (bit<32>)meta.host_port);
                                            if (value_aux_syn - value_aux_ack > (bit<48>)SYN_ACK_THRESHOLD)  {
                                                Alarm_ddos = 1;
                                                if ((aux_port[47:0] - aux_port[143:96]) > (bit<48>)PORT_SYN_ACK_THRESHOLD){
                                                    meta.alarm =1;
                                                }                                                    
                                            }
                                            flow_reg_ack.read(value_aux_ack,(bit<32>)meta.target_host_index);
                                            value_aux_ack = value_aux_ack+1;                                                                    
                                            flow_reg_ack.write((bit<32>)meta.target_host_index, value_aux_ack);
                                            
                                            //Correction of the TCP packet count with the SYN flag, ignoring the last 2 SYN retransmissions in the event of attack identification
                                            flow_reg_syn.read(value_aux_syn,(bit<32>)meta.target_host_index);
                                            
                                            if ((meta.alarm==1) && (Alarm_ddos==1) && (value_aux_syn > ((bit<48>) meta.retransmission_num))){
                                                
                                                #ifdef DEBUG
                                                    trash_reg_debug.write(0,(bit<128>)value_aux_syn); 
                                                    trash_reg_debug.write(0,(bit<128>)meta.retransmission_num);                                           
            
                                                #endif
                                                
                                                value_aux_syn = value_aux_syn - ((bit<48>)meta.retransmission_num) + 1;
                                                flow_reg_syn.write((bit<32>)meta.target_host_index, value_aux_syn);
                                                if (aux_port[143:96]> ((bit<48>) meta.retransmission_num)) {
                                                    
                                                    #ifdef DEBUG
                                                        trash_reg_debug.write(0,(bit<128>) aux_port[143:96]); 
                                                    #endif
                                                    
                                                    aux_port[143:96] = aux_port[143:96]-((bit<48>)meta.retransmission_num);
                                                }
                                            }
                                            
                                            aux_port[143:96] = aux_port[143:96]+1;
                                            aux_port[191:144]= standard_metadata.ingress_global_timestamp;
                                            
                                            #ifdef DEBUG
                                                trash_reg_debug.write(0,(bit<128>) aux_port[143:96]); 
                                            #endif
                                            
                                            host_3hand_reg.write(meta.host_port, aux_port);
                                            bf1_conn_3handshake_reg.read(auux0,(bit<32>)meta.flow_id_bf1);
                                            bf1_conn_3handshake_reg.write((bit<32>)meta.flow_id_bf1,auux0+1);

                                            auux=0;
                                            bf2_conn_3handshake_reg.read(auux,(bit<32>)meta.flow_id_bf2);
                                            bf2_conn_3handshake_reg.write((bit<32>)meta.flow_id_bf2,auux+1);
                                            auux=0;
                                            bf3_conn_3handshake_reg.read(auux,(bit<32>)meta.flow_id_bf3);
                                            bf3_conn_3handshake_reg.write((bit<32>)meta.flow_id_bf3,auux+1);
                                            auux=0;
                                                                                        
                                        }   
                                    } 
                                    meta.forward_packet=1;
                                } else {// not ack
                                    //synACK
                                    if((hdr.tcp.flags_ctrl == 0x12)  && (meta.source_host_hit==1)){ 
                                        meta.forward_packet=1;
                                        do_update_synack_reg();
                                        //Resetting of threshold_24.
                                        flow_reg_syn.read(value_aux_syn,0);
                                        flow_reg_ack.read(value_aux_ack,0);
                                        if ((value_aux_syn==1) && (value_aux_ack==1)) {
                                            flow_reg_syn.write((bit<32>)meta.target_host_index,1);
                                            flow_reg_ack.write((bit<32>)meta.target_host_index,0);   
                                        } 
                                        flow_reg_syn.read(value_aux_syn,(bit<32>)meta.source_host_index);
                                        flow_reg_ack.read(value_aux_ack,(bit<32>)meta.source_host_index);      
                                        
                                    } else { 
                                        if (((hdr.tcp.flags_ctrl == 0x02) && (!(meta.target_host_hit==1))) || ((hdr.tcp.flags_ctrl == 0x12)  && (!(meta.source_host_hit==1))) || ((hdr.tcp.flags_ctrl == 0x10) && (!(meta.target_host_hit==1)))){
                                           meta.forward_packet=1;   
                                        } else {// Other TCP flags, not SYN, SYNACK or ACK
                                            //Resetting of threshold_24.
                                            flow_reg_syn.read(value_aux_syn,0);
                                            flow_reg_ack.read(value_aux_ack,0);
                                            if ((value_aux_syn==1) && (value_aux_ack==1)) {
                                                flow_reg_syn.write((bit<32>)meta.target_host_index,0);
                                                flow_reg_ack.write((bit<32>)meta.target_host_index,0);  
                                            }  
                                            meta.forward_packet=1;
                                        }
                                    }
                                }
                            }     //not syn
                        }else{    //not tcp
                            meta.forward_packet=1;
                        }
                    } else { // from if ((meta.target_host_hit==1)){  
                        meta.forward_packet=1;
                    }  

                    if (meta.forward_packet==1){
                            ipv4_lpm.apply();
                            #ifdef DEBUG
                                loop2_number_debug.write(0,10);
                            #endif
                    } else {
                            drop_table.apply();
                            #ifdef DEBUG
                                loop2_number_debug.write(0,11);
                            #endif
                    }
                } //blacklist

            //Clearing the register 0 again
                flow_reg_syn.write(0,0);
                flow_reg_ack.write(0,0);
            }    

        }else{ //not ipv4
            if (hdr.ethernet.etherType==0x0806){
                    meta.forward_packet=1; 
                    forwarding_arp.apply();
                    #ifdef DEBUG
                        loop2_number_debug.write(0,11);
                    #endif
            }else{
                    meta.forward_packet=1;
            }
        } 
    }  //apply
}     //control


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.icmp);        
    }
}


/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
