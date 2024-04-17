/* -*- P4_16 -*- */

/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) Intel Corporation
 * SPDX-License-Identifier: CC-BY-ND-4.0
 */



#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "headers_l2.p4"
#include "util.p4"


#define PORT 8000
#define SSP_ACTION_READ 0
#define SSP_ACTION_INC 1
#define SSP_ACTION_CLOCK 2
#define TYPE_FAILURE 3
#define TYPE_DELFAILURE 4

//#define SYNC 1
//#define ASYNC 1
#define HYBRID

#define MAX_WORKERS 2
#define MAX_WORKERS_BITMASK 3    //this one is when the slot is all 1111
#define BUFFER_SIZE 2
#define AGGR_ROWS 2485
//#define AGGR_ROWS 310
#define VALUES_PER_ROW 32
//#define VALUES_PER_COL 310
#define VALUES_PER_COL 2485


struct metadata_t {
    bit<32> it;  // metadata example
    bit<32> fail;
    bit<MAX_WORKERS> bitmask;
    bit<MAX_WORKERS> buffer_slot;
    bit<16> low_clock_meta;
    bit<16> high_clock_meta;
    bit<16> training_window;
    bit<MAX_WORKERS> slot_or_bitmask_meta;
    bit<16> negative_check;   //this will save a variable that i need to check if it is negative
    bit<16> diff_for_negative_check;
    bit<16> flushqueue;
}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;
    Checksum() ipv4_checksum;
    
    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        ig_md.it = 0;
        transition parse_ethernet;
    }
 
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : reject;
        }
    }
    
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);    
        ipv4_checksum.add(hdr.ipv4);
        transition parse_udp;
    }    
    
    
    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dst_port) {
            PORT: parse_ssp;
            default: accept;
        }
    }    
    
    state parse_ssp {
        pkt.extract(hdr.ssp);
        transition select(hdr.ssp.actionCode) {
            SSP_ACTION_INC: parse_data;
            default: accept;
        }
    }

    state parse_data {
        pkt.extract(hdr.data);
        transition accept;
    }

}


Register<bit<32>, _>(VALUES_PER_COL) ssp_column_00;
Register<bit<32>, _>(VALUES_PER_COL) ssp_column_01;
Register<bit<32>, _>(VALUES_PER_COL) ssp_column_02;
Register<bit<32>, _>(VALUES_PER_COL) ssp_column_03;
Register<bit<32>, _>(VALUES_PER_COL) ssp_column_04;
Register<bit<32>, _>(VALUES_PER_COL) ssp_column_05;
Register<bit<32>, _>(VALUES_PER_COL) ssp_column_06;
Register<bit<32>, _>(VALUES_PER_COL) ssp_column_07;
Register<bit<32>, _>(VALUES_PER_COL) ssp_column_08;
Register<bit<32>, _>(VALUES_PER_COL) ssp_column_09;
Register<bit<32>, _>(VALUES_PER_COL) ssp_column_10;
Register<bit<32>, _>(VALUES_PER_COL) ssp_column_11;
Register<bit<32>, _>(VALUES_PER_COL) ssp_column_12;
Register<bit<32>, _>(VALUES_PER_COL) ssp_column_13;
Register<bit<32>, _>(VALUES_PER_COL) ssp_column_14;
Register<bit<32>, _>(VALUES_PER_COL) ssp_column_15;

Register<bit<32>, _>(VALUES_PER_COL) ssp_column_16;
Register<bit<32>, _>(VALUES_PER_COL) ssp_column_17;
Register<bit<32>, _>(VALUES_PER_COL) ssp_column_18;
Register<bit<32>, _>(VALUES_PER_COL) ssp_column_19;
Register<bit<32>, _>(VALUES_PER_COL) ssp_column_20;
Register<bit<32>, _>(VALUES_PER_COL) ssp_column_21;
Register<bit<32>, _>(VALUES_PER_COL) ssp_column_22;
Register<bit<32>, _>(VALUES_PER_COL) ssp_column_23;
Register<bit<32>, _>(VALUES_PER_COL) ssp_column_24;

Register<bit<32>, _>(VALUES_PER_COL) ssp_column_25;
Register<bit<32>, _>(VALUES_PER_COL) ssp_column_26;
Register<bit<32>, _>(VALUES_PER_COL) ssp_column_27;
Register<bit<32>, _>(VALUES_PER_COL) ssp_column_28;
Register<bit<32>, _>(VALUES_PER_COL) ssp_column_29;
Register<bit<32>, _>(VALUES_PER_COL) ssp_column_30;
Register<bit<32>, _>(VALUES_PER_COL) ssp_column_31;

Register<bit<32>, _>(1) clock_counter;
Register<bit<MAX_WORKERS>, _>(BUFFER_SIZE) ring_buffer;
Register<bit<16>, _>(1) low_clock;
Register<bit<16>, _>(1) high_clock;
Register<bit<16>, _>(1) window_size;
Register<bit<16>, _>(1) window_copy;

Register<bit<16>, _>(1) compare_clocks;
Register<bit<16>, _>(1) compare_clocks_2;


Register<bit<32>, _>(1) reading;
Register<bit<32>, _>(1) writing;
Register<bit<32>, _>(1) iter;
Register<bit<32>, _>(1) debug_worker;
Register<bit<32>, _>(1) debug_worker1;
Register<bit<16>, _>(1) debug_worker2;


Register<bit<32>, _>(1) sim_failure;


// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {



    Checksum() ipv4_checksum;
    apply {
       if(hdr.ipv4.isValid()){
        hdr.ipv4.hdr_checksum = ipv4_checksum.update(
            {hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.total_len,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.frag_offset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr});}
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.ssp);
        pkt.emit(hdr.data);
    }
}

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {


    #include "aggregation.p4"

    RegisterAction<bit<32>, _, bit<32>>(sim_failure) read_sim_failure = {
    void apply(inout bit<32> value, out bit<32> rv) {
            rv = value;
        }
    };
    
    RegisterAction<bit<32>, _, bit<32>>(debug_worker) debug = {
    void apply(inout bit<32> value){
        value = 1;     
    }    
    };

    RegisterAction<bit<32>, _, bit<32>>(debug_worker1) debug1 = {
    void apply(inout bit<32> value){
        value = 1;
    }
    };

    RegisterAction<bit<16>, _, bit<16>>(debug_worker2) debug2 = {
    void apply(inout bit<16> value){
        value = hdr.ssp.workerId;
    }
    };
    
     
    RegisterAction<bit<32>, _, bit<32>>(reading) read_counter = {
    void apply(inout bit<32> value, out bit<32> rv){
    	    value = value + 1;
    }
    };
    
    
    RegisterAction<bit<32>, _, bit<32>>(writing) write_counter = {
    void apply(inout bit<32> value, out bit<32> rv){
    	    value = value + 1;
    }
    };

    RegisterAction<bit<32>, _, bit<32>>(ring_buffer) write_buffer = {
    void apply(inout bit<32> value, out bit<32> rv){
            if(value == BUFFER_SIZE - 1) value = 0;
	    else value = value + 1;
            rv = value;
    }
    };
    
   
    action bounce_pkt(){
        ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
        //standard_metadata.egress_spec = standard_metadata.ingress_port;

        bit<48> tmpEth = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = hdr.ethernet.src_addr;
        hdr.ethernet.src_addr = tmpEth;

        bit<32> tmpIp = hdr.ipv4.dst_addr;
        hdr.ipv4.dst_addr = hdr.ipv4.src_addr;
        hdr.ipv4.src_addr = tmpIp;

        bit<16> tmpPort = hdr.udp.dst_port;
        hdr.udp.dst_port = hdr.udp.src_port;
        hdr.udp.src_port = tmpPort;    
    }

    action drop_() {
        ig_intr_dprsr_md.drop_ctl = 0;
    }
    action ipv4_forward(PortId_t port, mac_addr_t dst_mac) {
        ig_intr_tm_md.ucast_egress_port = port;
        hdr.ethernet.dst_addr = dst_mac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }


    //clock counter is the ring buffer.
    RegisterAction<bit<MAX_WORKERS>, _, bit<MAX_WORKERS>>(clock_counter) update_clock_counter = {
    void apply(inout bit<MAX_WORKERS> value, out bit<MAX_WORKERS> rv){
            //if all workers already passed this iteration, reset the slot
            if(value == MAX_WORKERS_BITMASK)
                value = ig_md.bitmask;
            else
                value = value | ig_md.bitmask;
	    rv = value;
    }
    };

   RegisterAction<bit<16>, _, bit<16>>(window_size) action_compare_window = {
    void apply(inout bit<16> value, out bit<16> rv){
             if(ig_md.diff_for_negative_check > value)
                 rv = 1;          //enqueue and drop  
             else
                 rv = 0;          //volta
    }
    };

   RegisterAction<bit<16>, _, bit<16>>(window_copy) action_compare_window_copy = {
    void apply(inout bit<16> value, out bit<16> rv){
             if(ig_md.diff_for_negative_check > value)
                 rv = 0;          //set meta flush to 1
             else
                 rv = 1;          //set meta flush to 0
    }
    };

/*
   RegisterAction<bit<16>, _, bit<16>>(compare_clocks_2) action_compare_clocks_2 = {
    void apply(inout bit<16> value, out bit<16> rv){
             rv = diff_clock_bariers | ((bit<16>) 32767);	
    }
    };*/
    
   RegisterAction<bit<16>, _, bit<16>>(low_clock) update_low_clock = {
    void apply(inout bit<16> value, out bit<16> rv){
                 value = hdr.ssp.workerClock;	
    }
    };
    
   RegisterAction<bit<16>, _, bit<16>>(high_clock) update_high_clock = {
    void apply(inout bit<16> value, out bit<16> rv){
                 if(hdr.ssp.workerClock > value){
                      value = hdr.ssp.workerClock;
                 }
          rv = value;
    }
    };

    action set_bitmask(bit<MAX_WORKERS> value){
        ig_md.bitmask = value;    //1 --- 1, 2 --- 2, 3 --- 4, 4 --- 8
    }

    action set_window(bit<16> window){
        ig_md.training_window = window;
    }
 

    //maps ID to an integer in which the only the IDth element is 
    table map_worker_bitmask {
        key = {
            hdr.ssp.workerId:exact;
        }
	actions = {
	    set_bitmask;
        }
    }

    action set_flushqueue(){
        ig_md.flushqueue = 1;
        ig_intr_tm_md.mcast_grp_a =  1;
    }

    table table_check_negative {
        key = {
            ig_md.negative_check:exact;  //65535 magical value - if it matches it is a negative number: clock is outside window. Drop packet
        }
        actions = {
             drop_;
        }
    }

    table table_check_negative_2 {
        key = {
            ig_md.negative_check:exact;  //65535 magical value - if it matches it is a negative number: clock is outside window. Drop packet
        }
        actions = {
             set_flushqueue;
             drop_;
        }
    }

    table set_window_table {
        key = {}
        actions = {set_window;}
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dst_addr: exact;
        }
        actions = { 
            ipv4_forward;
            drop_;
        }
        size = 1024;
        default_action = drop_();
    }

    

    apply {

	if(hdr.ssp.isValid()){
                if(hdr.ssp.actionCode == TYPE_FAILURE){                      /*if is a probe message just answer it */
                    hdr.ssp.actionCode = TYPE_DELFAILURE;
                    bounce_pkt();
                }
                //debug2.execute(0); 
	        //checa se e uma acao que incrementa
	        else if(hdr.ssp.actionCode == SSP_ACTION_INC){
	             aggregate_column_00.execute(hdr.ssp.gradSegment);   //ssp.gradSegment = linhaaa Ricardo
                     aggregate_column_01.execute(hdr.ssp.gradSegment);
                     aggregate_column_02.execute(hdr.ssp.gradSegment);   
                     aggregate_column_03.execute(hdr.ssp.gradSegment);
                     aggregate_column_04.execute(hdr.ssp.gradSegment);                       
                     aggregate_column_05.execute(hdr.ssp.gradSegment);
                     aggregate_column_06.execute(hdr.ssp.gradSegment);    
                     aggregate_column_07.execute(hdr.ssp.gradSegment);
                     aggregate_column_08.execute(hdr.ssp.gradSegment);
                     aggregate_column_09.execute(hdr.ssp.gradSegment);                                                                  
                     aggregate_column_10.execute(hdr.ssp.gradSegment);  
                     aggregate_column_11.execute(hdr.ssp.gradSegment);
                     aggregate_column_12.execute(hdr.ssp.gradSegment);  
                     aggregate_column_13.execute(hdr.ssp.gradSegment);
                     aggregate_column_14.execute(hdr.ssp.gradSegment);
                     aggregate_column_15.execute(hdr.ssp.gradSegment);
                     aggregate_column_16.execute(hdr.ssp.gradSegment);
                     aggregate_column_17.execute(hdr.ssp.gradSegment);
                     aggregate_column_18.execute(hdr.ssp.gradSegment);
                     aggregate_column_19.execute(hdr.ssp.gradSegment);
                     aggregate_column_20.execute(hdr.ssp.gradSegment);
                     aggregate_column_21.execute(hdr.ssp.gradSegment);
                     aggregate_column_22.execute(hdr.ssp.gradSegment);
                     aggregate_column_23.execute(hdr.ssp.gradSegment);
                     aggregate_column_24.execute(hdr.ssp.gradSegment);
                     aggregate_column_25.execute(hdr.ssp.gradSegment);
                     aggregate_column_26.execute(hdr.ssp.gradSegment);
                     aggregate_column_27.execute(hdr.ssp.gradSegment);
                     aggregate_column_28.execute(hdr.ssp.gradSegment);               
                     aggregate_column_29.execute(hdr.ssp.gradSegment);
                     aggregate_column_30.execute(hdr.ssp.gradSegment);                   
                     aggregate_column_31.execute(hdr.ssp.gradSegment);
                     write_counter.execute(0);    
	        } else if (hdr.ssp.actionCode == SSP_ACTION_READ){
                    hdr.data.setValid();
	            hdr.data.value00 = read_column_00.execute(hdr.ssp.gradSegment);
	            hdr.data.value01 = read_column_01.execute(hdr.ssp.gradSegment);
	            hdr.data.value02 = read_column_02.execute(hdr.ssp.gradSegment);
	            hdr.data.value03 = read_column_03.execute(hdr.ssp.gradSegment);
	            hdr.data.value04 = read_column_04.execute(hdr.ssp.gradSegment);
	            hdr.data.value05 = read_column_05.execute(hdr.ssp.gradSegment);
	            hdr.data.value06 = read_column_06.execute(hdr.ssp.gradSegment);
	            hdr.data.value07 = read_column_07.execute(hdr.ssp.gradSegment);
	            hdr.data.value08 = read_column_08.execute(hdr.ssp.gradSegment);
	            hdr.data.value09 = read_column_09.execute(hdr.ssp.gradSegment);
	            hdr.data.value10 = read_column_10.execute(hdr.ssp.gradSegment);
	            hdr.data.value11 = read_column_11.execute(hdr.ssp.gradSegment);
	            hdr.data.value12 = read_column_12.execute(hdr.ssp.gradSegment);
	            hdr.data.value13 = read_column_13.execute(hdr.ssp.gradSegment);
	            hdr.data.value14 = read_column_14.execute(hdr.ssp.gradSegment);
	            hdr.data.value15 = read_column_15.execute(hdr.ssp.gradSegment);
	            hdr.data.value16 = read_column_16.execute(hdr.ssp.gradSegment);
	            hdr.data.value17 = read_column_17.execute(hdr.ssp.gradSegment);
	            hdr.data.value18 = read_column_18.execute(hdr.ssp.gradSegment);
	            hdr.data.value19 = read_column_19.execute(hdr.ssp.gradSegment);
	            hdr.data.value20 = read_column_20.execute(hdr.ssp.gradSegment);
	            hdr.data.value21 = read_column_21.execute(hdr.ssp.gradSegment);
	            hdr.data.value22 = read_column_22.execute(hdr.ssp.gradSegment);
	            hdr.data.value23 = read_column_23.execute(hdr.ssp.gradSegment);
	            hdr.data.value24 = read_column_24.execute(hdr.ssp.gradSegment);
	            hdr.data.value25 = read_column_25.execute(hdr.ssp.gradSegment);
	            hdr.data.value26 = read_column_26.execute(hdr.ssp.gradSegment);
	            hdr.data.value27 = read_column_27.execute(hdr.ssp.gradSegment);
	            hdr.data.value28 = read_column_28.execute(hdr.ssp.gradSegment);
	            hdr.data.value29 = read_column_29.execute(hdr.ssp.gradSegment);
	            hdr.data.value30 = read_column_30.execute(hdr.ssp.gradSegment);
	            hdr.data.value31 = read_column_31.execute(hdr.ssp.gradSegment);	   
	            bounce_pkt();
	            read_counter.execute(0);         	      	            
	        }else if (hdr.ssp.actionCode == SSP_ACTION_CLOCK){
	            #ifdef HYBRID
                    bit<32> update_slot = (bit<32>) hdr.ssp.workerClock & (BUFFER_SIZE - 1);
                    map_worker_bitmask.apply();
		    ig_md.buffer_slot = update_clock_counter.execute(update_slot);

                    //in case all the workers completed the slot-th iteration
                    if(ig_md.buffer_slot == MAX_WORKERS_BITMASK){
                        ig_md.low_clock_meta = update_low_clock.execute(0);
                    }else{
			ig_md.high_clock_meta = update_high_clock.execute(0);
                    }

                    //set flushqueue in case there was an update in the low clock
                    if(ig_md.buffer_slot == MAX_WORKERS_BITMASK){
                        ig_md.diff_for_negative_check = ig_md.high_clock_meta - ig_md.low_clock_meta;
                        ig_md.flushqueue = action_compare_window_copy.execute(0);
                    }

                    ig_md.diff_for_negative_check  = (bit<16>) hdr.ssp.workerClock - ig_md.low_clock_meta;

                    ig_md.diff_for_negative_check = action_compare_window.execute(0);

                    if(ig_md.diff_for_negative_check == (bit<16>)1)
                        drop_();  //TODO: enqueue
                    else
                        bounce_pkt();

                    #endif
	            #ifdef SYNC
                    ig_md.it = update_clock_counter.execute(0);
	            if (ig_md.it == 0){
	            	ig_intr_tm_md.mcast_grp_a =  1; //multicast to group1
	            }else{ 
	                drop_();
	            }
		    #endif
		    #ifdef ASYNC
		    ig_intr_tm_md.mcast_grp_a =  1; //multicast to group1
                    #endif	
	        } 
                //ends aggregation
	}else{
            if(hdr.ipv4.isValid()){
                ipv4_lpm.apply();
            }   
        }
	ig_md.fail = read_sim_failure.execute(0);
        if(ig_md.fail == 1){drop_();}

	//bit<32> workerMask = (bit<32>)1 << hdr.ssp.workerId;
        ig_intr_tm_md.bypass_egress = 1w1;
    }
}



Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         EmptyEgressParser(),
         EmptyEgress(),
         EmptyEgressDeparser()) pipe;

Switch(pipe) main;
