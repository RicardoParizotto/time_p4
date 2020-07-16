#include <core.p4>
#include <v1model.p4>
#include "include/headers.p4"
#include "include/parser.p4"


register<bit<32>>(TOTAL_NUMBER_OF_PROCESSES) LvtValues;
register<bit<32>>(1) GVT;
register<bit<32>>(1) PrepareOk;
register<bit<32>>(1) RoundNumber;
register<bit<32>>(1000) RoundControl;
register<egressSpec_t>(1) primary_port;

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action answer_replica(){
        primary_port.read(meta.out_aux, 0);
        standard_metadata.egress_spec = meta.out_aux;  
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action start_execution(){
      GVT.write(0, 0);
      LvtValues.write(0, 0);
      LvtValues.write(1, 0);
      PrepareOk.write(0, 0);
      RoundNumber.write(0, 0);
    }

    action multicast(bit<32> grp_id) {
        standard_metadata.mcast_grp = (bit<16>) grp_id;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    apply {
        if(hdr.gvt.isValid()){

            if((hdr.gvt.type == TYPE_PROP || hdr.gvt.type == TYPE_PREPARE) && meta.iterator == 0){
	            GVT.read(meta.currentGVT, 0);

           		/*check for conditions to start a new gvt computation*/
           		if(meta.currentGVT < hdr.gvt.value){
                	LvtValues.write(hdr.gvt.pid, hdr.gvt.value);
                	//trigger metadata to start GVT calculation
               		meta.iterator = 1;   
            	}else{
                	/*If the value is less or equal to the GVT
                	we dont need to check anything, just drop it*/
                	drop();
            	}

        	} else if(hdr.gvt.type == TYPE_REQ){
            	start_execution();
        	}

        	/*this condition is to start the GVT computation*/ 
        	if(meta.iterator > 0 ){ 
            	
				/*if is the first iteration*/
	            if(meta.iterator == 1){
	              LvtValues.read(meta.minLVT, 0); 
	              GVT.read(meta.currentGVT, 0);     
	            }

	            /*note that we do not consider 
	            a scenario with zero processes */

	            LvtValues.read(meta.readedValue, meta.iterator);
	            
	            /*selecting the less gvt time*/
	            if(meta.readedValue < meta.minLVT){
	              meta.minLVT = meta.readedValue;
	            }

	            /*iterates through the register array*/
	            meta.iterator = meta.iterator + 1;

	            /*if it is the last iteration*/
	            if(meta.iterator == TOTAL_NUMBER_OF_PROCESSES){

                    /*update GVT and multicast the new value for replicas*/
                    GVT.write(0, meta.minLVT);
                    hdr.gvt.type = TYPE_DEL;

                    if (hdr.gvt.type == TYPE_PREPARE){
                    	hdr.gvt.type = TYPE_PREPAREOK;
                    	answer_replica();
                    } else {
                        /*the other case is the hdr.gvt.value is propose*/
                    	hdr.gvt.type = TYPE_PREPAREOK;
                    	multicast(1); 
                    }
            	} else {
                	resubmit(meta); 
            	}
       		} 
            if(hdr.gvt.type == TYPE_PREPAREOK){
                RoundControl.read( meta.numPrepareOks, hdr.gvt.round);
                meta.numPrepareOks = meta.numPrepareOks + 1;
                RoundControl.write (hdr.gvt.round, meta.numPrepareOks);
         	    if(meta.numPrepareOks >= MAJORITY){
         	    	hdr.gvt.type = TYPE_DEL;
         	    	GVT.read(hdr.gvt.value, 0);
         	   	    multicast(2);
         	    }
            }
        }

        /*TODO: deliver packet to end host */
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {    } 
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
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

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;