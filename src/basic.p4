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
register<bit<32>>(1) DoChangeNumber;

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action answer_replica(egressSpec_t port){
        standard_metadata.egress_spec = port;  
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

    action send_probe(egressSpec_t port) {
      standard_metadata.egress_spec = port;
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

    table set_primary {
      key = {
        meta.iterator: exact;
      }
      actions = {
      answer_replica;
      }
      size = 1;
    }

    table send_probe_server {
      key = {
         hdr.gvt.pid: exact;
      }
      actions = {
        send_probe;
      }
      size = 10;     /*each process need one entry*/
    }
    
    apply {
        if(hdr.gvt.isValid()){
          if( hdr.gvt.type == TYPE_FAILURE){
            /*if is a probe message just answer it
            TODO: configuration file*/
            hdr.gvt.type = TYPE_DELFAILURE;  
            send_probe_server.apply();
          }else if ((hdr.gvt.type == TYPE_PROP || hdr.gvt.type == TYPE_PREPARE) && meta.iterator == 0){
            /*if is a server proposal or a prepare message. Both case are equivalent
            but the first is a message recived from servers an the latter, TYPE_PREPARE, is for replicas*/
            GVT.read(meta.currentGVT, 0);
            /*check for conditions to start a new gvt computation*/
            if (meta.currentGVT < hdr.gvt.value) {
                LvtValues.write(hdr.gvt.pid, hdr.gvt.value);
                //trigger metadata to start GVT calculation
                meta.iterator = 1;   
            } else {
              /*If the value is less or equal to the GVT we dont need to check anything, just drop it*/
              drop();
            }
          } else if(hdr.gvt.type == TYPE_REQ){
            //if is a start message, TYPE_REQ  
            start_execution();
          /*if is acknoledgment message from replicas, TYPE_PREPAREOK*/  
          } else if(hdr.gvt.type == TYPE_PREPAREOK){
                RoundControl.read( meta.numPrepareOks, hdr.gvt.round);
                meta.numPrepareOks = meta.numPrepareOks + 1;
                RoundControl.write (hdr.gvt.round, meta.numPrepareOks);
                if(meta.numPrepareOks >= MAJORITY){
                  hdr.gvt.type = TYPE_DEL;
                  GVT.read(hdr.gvt.value, 0);
                  multicast(1);
                }
           } else if(hdr.gvt.type == TYPE_VIEWCHANGE){
               /*TODO: ensure that other start changes does not init while one is active*/
               hdr.gvt.type = TYPE_STARTCHANGE;
               DoChangeNumber.write (0, 0);
               multicast(3);

           } else if (hdr.gvt.type == TYPE_STARTCHANGE){

           } else if(hdr.gvt.type == TYPE_DOCHANGE){
               /*TODO: wait for the maximum and choose the most updated view*/
                DoChangeNumber.read( meta.numDoChanges, 0);
                meta.numPrepareOks = meta.numDoChanges + 1;
                DoChangeNumber.write (0, meta.numDoChanges);
                if(meta.numDoChanges >= MAJORITY){
                  /*TODO: we need to send a startview both for servers and then servers resend old proposals */ 
                  multicast(1);
                  hdr.gvt.type = TYPE_STARTVIEW;
                }
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
                    if (hdr.gvt.type == TYPE_PREPARE){
                      hdr.gvt.type = TYPE_PREPAREOK;
                      set_primary.apply();
                    } else { 
                        /*the other case is the hdr.gvt.value is propose*/
                        /*append round number to the header and reset the history of PREPAREOKS*/
                        RoundNumber.read(meta.currentRound, 0);
                        RoundNumber.write(0, meta.currentRound + 1);
                        hdr.gvt.round = meta.currentRound + 1;
                        hdr.gvt.type = TYPE_PREPARE;
                        /*send for replicas*/
                        multicast(2); 
                    }
              } else {
                resubmit(meta); 
              }
          }
        }
        /*TODO: deliver packet to end host */
        /*
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }*/
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