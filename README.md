
# Implementing GVT computation

This is a implementation of GVT computation using a p4 switch. (based on P4 tutorials)


## Introduction

The objective of this work is to write a P4 program and server functions
to compute and report the global virtual time (gvt) value.

With gvt computation, the switch must perform the following actions:
(1) receive computation requests from a gvt controller and reset variables,
(2) broadcast the request to processes running on servers, (3) receive proposals from 
processes and update the switch vision of the gvt value, and (4) forward the 
selected value out to an appropriate port to be sent for a controller.

Beyond that, the switch will have to handle ipv4 forwarding between processes runnig on servers.
The control plane of the switch is responsible for configuring output ports for multicasting
and the number of processes in the computation. Processes are identified by their unique ID and 
we should use that to map its lvt vision inside the switch. 

We will use only one switch for an initial implementation. Our P4 program will be written for 
the V1Model architecture implemented on P4.org's bmv2 software switch. 

