#include <iostream>
#include <pcap/pcap.h>
#include <netinet/ether.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<netinet/ip_icmp.h>
#include<net/ethernet.h>
#include<limits.h>
#include<iomanip>
#include "LinkLayer.h"
#include "NetworkLayer.h"
#include "TransportLayer.h"
#include <time.h>

#ifndef PCAPFILE_H_
#define PCAPFILE_H_

class PcapFile
{
private:
	pcap_t* session_handler;
	LinkLayer* l;
	NetworkLayer* n;
	TransportLayer* t;

	int pktCount;
public:
	PcapFile();
	bool OpenFile(char* filepath);
	void PrintSummary();
	void ProcessFile();
	friend void ProcessFileData(u_char *args, const struct pcap_pkthdr *hdr,const u_char *packet);
	virtual ~PcapFile();

	pcap_t* getSessionHandler() const {
		return session_handler;
	}

	LinkLayer* getLLayer() const {
		return l;
	}

	TransportLayer* getTLayer() const {
			return t;
	}
};

#endif /* PCAPFILE_H_ */
