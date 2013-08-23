#ifndef NETWORKLAYER_H_
#define NETWORKLAYER_H_
#include <iostream>
#include <iomanip>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <malloc.h>

#define MAX_TTL 256

typedef struct _protocolNo{
	int protNo;
	int frequency;
}ProtocolNo;

typedef struct _ip_src{
	char srcIp[INET_ADDRSTRLEN];
	int frequency;
}SrcIp;

typedef struct _ip_dest{
	char destIp[INET_ADDRSTRLEN];
	int frequency;
}DestIp;

typedef struct _arp{
	int macAddr[ETH_ALEN];
	int ipAddr[4];
}ArpDet;

class NetworkLayer {

public:
	static NetworkLayer* getInstance();
	~NetworkLayer();

	void PrintProtocolList();
	bool CheckAndIncProtcolNo(int protocolNo);
	void AddNewProtocol(int protocolNo);
	void SortProtocolList();

	void PrintIpAddress();
	bool CheckAndIncSrcIp(char* ip);
	bool CheckAndIncDestIp(char* ip);
	void AddNewSrcIp(char* ip);
	void AddNewDestIp(char* ip);
	void SortSrcIp();
	void SortDestIp();

	void PrintTtl();
	void IncTtl(int ttl);

	void PrintArpParticipants();
	bool CheckArpParticipant(const u_int8_t* macAddr,const u_int8_t *ipAddr);
	void AddNewArpParticipant(const u_int8_t* macAddr, const u_int8_t* ipAddr);
	void SortArpParticipants();

	void PrintNwLayerStats();
	void ProcessNWLayer(const struct pcap_pkthdr* hdr,const u_char* packet,int size, int ethernet_type);


private:
	static NetworkLayer* instance;
	NetworkLayer();
	
	ProtocolNo*  mProtArr;
	int mProtArrCount;
	int mProtCount;
	
	SrcIp* mSrcIpArr;
	int mSrcIpArrCount;
	DestIp* mDestIpArr;
	int mDestIpArrCount;
	int mPacketCount;
	
	int mTtlArr[MAX_TTL];

	ArpDet* mArpArr;
	int mArpArrCount;
};

#endif /* NWLAYEROUTPUT_H_ */
