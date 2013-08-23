#include "NetworkLayer.h"
using namespace std;

#define ZERO 0
#define MAX_PROTOCOL_NO 256
#define IP_LEN 4
#define PROTOCOL_NO 0x0600

NetworkLayer* NetworkLayer::instance;

NetworkLayer* NetworkLayer::getInstance() {
	if (instance == NULL) {
		instance = new NetworkLayer();
		return instance;
	} else {
		return instance;
	}
}

NetworkLayer::NetworkLayer() {
	mProtArrCount = 0;
	mProtCount = 0;
	mSrcIpArrCount = 0;
	mDestIpArrCount = 0;
	mPacketCount = 0;

	for (int idx=0;idx<MAX_PROTOCOL_NO; idx++) {
		mTtlArr[idx] = 0;
	}

	mArpArrCount = 0;
}


NetworkLayer::~NetworkLayer(){
	if (mProtArr != NULL) {
		delete mProtArr;
	}

	if(mSrcIpArr != NULL) {
		delete mSrcIpArr;
	}

	if(mDestIpArr != NULL) {
		delete mDestIpArr;
	}

	if(mArpArr != NULL) {
		delete mArpArr;
	}

}


/* Function that prints the list of Protocols */
void NetworkLayer::PrintProtocolList() {
	cout<<endl<<endl<<"==== Network Layer ===="<<endl<<endl;
	cout<<"---- Network Layer Protocols ----"<<endl;
	if(mProtArrCount == ZERO) {
		cout<<"(no results)"<<endl;
		return;
	}

	for (int idx=0;idx<mProtArrCount;idx++) {
		if(!(mProtArr[idx].protNo == ETHERTYPE_IP || mProtArr[idx].protNo == ETHERTYPE_ARP)) {

			if(mProtArr[idx].protNo < PROTOCOL_NO) {
				cout<<setw(20)<<"length = 0x"<<setfill('0')<<setw(4)<<hex<<mProtArr[idx].protNo<<setfill(' ');
			}
			else {
				cout<<setw(20)<<"0x"<<setfill('0')<<setw(4)<<hex<<mProtArr[idx].protNo<<setfill(' ');
			}
			cout<<"\t"<<dec<<setw(15)<<mProtArr[idx].frequency;
			cout<<"\t"<<setw(10)<<fixed<<setprecision(2)<<(((float)mProtArr[idx].frequency)/mProtCount)*100<<"%"<<endl;
		}
	}

	for (int idx=0;idx<mProtArrCount;idx++) {
			if (mProtArr[idx].protNo == ETHERTYPE_ARP) {
				cout<<setw(25)<<"ARP\t"<<dec<<setw(15)<<mProtArr[idx].frequency;
				cout<<"\t"<<setw(10)<<fixed<<setprecision(2)<<(((float)mProtArr[idx].frequency)/mProtCount)*100<<"%"<<endl;
			}
	}

	for (int idx=0;idx<mProtArrCount;idx++) {
		if(mProtArr[idx].protNo == ETHERTYPE_IP) {
			cout<<setw(25)<<"IP\t"<<dec<<setw(15)<<mProtArr[idx].frequency;
			cout<<"\t"<<setw(10)<<fixed<<setprecision(2)<<(((float)mProtArr[idx].frequency)/mProtCount)*100<<"%"<<endl;
		}
	}

	cout<<endl;
}

/* Function that checks if a protocol is present in the list and increments it
 * If the protocol isn't present, it returns false*/
bool NetworkLayer::CheckAndIncProtcolNo(int protocolNo) {
	for(int idx=0;idx<mProtArrCount;idx++) {
		if(mProtArr[idx].protNo == protocolNo) {
			mProtArr[idx].frequency++;
			return true;
		}
	}
	return false;
}

/* Function that adds a new protocol to the list */
void NetworkLayer::AddNewProtocol(int protocolNo) {
	if(mProtArrCount == ZERO) {
		mProtArr = (ProtocolNo*)malloc(sizeof(ProtocolNo));
		mProtArr[mProtArrCount].protNo = protocolNo;
		mProtArr[mProtArrCount].frequency = 1;
		mProtArrCount = 1;
	}
	else {
		mProtArrCount++;
		ProtocolNo* temp = (ProtocolNo*)realloc(mProtArr,mProtArrCount*sizeof(ProtocolNo));
		mProtArr = temp;
		mProtArr[mProtArrCount-1].protNo = protocolNo;
		mProtArr[mProtArrCount-1].frequency = 1;
	}
}

/* Function that sorts the Protocol List */
void NetworkLayer::SortProtocolList() {
	bool swap=true;
	while(swap) {
		swap=false;
		for (int idx=1;idx<mProtArrCount;idx++) {
			if(mProtArr[idx-1].protNo > mProtArr[idx].protNo) {
				ProtocolNo temp = mProtArr[idx-1];
				mProtArr[idx-1]= mProtArr[idx];
				mProtArr[idx] = temp;
				swap =true;
			}
		}
	}
}

/* Function that prints the Ip addresses */
void NetworkLayer::PrintIpAddress() {
	cout<<"\n---- Source IP Addresses ----"<<endl<<endl;
	if(mSrcIpArrCount == ZERO) {
		cout<<"(no results)"<<endl;
		return;
	}
	for (int idx=0; idx<mSrcIpArrCount; idx++) {
		cout<<mSrcIpArr[idx].srcIp<<"\t";
		cout<<setw(10)<<mSrcIpArr[idx].frequency<<"\t";
		cout<<setw(6)<<fixed<<setprecision(2)<<(((float) mSrcIpArr[idx].frequency)/mPacketCount)*100<<"%"<<endl;
	}

	cout<<"\n\n---- Dest IP Addresses ----"<<endl<<endl;
	if(mDestIpArrCount == ZERO) {
		cout<<"(no results)"<<endl;
		return;
	}
	for (int idx=0; idx<mDestIpArrCount; idx++) {
		cout<<mDestIpArr[idx].destIp<<"\t";
		cout<<setw(10)<<mDestIpArr[idx].frequency<<"\t";
		cout<<setw(6)<<fixed<<setprecision(2)<<(((float) mDestIpArr[idx].frequency)/mPacketCount)*100<<"%"<<endl;

	}
	cout<<endl;
}

/*Function that checks if a source Ip is present in the list and increments it
  If the Ip isn't present, it returns false*/
bool NetworkLayer::CheckAndIncSrcIp(char* ip) {
	for (int idx=ZERO;idx<mSrcIpArrCount; idx++) {
		if(strcmp(mSrcIpArr[idx].srcIp,ip) == 0) {
			mSrcIpArr[idx].frequency++;
			return true;
		}
	}
	return false;
}

/* Function that checks if a dest Ip is present in the list and increments it
   If the Ip isn't present, it returns false*/
bool NetworkLayer::CheckAndIncDestIp(char* ip) {
	for (int idx=ZERO;idx<mDestIpArrCount; idx++) {
		if(strcmp(mDestIpArr[idx].destIp,ip) == ZERO) {
			mDestIpArr[idx].frequency++;
			return true;
		}
	}
	return false;
}

/* Function that adds a new source ip to the list */
void NetworkLayer::AddNewSrcIp(char* ip) {
	if (mSrcIpArrCount == ZERO) {
		mSrcIpArr = (SrcIp*)malloc(sizeof(SrcIp));
		strcpy(mSrcIpArr[mSrcIpArrCount].srcIp,ip);
		mSrcIpArr[mSrcIpArrCount].frequency = 1;
		mSrcIpArrCount++;
	}
	else {
		mSrcIpArrCount++;
		SrcIp* temp = (SrcIp*)realloc(mSrcIpArr,mSrcIpArrCount*sizeof(SrcIp));
		mSrcIpArr = temp;
		strcpy(mSrcIpArr[mSrcIpArrCount-1].srcIp,ip);
		mSrcIpArr[mSrcIpArrCount-1].frequency = 1;
	}
}

/* Function that adds a new dest ip to the list */
void NetworkLayer::AddNewDestIp(char* ip) {
	if (mDestIpArrCount == ZERO) {
		mDestIpArr = (DestIp*)malloc(sizeof(DestIp));
		strcpy(mDestIpArr[mDestIpArrCount].destIp,ip);
		mDestIpArr[mDestIpArrCount].frequency = 1;
		mDestIpArrCount++;
	}
	else {
		mDestIpArrCount++;
		DestIp* temp = (DestIp*)realloc(mDestIpArr,mDestIpArrCount*sizeof(DestIp));
		mDestIpArr = temp;
		strcpy(mDestIpArr[mDestIpArrCount-1].destIp,ip);
		mDestIpArr[mDestIpArrCount-1].frequency = 1;
	}
}

/* Function that sorts the Source Ip List */
void NetworkLayer::SortSrcIp() {
	bool swap=true;
	while(swap) {
		swap=false;
		for (int idx=1;idx<mSrcIpArrCount;idx++) {
			if(ntohl(inet_addr(mSrcIpArr[idx-1].srcIp)) > ntohl(inet_addr(mSrcIpArr[idx].srcIp))) {
				SrcIp temp = mSrcIpArr[idx-1];
				mSrcIpArr[idx-1]= mSrcIpArr[idx];
				mSrcIpArr[idx] = temp;
				swap =true;
			}
		}
	}
}

/* Function that sorts the Dest Ip List */
void NetworkLayer::SortDestIp() {
	bool swap=true;
	while(swap) {
		swap=false;
		for (int idx=1;idx<mDestIpArrCount;idx++) {
			if(ntohl(inet_addr(mDestIpArr[idx-1].destIp)) > ntohl(inet_addr(mDestIpArr[idx].destIp))) {
				DestIp temp = mDestIpArr[idx-1];
				mDestIpArr[idx-1]= mDestIpArr[idx];
				mDestIpArr[idx] = temp;
				swap =true;
			}
		}
	}
}

/* Function that prints the list of Ttls */
void NetworkLayer::PrintTtl() {
	cout<<"\n---- Ttl ----"<<endl;
	bool foundTtl = false;
	for (int idx=0;idx<MAX_PROTOCOL_NO;idx++) {
		if(mTtlArr[idx] !=0) {
			foundTtl = true;
			cout<<"\t\t"<<setw(4)<<idx;
			cout<<"\t"<<setw(10)<<mTtlArr[idx];
			cout<<"\t"<<setw(6)<<fixed<<setprecision(2)<<(((float)mTtlArr[idx])/mPacketCount)*100<<"%"<<endl;
		}

	}
	if (!foundTtl) {
		cout<<"(no results)"<<endl;
	}
	cout<<endl;
}

/* Function that increments the frequency of a Ttl */
void NetworkLayer::IncTtl(int ttl) {
	for(int idx=0; idx<MAX_PROTOCOL_NO;idx++) {
		if(idx == ttl) {
			mTtlArr[idx]++;
		}
	}
}

/* Function that prints the list of ARP participants */
void NetworkLayer::PrintArpParticipants() {
	cout<<"\n---- Unique ARP participants ----"<<endl<<endl;
	if(mArpArrCount == ZERO) {
		cout<<"(no results)"<<endl;
		return;
	}

	for(int idx=0;idx<mArpArrCount;idx++) {
		for(int idx1=0;idx1<ETH_ALEN;idx1++) {
			cout<<hex<<setfill('0')<<setw(2)<<mArpArr[idx].macAddr[idx1]<<setfill(' ');
			if(idx1!=(ETH_ALEN-1)) {
				cout<<":";
			}
		}
		cout<<" / ";
		for (int idx1=0;idx1<IP_LEN;idx1++) {
			cout<<dec<<mArpArr[idx].ipAddr[idx1];
			if(idx1!=(IP_LEN-1)) {
				cout<<".";
			}
		}
		cout<<"\n";
	}
	cout<<endl;
}

/* Function that checks whether a combination of ARP participant are present in the list
   and increments the frequency. If it isn't present the function returns false */
bool NetworkLayer::CheckArpParticipant(const u_int8_t* macAddr,const u_int8_t *ipAddr) {
	bool uniqueCbnFound = false;

	for(int idx=0;idx<mArpArrCount;idx++) {
		bool macAddrMatch = true;
		bool ipAddrMatch = true;

		for(int idx1=0;idx1<ETH_ALEN;idx1++) {
			if(mArpArr[idx].macAddr[idx1] != (int)macAddr[idx1]) {
				macAddrMatch = false;
				break;
			}
		}

		for (int idx1=0;idx1<IP_LEN;idx1++) {
			if(mArpArr[idx].ipAddr[idx1] != (int)ipAddr[idx1]) {
				ipAddrMatch = false;
				break;
			}
		}

		if(macAddrMatch && ipAddrMatch) {
			uniqueCbnFound = true;
		}
	}

	if (uniqueCbnFound) {
		return true;
	} else {
		return false;
	}
}

/* Function that adds a new Arp Participant to the list */
void NetworkLayer::AddNewArpParticipant(const u_int8_t* macAddr,const u_int8_t* ipAddr) {
	bool bAddr = true;
	for (int idx=0;idx<ETH_ALEN;idx++) {
		if((int)macAddr[idx] != ZERO){
			bAddr = false;
		}
	}

	if(bAddr) {
		return;
	}

	bAddr = true;
	for (int idx=0;idx<ETH_ALEN;idx++) {
		if((int)macAddr[idx] != 255){
			bAddr = false;
		}
	}

	if(bAddr) {
		return;
	}



	if (mArpArrCount == ZERO) {
		mArpArr = (ArpDet*)malloc(sizeof(ArpDet));
		for (int idx=0;idx<ETH_ALEN;idx++) {
			mArpArr[mArpArrCount].macAddr[idx]=(int)macAddr[idx];
		}
		for (int idx=0;idx<IP_LEN;idx++) {
			mArpArr[mArpArrCount].ipAddr[idx]=(int)ipAddr[idx];
		}
		mArpArrCount++;
	}
	else {
		mArpArrCount++;
		ArpDet* temp = (ArpDet*)realloc(mArpArr,mArpArrCount*sizeof(ArpDet));
		mArpArr = temp;
		for (int idx=0;idx<ETH_ALEN;idx++) {
			mArpArr[mArpArrCount-1].macAddr[idx]=(int)macAddr[idx];
		}
		for (int idx=0;idx<IP_LEN;idx++) {
			mArpArr[mArpArrCount-1].ipAddr[idx]=(int)ipAddr[idx];
		}
	}
}

/* Function that sorts the ARP list */
void NetworkLayer::SortArpParticipants() {
	bool swap=true;
	while(swap) {
		swap=false;
		for (int idx=1;idx<mArpArrCount;idx++) {

			long int macAddr1=0,macAddr2=0;
			for(int idx1=0;idx1<ETH_ALEN; idx1++) {
				macAddr1 += mArpArr[idx-1].macAddr[idx1]*pow(256,(ETH_ALEN-(idx1+1)));
			}
			for(int idx1=0;idx1<ETH_ALEN; idx1++) {
				macAddr2 += mArpArr[idx].macAddr[idx1]*pow(256,(ETH_ALEN-(idx1+1)));
			}

			if(macAddr1 > macAddr2) {
				ArpDet temp = mArpArr[idx-1];
				mArpArr[idx-1]= mArpArr[idx];
				mArpArr[idx] = temp;
				swap =true;
			}
		}
	}
}

/* Function that prints the cummulative results for the NW layer */
void NetworkLayer::PrintNwLayerStats() {
	SortProtocolList();
	PrintProtocolList();
	SortSrcIp();
	SortDestIp();
	PrintIpAddress();
	PrintTtl();
	SortArpParticipants();
	PrintArpParticipants();
}

/* Function that prcesses the packet for NW layer stats */
void NetworkLayer::ProcessNWLayer(const struct pcap_pkthdr* hdr,const u_char *packet,int size, int ethernet_type){
	mProtCount++;
	if(!CheckAndIncProtcolNo(ethernet_type)) {
		AddNewProtocol(ethernet_type);
	}
	
	if(ethernet_type == ETHERTYPE_IP) {
		mPacketCount++;
		char srcIp[INET_ADDRSTRLEN];
		char destIp[INET_ADDRSTRLEN];
		const struct ip* ipHdr = (struct ip*)(packet + size);
				
		inet_ntop(AF_INET, &(ipHdr->ip_src), srcIp, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(ipHdr->ip_dst), destIp, INET_ADDRSTRLEN);
		if(!CheckAndIncSrcIp(srcIp)) {
			AddNewSrcIp(srcIp);
		}
		if(!CheckAndIncDestIp(destIp)) {
			AddNewDestIp(destIp);	
		}

		IncTtl(ipHdr->ip_ttl);
	}
	
	if(ethernet_type == ETHERTYPE_ARP) {
		const struct ether_arp* arpHdr= (struct ether_arp*)(packet + size);
		if(!CheckArpParticipant(arpHdr->arp_sha,arpHdr->arp_spa)) {
			AddNewArpParticipant(arpHdr->arp_sha,arpHdr->arp_spa);
		}

		if(!CheckArpParticipant(arpHdr->arp_tha,arpHdr->arp_tpa)) {
			AddNewArpParticipant(arpHdr->arp_tha,arpHdr->arp_tpa);
		}
	}
}
