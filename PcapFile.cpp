#include "PcapFile.h"

#define CHAR_BUFFER 80
#define ONE_SECOND_inMs 1000000
#define ONE_Hour_inS 3600
#define ONE_Minute_inS 60

int gMinSize=INT_MAX;
int gMaxSize=0;
int gCount=0;
int gTotSize=0;
timeval gStartTime;
timeval gEndTime;

using namespace std;


/* Default constructor to initialize layer objects */
PcapFile::PcapFile() {
	l = new LinkLayer();
	n = NetworkLayer::getInstance();
	t = new TransportLayer();
}


/* Primary pcap loop handler function to call layer functions for different headers*/
void ProcessFileData(u_char *args, const struct pcap_pkthdr *hdr,const u_char *packet)
{

	++gCount;
	if((int)hdr->len < gMinSize) {
		gMinSize = (int)hdr->len;
	}

	if((int)hdr->len > gMaxSize) {
		gMaxSize =  (int)hdr->len;
	}
	gTotSize += (int)hdr->len;

	if(gCount == 1) {
		gStartTime = hdr->ts;
	}
	gEndTime = hdr->ts;

	PcapFile* p = (PcapFile*)args;

	struct ether_header* eth_hdr;
	struct ip* ip_hdr;

	eth_hdr = (struct ether_header*)(packet);
	ip_hdr = (struct ip*)(packet + sizeof(ether_header));

	LinkLayer* l = p->getLLayer();
	l->AddLinkInfo(eth_hdr);

	NetworkLayer* n = NetworkLayer::getInstance();
	n->ProcessNWLayer(hdr,packet,sizeof(struct ether_header),(int)ntohs(eth_hdr->ether_type));

	TransportLayer* t = p->getTLayer();
	if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP)
		t->AddTransportInfo(ip_hdr);

}


/* Function to open .pcap file using pcap lib. Returns
false if error/failure*/
bool PcapFile::OpenFile(char* filepath)
{

	char errbuf[PCAP_ERRBUF_SIZE];
	session_handler = pcap_open_offline(filepath,errbuf);

	if(session_handler == NULL) {
		cout<<"Error trying to open the file for parsing."<<endl;
		cout<<"Error is:\t"<<errbuf<<endl;
		return false;
	}

	if(pcap_datalink(session_handler) != DLT_EN10MB) {
		cout<<"Data Not Captured from Ethernet"<<endl;
		return false;
	}
	return true;

}



/* Print .pcap file's session summary*/
void PcapFile::PrintSummary(){
	cout<<"=== Summary ===\n"<<endl;
	cout<<setw(30)<<"Start Date:\t";
	char buffer[CHAR_BUFFER];
	strftime(buffer,CHAR_BUFFER,"%Y-%m-%d %H:%M:%S",localtime(&gStartTime.tv_sec));
	cout<<buffer<<"."<<setw(6)<<setfill('0')<<gStartTime.tv_usec<<setfill(' ')<<endl;


	long mSeconds,seconds;
	if(gStartTime.tv_usec > gEndTime.tv_usec) {
		gEndTime.tv_sec--;
		mSeconds = ONE_SECOND_inMs+gEndTime.tv_usec-gStartTime.tv_usec;
	} else {
		mSeconds = gEndTime.tv_usec-gStartTime.tv_usec;
	}

	seconds = gEndTime.tv_sec-gStartTime.tv_sec;
	int hour = seconds/ONE_Hour_inS;
	int minutes = (seconds - (hour*ONE_Hour_inS))/ONE_Minute_inS;
	int sec = seconds -((hour*ONE_Hour_inS)+(minutes*ONE_Minute_inS));

	cout<<setw(30)<<"Duration:\t";
	cout<<setw(2)<<setfill('0')<<hour<<setfill(' ')<<":";
	cout<<setw(2)<<setfill('0')<<minutes<<setfill(' ')<<":";
	cout<<setw(2)<<setfill('0')<<sec<<setfill(' ')<<".";
	cout<<setw(6)<<setfill('0')<<mSeconds<<setfill(' ')<<endl;

	cout<<setw(30)<<"# Packets\t";
	cout<<gCount<<endl;
	cout<<setw(30)<<"Smallest:\t";
	cout<<gMinSize<<" bytes"<<endl;
	cout<<setw(30)<<"Largest:\t";
	cout<<gMaxSize<<" bytes"<<endl;
	cout<<setw(30)<<"Average:\t";
	cout<<fixed<<setprecision(2)<<((float)gTotSize)/gCount<<" bytes"<<endl;
}



/* Function to initialize file processing*/
void PcapFile::ProcessFile()
{
	pcap_loop(session_handler,-1,ProcessFileData,(u_char*)this);
	PrintSummary();
	l->Display();
	n->PrintNwLayerStats();
	t->Display();
}



PcapFile::~PcapFile() {
	pcap_close(session_handler);
	session_handler =NULL;
	delete l;
	delete n;
	delete t;
}

