#include "TransportLayer.h"
#include <stdio.h>

using namespace std;

TransportLayer::TransportLayer()
{
	icmres = new ICMP_Response(); //Init icmpresponse messages
	proto_count = 0;
	tcp_src_count = 0;
	tcp_dst_count = 0;
	flag_count = 0;
	opt_count = 0;
	udp_src_count = 0;
	udp_dst_count = 0;
	type_count = 0;
	code_count = 0;
	src_ip_count = 0;
	dst_ip_count = 0;
	resp_count = 0;
}



/* Primary function to add packet information to different arrays
on ip protocol*/
void TransportLayer::AddTransportInfo(ip* ip_hdr)
{
	int port = 0;
	int ip_p = ip_hdr->ip_p;
	struct udphdr* udp_hdr;
	struct tcphdr* tcp_hdr;
	struct icmphdr* icmp;

	AddProtocol(ip_p);


	if(ip_p == IPPROTO_TCP)
	{
		tcp_hdr = (struct tcphdr*)((u_char*)ip_hdr+(ip_hdr->ip_hl*4));

		port = ntohs(tcp_hdr->source);
		AddNew(ConvToStr(port),tcp_src_arr,tcp_src_count);

		port = ntohs(tcp_hdr->dest);
		AddNew(ConvToStr(port),tcp_dst_arr,tcp_dst_count);

		char* flags = GetEnabledFlags(tcp_hdr);
		AddNew(flags,flag_arr,flag_count);

		AddTCPOpts(tcp_hdr);
	}
	else if(ip_p == IPPROTO_UDP)
	{
		udp_hdr = (struct udphdr*)((u_char*)ip_hdr+(ip_hdr->ip_hl*4));

		port = ntohs(udp_hdr->source);
		AddNew(ConvToStr(port), udp_src_arr,udp_src_count);

		port = ntohs(udp_hdr->dest);
		AddNew(ConvToStr(port),udp_dst_arr,udp_dst_count);
	}
	else if(ip_p == IPPROTO_ICMP)
	{
		icmp = (struct icmphdr*)((u_char*)ip_hdr+(ip_hdr->ip_hl*4));

		AddNew(ConvToStr(icmp->type),type_arr,type_count);

		AddNew(ConvToStr(icmp->code),code_arr,code_count);

		char* ip = inet_ntoa(ip_hdr->ip_src);
		AddNew(ip,src_ip_arr,src_ip_count);

		ip = inet_ntoa(ip_hdr->ip_dst);
		AddNew(ip,dst_ip_arr,dst_ip_count);

		AddNew(icmres->GetResponse(icmp->type,icmp->code),
				resp_arr,resp_count);
	}

}


/* Function to add tcp options specified in tcp header tcp*/
void TransportLayer::AddTCPOpts(struct tcphdr* tcp)
{
	TCPOptions* tops = new TCPOptions();
	int optcount = tops->GetOptCount();
	bool setOpts[optcount];
	unsigned int hlen = 0;
	int offset = 0;
	int kind = 0;
	int optlen = 0;

	// boolean array to keep track of already occured options
	for(int i=0;i<optcount;i++)
		setOpts[i] = false;

	hlen = tcp->doff*4;

	// char array starting from options till end
	const u_char* cp = (const u_char*)tcp + sizeof(tcphdr);

	while(hlen > sizeof(struct tcphdr))
	{
		kind = (int)cp[offset];

		char opt[4];
		sprintf(opt,"0x%02x",cp[offset]);

		optlen = tops->GetOptLen(kind);

		if(optlen == -1)
			optlen = (int)cp[offset+1]; //variable length

		offset += optlen; // increment for next look ahead

		hlen -= optlen;	// decrement to note progress

		if(setOpts[kind] == false) // if not has occured before
		{
			AddNew((char*)opt,opt_arr,opt_count);
			setOpts[kind] = true;
		}
	}

}



/* Function to return single character string containing
all enabled flags in tcp header tcp*/
char* TransportLayer::GetEnabledFlags(tcphdr* tcp)
{
	string flags;

	if(tcp->ack == 1)
		flags = flags + "ACK,";
	if(tcp->syn == 1)
		flags = flags + "SYN,";
	if(tcp->psh == 1)
		flags = flags + "PSH,";
	if(tcp->rst == 1)
		flags = flags + "RST,";
	if(tcp->fin == 1)
		flags = flags + "FIN,";
	if(tcp->urg == 1)
		flags = flags + "URG,";

	//remove last comma
	flags.resize(flags.length()-1); 


	return ConvToCharArray(flags);
}




/* Function to convert interger to char array*/
char* TransportLayer::ConvToStr(int num)
{

	ostringstream conv;
	conv<<num;
	conv.str();
	return ConvToCharArray(conv.str());
}



/* Function to convert string to char array*/
char* TransportLayer::ConvToCharArray(std::string str)
{
	char* output;
	unsigned int i=0;

	output = (char*)malloc(str.length());
	for(i=0;i<str.length();i++)
		output[i] = str[i];
	output[i] = '\0';

	return output;
}


/* Function to add integer protocol layer attributes*/
void TransportLayer::AddProtocol(int p_ip)
{
	char* protocol;
	ostringstream conv;

	if(p_ip == IPPROTO_TCP)
		protocol = (char*)"TCP";
	else if(p_ip == IPPROTO_UDP)
		protocol = (char*)"UDP";
	else if(p_ip == IPPROTO_ICMP)
		protocol = (char*)"ICMP";
	else
	{
		conv << p_ip;
		string tmp = conv.str();

		if(tmp.length() == 1)
			tmp = "0" + tmp;
		tmp = "0x" + tmp;

		protocol = ConvToCharArray(tmp);
	}

	AddNew(protocol,proto_arr,proto_count);
}




/* Function to check if val exists in structure array arr
return index of val of found, -1 else */
int TransportLayer::CheckExisting(char* val, tdata *arr, int len)
{
	for(int i=0;i<len;i++)
	{
		if(strcmp(val,arr[i].val) == 0)
			return i;
	}
	return -1;
}




/* Generic add function, that will add char array val, to 
structure array tdata whose length is count. The length of
the array will be incremented by 1*/
void TransportLayer::AddNew(char* val, tdata* &arr, int &count)
{

	int idx = CheckExisting(val,arr,count);

	if(idx != -1)
		arr[idx].freq += 1;
	else
	{
		count = count + 1;
		tdata* tmp;
		if(count == 1)
			tmp = (tdata*)malloc(sizeof(tdata));
		else
			tmp = (tdata*)realloc(arr,count*sizeof(tdata));
		arr = tmp;

		unsigned int i = 0;
		for(i=0;i<strlen(val);i++)
			arr[count-1].val[i] = val[i];
		arr[count-1].val[i] = '\0';

		arr[count-1].freq = 1;
	}
}


/* Function to get total number of occurences of element
maintained in arr for percentage calculation*/
int TransportLayer::GetTotal(tdata* arr, int count)
{
	int tot = 0;
	for(int i=0;i<count;i++)
		tot += arr[i].freq;
	return tot;
}




/*Simple sort function, does string compare if isString is true
else numeric comparison*/
void TransportLayer::Sort(tdata* &arr,int len, bool isString)
{
	int comp = 0;

	for(int i=0;i<len;i++)
	{
		for(int j=0;j<len;j++)
		{
			if(isString)
				comp = strcmp(arr[i].val,arr[j].val);
			else
				comp = atoi(arr[i].val) - atoi(arr[j].val);

			if(comp < 0)
			{
				tdata tmp;
				tmp = arr[i];
				arr[i] = arr[j];
				arr[j] = tmp;
			}
		}
	}
}




/* Display function to sort and display all layer arrays*/
void TransportLayer::Display()
{
	Sort(proto_arr,proto_count,true);
	Sort(tcp_src_arr,tcp_src_count,false);
	Sort(tcp_dst_arr,tcp_dst_count,false);
	Sort(flag_arr,flag_count,true);
	Sort(udp_src_arr,udp_src_count,false);
	Sort(udp_dst_arr,udp_dst_count,false);
	Sort(src_ip_arr,src_ip_count,true);
	Sort(dst_ip_arr,dst_ip_count,true);
	Sort(opt_arr,opt_count,true);
	Sort(type_arr,type_count,false);
	Sort(code_arr,code_count,false);
	Sort(resp_arr,resp_count,true);

	cout<<"\n\n=== Transport Layer ===";
	ShowDetails(proto_arr,proto_count,(char*)"Transport Layer Protocols");
	cout<<"\n\n=== Transport Layer : TCP ===";
	ShowDetails(tcp_src_arr,tcp_src_count,(char*)"Source TCP Ports");
	ShowDetails(tcp_dst_arr,tcp_dst_count,(char*)"Destination TCP Ports");
	ShowDetails(flag_arr,flag_count,(char*)"TCP Flags");
	ShowDetails(opt_arr,opt_count,(char*)"TCP Options");
	cout<<"\n\n=== Transport Layer : UDP ===";
	ShowDetails(udp_src_arr,udp_src_count,(char*)"Source UDP Ports");
	ShowDetails(udp_dst_arr,udp_dst_count,(char*)"Destination UDP Ports");
	ShowDetails(src_ip_arr,src_ip_count,(char*)"Source IPs for ICMP");
	ShowDetails(dst_ip_arr,dst_ip_count,(char*)"Destination IPs for ICMP");
	ShowDetails(type_arr,type_count,(char*)"ICMP Types");
	ShowDetails(code_arr,code_count,(char*)"ICMP Codes");
	ShowDetails(resp_arr,resp_count,(char*)"ICMP Responses");

	cout<<"\n\n";

}



/* Generic display function that will dsiplay the contents of arr of length
count in a formatted manner with heading as title */
void TransportLayer::ShowDetails(tdata* arr, int count, char* heading)
{

	int tot = GetTotal(arr,count);

	cout<<std::showpoint<<setprecision(3);

	cout<<"\n\n--- "<<heading<<" ---\n\n";
	if(count == 0)
		cout<<"(no results)";
	for(int i=0;i<count;i++)
		cout<<setw(20)<<arr[i].val<<"\t\t"<<setw(10)<<arr[i].freq<<"\t"<<setw(6)<<fixed<<setprecision(2)<<(float)arr[i].freq*100/tot<<"%"<<endl;

}


TransportLayer::~TransportLayer() {
}

