#include "LinkLayer.h"
#include <netinet/in.h>
#include <sstream>
#include <malloc.h>

using namespace std;

LinkLayer::LinkLayer()
{
	src_count = 0;
	dst_count = 0;
}



/* Primary function to add link layer information to arrays*/
void LinkLayer::AddLinkInfo(ether_header* eth_hdr)
{
	AddSrcIP(ether_ntoa((struct ether_addr*)eth_hdr->ether_shost));
	AddDstIP(ether_ntoa((struct ether_addr*)eth_hdr->ether_dhost));
}




/* Function to check if source ip alread exists. Returns index
if found, -1 else */
int LinkLayer::FindSrcIP(char* ip)
{
	for(int i=0;i<src_count;i++)
	{
		if(strcmp(src_arr[i].addr,ip) == 0)
			return i;
	}

	return -1;
}



/* Function to check if destination ip alread exists. Returns index
if found, -1 else */
int LinkLayer::FindDstIP(char* ip)
{
	for(int i=0;i<dst_count;i++)
	{
		if(strcmp(dst_arr[i].addr,ip) == 0)
			return i;
	}

	return -1;
}



/* Function to add ip to source array*/
void LinkLayer::AddSrcIP(char* ip)
{
	string tmp = NormalizeIPLen(ip);

	ip = (char*)tmp.c_str();

	int idx = FindSrcIP(ip);

	if(idx != -1)
		src_arr[idx].freq += 1;
	else
	{
		src_count = src_count + 1;
		ip_data* temp;
		if(src_count == 1)
			temp = (ip_data*)malloc(sizeof(ip_data));
		else
			temp = (ip_data*)realloc(src_arr,src_count*sizeof(ip_data));
		src_arr = temp;

		strcpy(ip,tmp.c_str());

		unsigned int i =0;
		for (i=0;i<strlen(ip);i++)
			src_arr[src_count-1].addr[i] = ip[i];

		src_arr[src_count-1].addr[i] = '\0';
		src_arr[src_count-1].freq = 1;
	}
}


/* Function to add address 'ip' to destination array*/
void LinkLayer::AddDstIP(char* ip)
{
	string tmp = NormalizeIPLen(ip);

	ip = (char*)tmp.c_str();

	int idx = FindDstIP(ip);

	if(idx != -1)
		dst_arr[idx].freq += 1;
	else
	{
		dst_count = dst_count + 1;
		ip_data* temp;
		if(dst_count == 1)
			temp = (ip_data*)malloc(sizeof(ip_data));
		else
			temp = (ip_data*)realloc(dst_arr,dst_count*sizeof(ip_data));
		dst_arr = temp;

		strcpy(ip,tmp.c_str());

		unsigned int i =0;
		for (i=0;i<strlen(ip);i++)
			dst_arr[dst_count-1].addr[i] = ip[i];
		dst_arr[dst_count-1].addr[i] = '\0';

		dst_arr[dst_count-1].freq = 1;
	}
}


/* Function to ensure all octets in address 'ip'
are of length 2 (padding) */
string LinkLayer::NormalizeIPLen(char* ip)
{
	string str(ip);

	unsigned int pos = str.find(":");
	string oct, result;

	while(pos <= strlen(ip))
	{
		oct = str.substr(0,pos);
		str = str.substr(pos+1);

		if(strlen(oct.c_str()) == 1)
			oct = "0" + oct;

		result = result + oct + ":";

		pos = str.find(":");
	}

	if(str.length() == 1)
		str = "0" + str;
	result = result + str;

	return result;
}



/* Simple sort of array arr using string compare*/
void LinkLayer::Sort(ip_data* &arr,int len)
{

	for(int i=0;i<len;i++)
	{
		for(int j=0;j<len;j++)
		{

			if(strcmp(arr[i].addr,arr[j].addr) < 0)
			{
				ip_data tmp;
				tmp = arr[i];
				arr[i] = arr[j];
				arr[j] = tmp;
			}
		}
	}
}




/* Function to display contents of source and destination arrays*/
void LinkLayer::Display()
{

	int tot1 = 0;
	int tot2 = 0;

	for(int i=0;i<src_count;i++)
		tot1 += src_arr[i].freq;

	for(int i=0;i<dst_count;i++)
		tot2 += dst_arr[i].freq;

	Sort(src_arr,src_count);
	Sort(dst_arr,dst_count);

	cout<<std::showpoint<<setprecision(3);

	cout<<"\n\n=== Link Layer ===\n\n";
	cout<<"--- Source Ethernet Address ---\n\n";

	if(src_count == 0)
		cout<<"(no results)";

	for(int i=0;i<src_count;i++)
		cout<<setw(20)<<src_arr[i].addr<<"\t\t"<<setw(10)<<src_arr[i].freq<<"\t\t"<<setw(6)<<fixed<<setprecision(2)<<(float)src_arr[i].freq*100/tot1<<"%"<<endl;

	cout<<"\n\n--- Destination Ethernet Address ---\n\n";

	if(dst_count == 0)
		cout<<"(no results)";

	for(int i=0;i<dst_count;i++)
		cout<<setw(20)<<dst_arr[i].addr<<"\t\t"<<setw(10)<<dst_arr[i].freq<<"\t\t"<<setw(6)<<fixed<<setprecision(2)<<(float)dst_arr[i].freq*100/tot2<<"%"<<endl;
}

LinkLayer::~LinkLayer() {
}

