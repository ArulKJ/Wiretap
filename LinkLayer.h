#include <iostream>
#include <string.h>
#include <stdlib.h>
#include <string>
#include <iomanip>
#include <netinet/ether.h>

#ifndef LINKLAYER_H_
#define LINKLAYER_H_

#define VLEN 128

typedef struct _ip_data
{
	char addr[VLEN];
	int freq;
}ip_data;


class LinkLayer
{
private:
	ip_data* src_arr;
	ip_data* dst_arr;
	int dst_count;
	int src_count;
public:
	LinkLayer();
	void AddLinkInfo(ether_header* eth_hdr);
	void Sort(ip_data* &arr, int len);
	void AddSrcIP(char* ip);
	void AddDstIP(char* ip);
	int FindDstIP(char* ip);
	int FindSrcIP(char* ip);
	void Add(char* das);
	std::string NormalizeIPLen(char* ip);
	void Display();
	virtual ~LinkLayer();
};

#endif /* LINKLAYER_H_ */
