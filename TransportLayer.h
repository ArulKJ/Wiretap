#include <iostream>
#include <iomanip>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<netinet/ip_icmp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sstream>
#include <string.h>
#include<stdio.h>
#include <stdlib.h>
#include "ICMPResponse.h"
#include "TCPOptions.h"

#ifndef TRANSPORTLAYER_H_
#define TRANSPORTLAYER_H_

#define VLEN 128


typedef struct _tdata
{
	char val[VLEN];
	int freq;
}tdata;

class TransportLayer
{

private:

	tdata* src_ip_arr;
	tdata* dst_ip_arr;
	tdata* tcp_src_arr;
	tdata* tcp_dst_arr;
	tdata* udp_src_arr;
	tdata* udp_dst_arr;
	tdata* type_arr;
	tdata* code_arr;
	tdata* flag_arr;
	tdata* proto_arr;
	tdata* resp_arr;
	tdata* opt_arr;
	int src_ip_count;
	int dst_ip_count;
	int tcp_src_count;
	int tcp_dst_count;
	int udp_src_count;
	int udp_dst_count;
	int flag_count;
	int proto_count;
	int type_count;
	int code_count;
	int resp_count;
	int opt_count;
	ICMP_Response* icmres;
public:
	TransportLayer();
	void AddTransportInfo(ip* ip_hdr);
	void AddProtocol(int p_ip);
	void AddTCPOpts(struct tcphdr* tcp);
	char* GetEnabledFlags(tcphdr* tcp);
	char* ConvToStr(int num);
	char* ConvToCharArray(std::string str);
	int CheckExisting(char* val, tdata* arr, int len);
	void AddNew(char* val, tdata* &arr, int &count);
	int GetTotal(tdata* arr, int count);
	void Sort(tdata* &arr,int len,bool isString);
	void Display();
	void ShowDetails(tdata* arr, int count, char* heading);
	virtual ~TransportLayer();
};

#endif /* TRANSPORTLAYER_H_ */
