#include<iostream>
#include<string.h>
#include<stdlib.h>

#ifndef ICMPRESPONSE_H_
#define ICMPRESPONSE_H_


class ICMP_Response
{
	struct dict
	{
		int id;
		char value[128];
		dict* codes;
		int codes_count;
	};
private:
	dict* responses;
	int count;
public:
	ICMP_Response();
	void AddType(int key,char* val);
	void AddCodes(int type,int key, char* val);
	char* GetResponse(int type);
	char* GetResponse(int type, int code);
	virtual ~ICMP_Response();
};

#endif /* ICMPRESPONSE_H_ */
