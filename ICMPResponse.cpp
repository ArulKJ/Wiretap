#include "ICMPResponse.h"
#include <malloc.h>

using namespace std;

ICMP_Response::ICMP_Response()
{
	count = 0;

	AddType(0,(char*)"ECHOREPLY");
	AddType(3,(char*)"UNREACH");
	AddCodes(3,0,(char*)"NET");
	AddCodes(3,1,(char*)"HOST");
	AddCodes(3,2,(char*)"PROTOCOL");
	AddCodes(3,3,(char*)"PORT");
	AddCodes(3,4,(char*)"NEEDFRAG");
	AddCodes(3,5,(char*)"SRCFAIL");
	AddCodes(3,6,(char*)"NET_UNKNOWN");
	AddCodes(3,7,(char*)"HOST_UNKNOWN");
	AddCodes(3,8,(char*)"ISOLATED");
	AddCodes(3,9,(char*)"NET_PROHIB");
	AddCodes(3,10,(char*)"HOST_PROHIB");
	AddCodes(3,11,(char*)"TOSNET");
	AddCodes(3,12,(char*)"TOSHOST");
	AddCodes(3,13,(char*)"FILTER_PROHIB");
	AddCodes(3,14,(char*)"HOST_PRECEDENCE");
	AddCodes(3,15,(char*)"PRECEDENCE_CUTOFF");
	AddType(4,(char*)"SOURCEQUENCH");
	AddType(5,(char*)"REDIRECT");
	AddCodes(5,0,(char*)"NET");
	AddCodes(5,0,(char*)"HOST");
	AddCodes(5,0,(char*)"TOSNET");
	AddCodes(5,0,(char*)"TOSHOST");
	AddType(8,(char*)"ECHO");
	AddType(9,(char*)"ROUTERADVERT");
	AddCodes(9,0,(char*)"COMMON");
	AddCodes(9,16,(char*)"NOCOMMON");
	AddType(10,(char*)"ROUTERSOLICIT");
	AddType(11,(char*)"TIMXCEED");
	AddCodes(11,0,(char*)"INTRANS");
	AddCodes(11,1,(char*)"REASS");
	AddType(12,(char*)"PARAMPROB");
	AddCodes(12,1,(char*)"OPTABSENT");
	AddCodes(12,2,(char*)"BADLENGTH");
	AddType(13,(char*)"TSTAMP");
	AddType(14,(char*)"TSTAMPREPLY");
	AddType(15,(char*)"IREQ");
	AddType(16,(char*)"IREQREPLY");
	AddType(17,(char*)"MASKREQ");
	AddType(18,(char*)"MASKREPLY");
}



void ICMP_Response::AddType(int key, char* val)
{

	count = count + 1;
	dict* tmp;
	if(count == 1)
		tmp = (dict*)malloc(sizeof(dict));
	else
		tmp = (dict*)realloc(responses,count*sizeof(dict));
	responses = tmp;

	responses[count-1].id = key;

	unsigned int i = 0;
	for(i=0;i<strlen(val);i++)
		responses[count-1].value[i] = val[i];
	responses[count-1].value[i] = '\0';

	responses[count-1].codes_count = 0;

}





void ICMP_Response::AddCodes(int type,int key,char* val)
{
	for(int i=0;i<count;i++)
	{
		if(responses[i].id == type)
		{
			responses[i].codes_count += 1;
			int nc = responses[i].codes_count;
			dict* tmp;
			if(nc == 1)
				tmp = (struct dict*)malloc(sizeof(dict));
			else
				tmp = (struct dict*)realloc(responses[i].codes,nc*sizeof(dict));
			responses[i].codes = tmp;

			responses[i].codes[nc-1].id = key;

			unsigned int j = 0;
			for(j = 0;j<strlen(val);j++)
				responses[i].codes[nc-1].value[j] = val[j];
			responses[i].codes[nc-1].value[j] = '\0';
		}
	}
}



char* ICMP_Response::GetResponse(int type)
{
	for(int i=0;i<count;i++)
	{
		if(responses[i].id == type)
			return responses[i].value;
	}

	return (char*)"NA";
}



char* ICMP_Response::GetResponse(int type,int code)
{
	for(int i=0;i<count;i++)
	{
		if(responses[i].id == type)
		{
			char* res = (char*)malloc(sizeof(responses[i].value));
			strcpy(res,responses[i].value);
			strcat(res, " ");

			for(int j=0;j<responses[i].codes_count;j++)
			{
				if(responses[i].codes[j].id == code)
				{
					res = strcat(res, responses[i].codes[j].value);
					break;
				}
			}
			return res;
		}
	}
	return (char*)"NA";
}


ICMP_Response::~ICMP_Response() {
}

