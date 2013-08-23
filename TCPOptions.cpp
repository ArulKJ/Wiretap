#include "TCPOptions.h"


/*Class to maintain length to various tcp options*/


TCPOptions::TCPOptions()
{
	for(int i=0;i<OPTLEN;i++)
		options[i] = 1;

	AddOption(EOL,1);
	AddOption(NO_OP,1);
	AddOption(MSS,4);
	AddOption(WSOPT,3);
	AddOption(SACK_P,2);
	AddOption(SACK,-1);
	AddOption(ECHO,6);
	AddOption(ECHO_REPLY,6);
	AddOption(TSOPT,10);
}


void TCPOptions::AddOption(int kind, int len)
{
	if(kind >= 0 && kind < OPTLEN)
		options[kind] = len;
}


int TCPOptions::GetOptLen(int kind)
{
	if(kind >= 0 && kind < OPTLEN)
		return options[kind];
	return -1;
}


int TCPOptions::GetOptCount()
{
	return OPTLEN;
}


TCPOptions::~TCPOptions() {
}

