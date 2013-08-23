#include <iostream>
#include "PcapFile.h"

using namespace std;

int main(int argc,char* argv[])
{
	// Check to see if only one param is specified
	if(argc != 2) {
		cout<<"Missing filename or too many parameters"<<endl;
		cout<<"Format is:\nWiretap <Filename>"<<endl;
		return 1;
	}

	// Perform all the parsing after opening the file
	PcapFile* p = new PcapFile();
	if(p->OpenFile(argv[1])){
		p->ProcessFile();
	}
	return 0;
}



