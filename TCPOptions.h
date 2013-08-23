#ifndef TCPOPTIONS_H_
#define TCPOPTIONS_H_

#define OPTLEN 255
#define EOL 0
#define NO_OP 1
#define MSS 2
#define WSOPT 3
#define SACK_P 4
#define SACK 5
#define ECHO 6
#define ECHO_REPLY 7
#define TSOPT 8

class TCPOptions
{
private:
	int options[OPTLEN];
public:
	TCPOptions();
	void AddOption(int kind,int len);
	int GetOptLen(int kind);
	int GetOptCount();
	virtual ~TCPOptions();
};

#endif /* TCPOPTIONS_H_ */
