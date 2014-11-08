// You will build this in project part B - this is merely a
// stub that does nothing but integrate into the stack

// For project parts A and B, an appropriate binary will be 
// copied over as part of the build process



#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>


#include <iostream>

#include "Minet.h"

using namespace std;

struct TCPState {
    // need to write this
    std::ostream & Print(std::ostream &os) const { 
	os << "TCPState()" ; 
	return os;
    }
};


int main(int argc, char * argv[]) {
    MinetHandle mux;
    MinetHandle sock;
    
    ConnectionList<TCPState> clist;
	
	//Temporary connection object to avoid using clist
	Connection temp;

    MinetInit(MINET_TCP_MODULE);

    mux = MinetIsModuleInConfig(MINET_IP_MUX) ?  
	MinetConnect(MINET_IP_MUX) : 
	MINET_NOHANDLE;
    
    sock = MinetIsModuleInConfig(MINET_SOCK_MODULE) ? 
	MinetAccept(MINET_SOCK_MODULE) : 
	MINET_NOHANDLE;

    if ( (mux == MINET_NOHANDLE) && 
	 (MinetIsModuleInConfig(MINET_IP_MUX)) ) {

	MinetSendToMonitor(MinetMonitoringEvent("Can't connect to ip_mux"));

	return -1;
    }

    if ( (sock == MINET_NOHANDLE) && 
	 (MinetIsModuleInConfig(MINET_SOCK_MODULE)) ) {

	MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock_module"));

	return -1;
    }
    
    cerr << "tcp_module STUB VERSION handling tcp traffic.......\n";

    MinetSendToMonitor(MinetMonitoringEvent("tcp_module STUB VERSION handling tcp traffic........"));

    MinetEvent event;
    double timeout = 100;

    while (MinetGetNextEvent(event, timeout) == 0) {

		if ((event.eventtype == MinetEvent::Dataflow) && 
			(event.direction == MinetEvent::IN)) {
		
			if (event.handle == mux) 
			{
				// ip packet has arrived!
				cout<< "In event.handle == mux loop\n";
				
				Packet rec;
				TCPHeader tcpheader;
				IPHeader ipheader;
				size_t size, actualSize;
				char recvBuf[1024];
				Connection c;
				
				
				//Receive packet
				MinetReceive(mux, rec);
				unsigned short len = TCPHeader::EstimateTCPHeaderLength(rec);
				unsigned char flags;
				rec.ExtractHeaderFromPayload<TCPHeader>(len);
				
				//pull headers
				tcpheader = rec.FindHeader(Headers::TCPHeader);
				ipheader = rec.FindHeader(Headers::IPHeader);
				
				//Lines 79-85 on udp, I assume this is setting the conn
				//with the proper properties.
				ipheader.GetDestIP(c.src);
				ipheader.GetSourceIP(c.dest);
				c.protocol = IP_PROTO_TCP;
				tcpheader.GetSourcePort(c.destport);
				tcpheader.GetDestPort(c.srcport);
				
				//Get flags
				tcpheader.GetFlags(flags);
				
				
				//Working with connectionlist
				ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
				
				if (cs != clist.end())
				{
					//connection already est
					cout << "We should be replying here I think\n";
				}
				else
				{
					//I think we have to make a new connection here
					cout << "Not in connection list\n";
					//Check to ensure that we received a syn
					
					if(IS_SYN(flags))
					{
						cout<< "this is a syn \n";
						//Add new connection
						
						unsigned int recseq;
						unsigned short recsrcport;
						tcpheader.GetSeqNum(recseq);
						tcpheader.GetSourcePort(recsrcport);
						
						//This must be a ctsm, not jsut a connection
						//clist.push_back(c);
						
						Packet rp;
						TCPHeader rtcph;
						IPHeader riph;
						flags = 0;
						
						//Setup IP Header
						riph.SetProtocol(IP_PROTO_TCP);
						riph.SetSourceIP(c.src);
						riph.SetDestIP(c.dest);
						riph.SetTotalLength(TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH);
						rp.PushFrontHeader(riph);
						
						//Setup TCP header
						SET_SYN(flags);
						SET_ACK(flags);
						rtcph.SetSourcePort(c.srcport, rp);
						rtcph.SetDestPort(c.destport, rp);
						rtcph.SetSeqNum(100, rp);
						rtcph.SetAckNum(recseq + 1, rp);
						rtcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH, rp);
						rtcph.SetFlags(flags, rp);
						if(rtcph.IsCorrectChecksum(rp))
						{
							cout << "Checksum should be ok\n";
						}
						rp.PushBackHeader(rtcph);
						MinetSend(mux, rp);
						
						
						/*SockRequestResponse resp;
						resp.type = WRITE;
						resp.connection = c;
						resp.error = EOK;
						resp.data = NULL;
						
						MinetSend(sock, resp);*/
						
					}
					else
					{
						//Same error processing as in udp 105-109
						MinetSendToMonitor(MinetMonitoringEvent("Unknown port, sending ICMP error message"));
						IPAddress source; ipheader.GetSourceIP(source);
						ICMPPacket error(source,DESTINATION_UNREACHABLE,PORT_UNREACHABLE,rec);
						MinetSendToMonitor(MinetMonitoringEvent("ICMP error message has been sent to host"));
						MinetSend(mux, error);
					}
				}
				
				
				
				
				
				
				//Buffer payload = rec.GetPayload().ExtractFront((unsigned short)size);
				
				//display buffer
				//size = payload.GetSize();
				//actualSize = payload.GetData(recvBuf, size, 0);
				
				
				//cout << recvBuf << "\n" << size << "\n" << actualSize << "\n";
				//cout << recvBuf << "\n" << size << "\n" << actualSize << "\n";
				
			}

			if (event.handle == sock) 
			{
				SockRequestResponse req;
				MinetReceive(sock,req);
				switch (req.type) 
				{
					case CONNECT:
					case ACCEPT:
					{ // ignored, send OK response
						SockRequestResponse repl;
						repl.type=STATUS;
						repl.connection=req.connection;
						// buffer is zero bytes
						repl.bytes=0;
						repl.error=EOK;
						MinetSend(sock,repl);
					}
					break;
					case STATUS:
					  // ignored, no response needed
					  break;
					  // case SockRequestResponse::WRITE:
					case WRITE:
					{
						/*unsigned bytes = MIN_MACRO(UDP_MAX_DATA, req.data.GetSize());
						// create the payload of the packet
						Packet p(req.data.ExtractFront(bytes));
						// Make the IP header first since we need it to do the udp checksum
						IPHeader ih;
						ih.SetProtocol(IP_PROTO_UDP);
						ih.SetSourceIP(req.connection.src);
						ih.SetDestIP(req.connection.dest);
						ih.SetTotalLength(bytes+UDP_HEADER_LENGTH+IP_HEADER_BASE_LENGTH);
						// push it onto the packet
						p.PushFrontHeader(ih);
						// Now build the UDP header
						// notice that we pass along the packet so that the udpheader can find
						// the ip header because it will include some of its fields in the checksum
						UDPHeader uh;
						uh.SetSourcePort(req.connection.srcport,p);
						uh.SetDestPort(req.connection.destport,p);
						uh.SetLength(UDP_HEADER_LENGTH+bytes,p);
						// Now we want to have the udp header BEHIND the IP header
						p.PushBackHeader(uh);
						MinetSend(mux,p);
						SockRequestResponse repl;
						// repl.type=SockRequestResponse::STATUS;
						repl.type=STATUS;
						repl.connection=req.connection;
						repl.bytes=bytes;
						repl.error=EOK;
						MinetSend(sock,repl);*/
					}
					break;
					  // case SockRequestResponse::FORWARD:
					case FORWARD:
					{
						ConnectionToStateMapping<TCPState> m;
						m.connection=req.connection;
						// remove any old forward that might be there.
						ConnectionList<TCPState>::iterator cs = clist.FindMatching(req.connection);
						if (cs!=clist.end()) {
							clist.erase(cs);
						}
						clist.push_back(m);
						SockRequestResponse repl;
						// repl.type=SockRequestResponse::STATUS;
						repl.type=STATUS;
						repl.connection=req.connection;
						repl.error=EOK;
						repl.bytes=0;
						MinetSend(sock,repl);
					}
					break;
					  // case SockRequestResponse::CLOSE:
					case CLOSE:
					{
						ConnectionList<TCPState>::iterator cs = clist.FindMatching(req.connection);
						SockRequestResponse repl;
						repl.connection=req.connection;
						// repl.type=SockRequestResponse::STATUS;
						repl.type=STATUS;
						if (cs==clist.end()) {
							repl.error=ENOMATCH;
						} else {
							repl.error=EOK;
							clist.erase(cs);
						}
						MinetSend(sock,repl);
					}
					break;
					default:
					{
						SockRequestResponse repl;
						// repl.type=SockRequestResponse::STATUS;
						repl.type=STATUS;
						repl.error=EWHAT;
						MinetSend(sock,repl);
					}
				}
			}
		}

		else if (event.eventtype == MinetEvent::Timeout) 
		{
			// timeout ! probably need to resend some packets
			
			//cout<< "Timeout event\n";
		}
		else
		{
			cout << "I have no idea how anything could get here";
		}

    }

    MinetDeinit();

    return 0;
}
