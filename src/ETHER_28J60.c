#include "EtherShield.h"
#include <ETHER_28J60.h>
#include <string.h>
static  uint16_t _port;

#define BUFFER_SIZE 500
static uint8_t buf[BUFFER_SIZE+1];
uint16_t plen;


void ETHER_28J60_setup(uint8_t macAddress[], uint8_t ipAddress[], uint16_t port)
{
    ES_enc28j60Init(macAddress);
    _port = port;
    ES_init_ip_arp_udp_tcp(macAddress, ipAddress, _port);
}


size_t ETHER_28J60_serviceRequest(uint8_t *buffer, size_t bSize)
{
	uint16_t dat_p;
	int8_t cmd;
	plen = ES_enc28j60PacketReceive(BUFFER_SIZE, buf);

	/*plen will ne unequal to zero if there is a valid packet (without crc error) */
	if(plen!=0)
	{
		// arp is broadcast if unknown but a host may also verify the mac address by sending it to a unicast address.
	    if (ES_eth_type_is_arp_and_my_ip(buf, plen))
		{
	      ES_make_arp_answer_from_request(buf);
	      return 0;
	    }
	    // check if ip packets are for us:
	    if (ES_eth_type_is_ip_and_my_ip(buf, plen) == 0)
	 	{
	      return 0;
	    }
	    if (buf[IP_PROTO_P]==IP_PROTO_ICMP_V && buf[ICMP_TYPE_P]==ICMP_TYPE_ECHOREQUEST_V)
		{
	      ES_make_echo_reply_from_request(buf, plen);
	      return 0;
	    }
	    // tcp port www start, compare only the lower byte
	    if (buf[IP_PROTO_P] == IP_PROTO_TCP_V && buf[TCP_DST_PORT_H_P] == 0 && buf[TCP_DST_PORT_L_P] == _port)
		{
	    	if (buf[TCP_FLAGS_P] & TCP_FLAGS_SYN_V)
			{
	         	ES_make_tcp_synack_from_syn(buf); // make_tcp_synack_from_syn does already send the syn,ack
	         	return 0;
	      	}
	      	if (buf[TCP_FLAGS_P] & TCP_FLAGS_ACK_V)
			{
	        	ES_init_len_info(buf); // init some data structures
	        	dat_p=ES_get_tcp_data_pointer();
	        	if (dat_p==0)
				{ // we can possibly have no data, just ack:
	          		if (buf[TCP_FLAGS_P] & TCP_FLAGS_FIN_V)
					{
	          			ES_make_tcp_ack_from_any(buf, 0, 0);
	          		}
	          		return 0;
	        	}
	        	if (strncmp("GET ",(char *)&(buf[dat_p]),4)!=0)
				{
	          		// head, post and other methods for possible status codes see:
	            	// http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
	            	plen=ES_fill_tcp_data(buf,0,"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>200 OK</h1>");
//					plen=ES_fill_tcp_data_p(buf,plen,PSTR("<h1>A</h1>"));
	            	ETHER_28J60_respond();
	          		return 0;
	        	}
	 			if (strncmp("/",(char *)&(buf[dat_p+4]),1)==0) // was "/ " and 2
				{
					// Copy the request action before we overwrite it with the response
					size_t i = 0;
					while (buf[dat_p+5+i] != ' ' && i < bSize)
					{
						buffer[i] = buf[dat_p+5+i];
						i++;
					}
					buffer[i] = '\0';
					plen=ES_fill_tcp_data(buf,0,"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n");
	            	ETHER_28J60_respond();
					return i;
	         	}
	      }
	      else
	      {
			  return 0;
	      }
		}
	}
	return 0;
}

void ETHER_28J60_print(char* text)
{
	int j = 0;
  	while (text[j]) 
	{
    	buf[TCP_CHECKSUM_L_P+3+plen]=text[j++];
    	plen++;
  	}
}

void ETHER_28J60_respond()
{
	ES_make_tcp_ack_from_any(buf, 0, 0); // send ack for http get
	ES_make_tcp_ack_with_data(buf,plen); // send data
}
