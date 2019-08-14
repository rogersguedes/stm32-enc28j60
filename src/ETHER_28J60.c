#include "EtherShield.h"
#include <ETHER_28J60.h>
#include "ip_arp_udp_tcp.h"
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


int ETHER_28J60_serviceRequest(uint8_t *buffer, size_t bSize)
{
	uint16_t data_idx;
	size_t data_length, i = 0;
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
	        	data_idx=ES_get_tcp_data_pointer();
	        	if (data_idx==0)
				{ // we can possibly have no data, just ack:
	          		if (buf[TCP_FLAGS_P] & TCP_FLAGS_FIN_V)
					{
	          			ES_make_tcp_ack_from_any(buf, 0, 0);
	          		}
	          		return 0;
	        	}
	        	data_length=get_tcp_data_len(buf);

	 			if(data_length > bSize)//error enough memory
	 			{
	 				return -1;
	 			}
	 			i=0;
	 			while(i < bSize && i < data_length){
					buffer[i] = buf[data_idx+i];
					i++;
	 			}
	 			data_length = plen;
	 			plen=0;
	 			ES_make_tcp_ack_from_any(buf, 0, 0); // send ack ASAP to avoid peer retransmission
	 			return data_length;
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
	ES_make_tcp_ack_with_data(buf,plen); // send data
}
