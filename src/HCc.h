#ifndef LOWPAN_HCC
#define LOWPAN_HCC

#include "IPv6.h"
#include "frag.h"
#include "MAC.h"
#include "utilities.h"
#include "types.h"



////// LOWPAN_COMPRESSION_HC1
/* HC1 IPv6 header compression */
/* HC1 defined in RFC4944 */
#define NEXT_HEADER_UNCOMPRESSED 0
#define NEXT_HEADER_UDP 		 1
#define NEXT_HEADER_ICMP 		 2
#define NEXT_HEADER_TCP 		 3

#define HC1_GET_SOURCE_PREFIX_COMPRESSED(_BYTE) (_BYTE & 1)
#define HC1_GET_SOURCE_INTERFACE_IDENTIFIER_COMPRESSED(_BYTE) ((_BYTE >> 1) & 1)
#define HC1_GET_DESTINATION_PREFIX_COMPRESSED(_BYTE) ((_BYTE >> 2) & 1)
#define HC1_GET_DESTINATION_INTERFACE_IDENTIFIED_COMPRESSED(_BYTE) ( (_BYTE >> 3) & 1)
#define HC1_GET_TRAFFIC_AND_FLOW_LABEL_ZERO(_BYTE) ((_BYTE >> 4) & 1)
#define HC1_GET_NEXT_HEADER(_BYTE) ((_BYTE >> 5) & 3)
#define HC1_GET_ADDITIONAL_HC2_FOLLOWS(_BYTE) ((_BYTE >> 7) & 1)

#define HC1_SET_SOURCE_PREFIX_COMPRESSED(_BYTE, _VAL) _BYTE ^= ((_VAL & 1) ^ _BYTE) & 0X01
#define HC1_SET_SOURCE_INTERFACE_IDENTIFIER_COMPRESSED(_BYTE, _VAL) _BYTE ^= (((_VAL & 1) << 1) ^ _BYTE) & 0X02
#define HC1_SET_DESTINATION_PREFIX_COMPRESSED(_BYTE, _VAL) _BYTE ^= (((_VAL & 1) << 2) ^ _BYTE) & 0X04
#define HC1_SET_DESTINATION_INTERFACE_IDENTIFIED_COMPRESSED(_BYTE, _VAL) _BYTE ^= (((_VAL & 1) << 3) ^ _BYTE) & 0X08
#define HC1_SET_TRAFFIC_AND_FLOW_LABEL_ZERO(_BYTE, _VAL) _BYTE ^= (((_VAL & 1) << 4) ^ _BYTE) & 0X10
#define HC1_SET_NEXT_HEADER(_BYTE, _VAL) _BYTE ^= (((_VAL & 3) << 5) ^ _BYTE) & 0X60
#define HC1_SET_ADDITIONAL_HC2_FOLLOWS(_BYTE, _VAL) _BYTE ^= (((_VAL & 1) << 7) ^ _BYTE) & 0X80

///// LOWPAN_COMPRESSION_HC_06
/*
    Implementation of:
    Compression Format for IPv6 Datagrams in 6LoWPAN Networks
                        draft-ietf-6lowpan-hc-06
    Updated in RFC6282 at: tools.ietf.org/html/rfc6282
*/


#define IPHC_TF_INLINE				0
#define IPHC_TF_ECN_FL				1
#define IPHC_TF_ECD_DSCP			2
#define IPHC_TF_ELIDED				3

#define IPHC_NH_NOTCOMPRESSED		0
#define IPHC_NH_COMPRESSED			1

#define IPHC_HLIM_INLINE			0
#define IPHC_HLIM_1					1
#define IPHC_HLIM_64				2
#define IPHC_HLIM_255				3

//ON SAC = 0
#define IPHC_SAM_128				0
#define IPHC_SAM_64					1
#define IPHC_SAM_16					2
#define IPHC_SAM_0					3

#define IPHC_DAM_128				0
#define IPHC_DAM_64					1
#define IPHC_DAM_16					2
#define IPHC_DAM_0					3

#define IPHC_DAM_00					0
#define IPHC_DAM_01					1
#define IPHC_DAM_10					2
#define IPHC_DAM_11					3

#define IPHC_GET_TF(_BUF) (((GET_BIT(_BUF[0], 4) << 1) | (GET_BIT(_BUF[0], 3))) & 0x03)
#define IPHC_GET_NH(_BUF) (GET_BIT(_BUF[0], 2))
#define IPHC_GET_HLIM(_BUF) ((GET_BIT(_BUF[0], 1) << 1) | GET_BIT(_BUF[0], 0))
#define IPHC_GET_CID(_BUF) (GET_BIT(_BUF[1], 7))
#define IPHC_GET_SAC(_BUF) (GET_BIT(_BUF[1], 6))
#define IPHC_GET_SAM(_BUF) ((GET_BIT(_BUF[1], 5) << 1) | GET_BIT(_BUF[1], 4))
#define IPHC_GET_M(_BUF) (GET_BIT(_BUF[1], 3))
#define IPHC_GET_DAC(_BUF) (GET_BIT(_BUF[1], 2))
#define IPHC_GET_DAM(_BUF) ((GET_BIT(_BUF[1], 1) << 1) | GET_BIT(_BUF[1], 0))

#define IPHC_SET_TF(_BUF, _VAL) (_BUF[0] ^= (((_VAL & 3) << 3) ^ _BUF[0]) & 0X18)
#define IPHC_SET_NH(_BUF, _VAL) (_BUF[0] ^= (((_VAL & 1) << 2) ^ _BUF[0]) & 0X04)
#define IPHC_SET_HLIM(_BUF, _VAL) (_BUF[0] ^= ((_VAL & 3) ^ _BUF[0]) & 0X03)
#define IPHC_SET_CID(_BUF, _VAL) (_BUF[1] ^= (((_VAL & 1) << 7) ^ _BUF[1]) & 0X80)
#define IPHC_SET_SAC(_BUF, _VAL) (_BUF[1] ^= (((_VAL & 1) << 6) ^ _BUF[1]) & 0X40)
#define IPHC_SET_SAM(_BUF, _VAL) (_BUF[1] ^= (((_VAL & 3) << 4) ^ _BUF[1]) & 0X30)
#define IPHC_SET_M(_BUF, _VAL) (_BUF[1] ^= (((_VAL & 1) << 3) ^ _BUF[1]) & 0X08)
#define IPHC_SET_DAC(_BUF, _VAL) (_BUF[1] ^= (((_VAL & 1) << 2) ^ _BUF[1]) & 0X04)
#define IPHC_SET_DAM(_BUF, _VAL) (_BUF[1] ^= ((_VAL & 3) ^ _BUF[1]) & 0X03)



#define IPHC_SET_DISPATCH(_BYTE) (_BYTE[0] ^= (_BYTE[0] ^ 0x60) & 0XE0)
#define IPHC_DISPATCH(_BYTE) ((GET_BIT(_BYTE, 7) ^ 1) && (GET_BIT(_BYTE, 6) & 1) && (GET_BIT(_BYTE, 5) & 1))


#define IPV6_ADDR_MAC_BASED(_ADDR, _MAC_ADDR) ((_ADDR[8]  == _MAC_ADDR[0]) 	&& 	\
											  (_ADDR[9]  == _MAC_ADDR[1]) 	&& 	\
											  (_ADDR[10] == _MAC_ADDR[2]) 	&& 	\
											  (_ADDR[11] == _MAC_ADDR[3]) 	&& 	\
											  (_ADDR[12] == _MAC_ADDR[4]) 	&& 	\
											  (_ADDR[13] == _MAC_ADDR[5]) 	&& 	\
											  (_ADDR[14] == _MAC_ADDR[6]) 	&& 	\
											  (_ADDR[15] == _MAC_ADDR[7]))
#define IPV6_ADDR_IID16_COMPRESSABLE(_ADDR) ((_ADDR[8] == 0) 		&& 	\
										  (_ADDR[9] == 0) 		&& 	\
										  (_ADDR[10] == 0) 		&& 	\
										  (_ADDR[11] == 0xff) 	&& 	\
										  (_ADDR[12] == 0xfe) 	&& 	\
										  (_ADDR[13] == 0))
#define IPV6_ADDR_MCAST_8(_ADDR) ((_ADDR[1] == 2) 	&& 	\
								  (_ADDR[2] == 0)		&& 	\
								  (_ADDR[3] == 0) 	&& 	\
								  (_ADDR[4] == 0) 	&& 	\
								  (_ADDR[5] == 0) 	&& 	\
								  (_ADDR[6] == 0) 	&& 	\
								  (_ADDR[7] == 0) 	&& 	\
								  (_ADDR[8] == 0) 	&& 	\
								  (_ADDR[9] == 0) 	&& 	\
								  (_ADDR[10] == 0) 	&& 	\
								  (_ADDR[11] == 0) 	&& 	\
								  (_ADDR[12] == 0) 	&& 	\
								  (_ADDR[13] == 0) 	&& 	\
								  (_ADDR[14] == 0))
#define IPV6_ADDR_MCAST_32(_ADDR) ((_ADDR[1] == 0)	&& 	\
                                  (_ADDR[2] == 0)	&& 	\
								  (_ADDR[3] == 0) 	&& 	\
								  (_ADDR[4] == 0) 	&& 	\
								  (_ADDR[5] == 0) 	&& 	\
								  (_ADDR[6] == 0) 	&& 	\
								  (_ADDR[7] == 0) 	&& 	\
								  (_ADDR[8] == 0) 	&& 	\
								  (_ADDR[9] == 0) 	&& 	\
								  (_ADDR[10] == 0) 	&& 	\
								  (_ADDR[11] == 0) 	&& 	\
								  (_ADDR[12] == 0))
#define IPV6_ADDR_MCAST_48(_ADDR) ((_ADDR[1] == 0)	&& 	\
                                  (_ADDR[2] == 0)	&& 	\
								  (_ADDR[3] == 0) 	&& 	\
								  (_ADDR[4] == 0) 	&& 	\
								  (_ADDR[5] == 0) 	&& 	\
								  (_ADDR[6] == 0) 	&& 	\
								  (_ADDR[7] == 0) 	&& 	\
								  (_ADDR[8] == 0) 	&& 	\
								  (_ADDR[9] == 0) 	&& 	\
								  (_ADDR[10] == 0))


#if ARCHITECT == BIG_ENDIAN_ARC

#elif ARCHITECT == LITTLE_ENDIAN_ARCH

#define LOWPAN_SET_FLOWLABEL_COMPRESSED(_LPBUF, _IPBUF) ({ _LPBUF[0] = (_IPBUF[1] & 0xc0);	\
														   _LPBUF[1] = _IPBUF[2]; 			\
														   _LPBUF[2] = _IPBUF[3]; })

#endif

#define NHC_UDP_00	0xf0
#define NHC_UDP_01	0xf1
#define NHC_UDP_10	0xf2
#define NHC_UDP_11	0xf3

///compresses IPv6 packet with IPHC compression method
///args:: ipbuf: original IPv6 buffer
///       ipsize: size of IPv6 packet
///       resbuf: pointer to buffer for compressed packet
///       ressize: pointer to uint16_t for size of compressed packet
///NOTE: context based IP address Compression is not supported
void IPHC06Compression(uint8_t* ipbuf, uint16_t ipsize, uint8_t* resbuf, uint16_t* ressize);
void IPHC06Compression(uint8_t* ipbuf, uint16_t ipsize, uint8_t* resbuf, uint16_t* ressize)
{
	uint8_t temp;
	uint8_t iphc[2];

	iphc[0] = 0;
	iphc[1] = 0;

	uint8_t* r = (resbuf + 2);

	IPHC_SET_DISPATCH(iphc);

	temp = IPV6_GET_Traffic_Class(ipbuf);
	temp = (temp >> 2 | ((temp & 0x03) << 6));

	if(IPV6_GET_FLOW_LABLE(ipbuf) == 0)
	{
		if(IPV6_GET_Traffic_Class(ipbuf) == 0)
		{
			IPHC_SET_TF(iphc, IPHC_TF_ELIDED);
		}
		else
		{
			IPHC_SET_TF(iphc, IPHC_TF_ECD_DSCP);

			temp = IPV6_GET_Traffic_Class(ipbuf);
			temp = ((temp << 6) & 0xc0) | ((temp >> 2) & 0x3f);

			(*r) = temp;
			r += 1;
		}
	}
	else
	{
		if(IPV6_GET_Traffic_Class(ipbuf) == 0)
		{
			IPHC_SET_TF(iphc, IPHC_TF_ECN_FL);

			LOWPAN_SET_FLOWLABEL_COMPRESSED(r, ipbuf);
			(*r) = ((IPV6_GET_Traffic_Class(ipbuf) << 6) & 0xc0);

			r += 3;
		}
		else
		{
			IPHC_SET_TF(iphc, IPHC_TF_INLINE);

			temp = IPV6_GET_Traffic_Class(ipbuf);
			temp = ((temp << 6) & 0xc0) | ((temp >> 2) & 0x3f);

			r[0] = temp;
			r[1] = ipbuf[1] & 0x0f;
			r[2] = ipbuf[2];
			r[3] = ipbuf[3];

			r += 4;
		}
	}

	if(IPV6_GET_NEXT_HEADER(ipbuf) == UIP_PROTO_UDP)
	{
		IPHC_SET_NH(iphc, IPHC_NH_COMPRESSED);
	}
	else
	{
		(*r) = IPV6_GET_NEXT_HEADER(ipbuf);
		r += 1;
	}

	if(IPV6_GET_HOP_LIMIT(ipbuf) == 1)
		IPHC_SET_HLIM(iphc, IPHC_HLIM_1);
	else if(IPV6_GET_HOP_LIMIT(ipbuf) == 64)
		IPHC_SET_HLIM(iphc, IPHC_HLIM_64);
	else if(IPV6_GET_HOP_LIMIT(ipbuf) == 255)
		IPHC_SET_HLIM(iphc, IPHC_HLIM_255);
	else
	{
		IPHC_SET_HLIM(iphc, IPHC_HLIM_INLINE);

		(*r) = IPV6_GET_HOP_LIMIT(ipbuf);
		r += 1;
	}


	//SRC
	if(IPV6_ADDR_UNSPECIFIED(IPV6_GET_SRC_ADDR_PTR(ipbuf)))
	{
		IPHC_SET_SAC(iphc, 1);
		IPHC_SET_SAM(iphc, 0);
	}
	//else if(){//contexts are not supported in this version}
	else if( IPV6_ADDR_UNICAST_LINK_LOCAL(IPV6_GET_SRC_ADDR_PTR(ipbuf)) &&
			 IPV6_ADDR_UNICAST_DEST_CONDISION(IPV6_GET_DEST_ADDR_PTR(ipbuf)) )
	{
		if(IPV6_ADDR_MAC_BASED(IPV6_GET_SRC_ADDR_PTR(ipbuf), srcAddr802154))
		{
			IPHC_SET_SAM(iphc, IPHC_SAM_0);
		}
		else if(IPV6_ADDR_IID16_COMPRESSABLE(IPV6_GET_SRC_ADDR_PTR(ipbuf)))
		{
			IPHC_SET_SAM(iphc, IPHC_SAM_16);

			memcpy(r, IPV6_GET_SRC_ADDR_PTR(ipbuf) + 14, 2);
			r += 2;
		}
		else
		{
			IPHC_SET_SAM(iphc, IPHC_SAM_64);

			memcpy(r, IPV6_GET_SRC_ADDR_PTR(ipbuf) + 8, 8);
			r += 8;
		}
	}
	else
	{
		IPHC_SET_SAM(iphc, IPHC_SAM_128);
		IPHC_SET_SAC(iphc, 0);

		memcpy(r, IPV6_GET_SRC_ADDR_PTR(ipbuf), 16);
		r += 16;
	}

	//DEST
	if(IPV6_ADDR_MULTICAST(IPV6_GET_DEST_ADDR_PTR(ipbuf)))
	{
		IPHC_SET_M(iphc, 1);
		if(IPV6_ADDR_MCAST_8(IPV6_GET_DEST_ADDR_PTR(ipbuf)))
		{
			IPHC_SET_DAM(iphc, IPHC_DAM_11);

			(*r) = (IPV6_GET_DEST_ADDR_PTR(ipbuf))[15];
			r += 1;
		}
		else if(IPV6_ADDR_MCAST_32(IPV6_GET_DEST_ADDR_PTR(ipbuf)))
		{
			IPHC_SET_DAM(iphc, IPHC_DAM_10);

			memcpy(r, IPV6_GET_DEST_ADDR_PTR(ipbuf) + 12, 4);
			r += 4;
		}
		else if(IPV6_ADDR_MCAST_48(IPV6_GET_DEST_ADDR_PTR(ipbuf)))
		{
			IPHC_SET_DAM(iphc, IPHC_DAM_01);

			memcpy(r, IPV6_GET_DEST_ADDR_PTR(ipbuf) + 10, 6);
			r += 6;
		}
		else
		{
			IPHC_SET_DAM(iphc, IPHC_DAM_00);

			memcpy(r, IPV6_GET_DEST_ADDR_PTR(ipbuf), 16);
			r += 16;
		}
	}
	else //if addr is not multicast
	{
		//if(//context are not supported in this version) else
		if(IPV6_ADDR_UNICAST_LINK_LOCAL(IPV6_GET_DEST_ADDR_PTR(ipbuf)) &&
			IPV6_ADDR_UNICAST_DEST_CONDISION(IPV6_GET_DEST_ADDR_PTR(ipbuf)) )
		{
			if(IPV6_ADDR_MAC_BASED(IPV6_GET_DEST_ADDR_PTR(ipbuf), destAddr802154))
			{
				IPHC_SET_DAM(iphc, IPHC_DAM_0);
			}
			else if(IPV6_ADDR_IID16_COMPRESSABLE(IPV6_GET_DEST_ADDR_PTR(ipbuf)))
			{
				IPHC_SET_DAM(iphc, IPHC_DAM_16);

				memcpy(r, IPV6_GET_DEST_ADDR_PTR(ipbuf) + 14, 2);
				r += 2;
			}
			else
			{
				IPHC_SET_DAM(iphc, IPHC_DAM_64);

				memcpy(r, IPV6_GET_DEST_ADDR_PTR(ipbuf) + 8, 8);
				r += 8;
			}
		}
		else
		{
			IPHC_SET_DAM(iphc, IPHC_DAM_00);

			memcpy(r, IPV6_GET_DEST_ADDR_PTR(ipbuf), 16);
			r += 16;
		}
	}

	temp = 0;
	//UDP COMPRESSION
	if(IPV6_GET_NEXT_HEADER(ipbuf) == UIP_PROTO_UDP)
	{
		if(((IPV6_UDP_GET_SRC_PORT(ipbuf) & 0xfff0) == 0xf0b0) && ((IPV6_UDP_GET_DEST_PORT(ipbuf) & 0xfff0) == 0xf0b0))
		{
			(*r) = NHC_UDP_11;
			(*(r + 1)) = (uint8_t) (((IPV6_UDP_GET_SRC_PORT(ipbuf) & 0x0f) << 4) | (IPV6_UDP_GET_DEST_PORT(ipbuf) & 0x0f));

			r += 2;
		}
		else if((IPV6_UDP_GET_DEST_PORT(ipbuf) & 0xff00) == 0xf000)
		{
			(*r) = NHC_UDP_01;
			SET16(r, 1, IPV6_UDP_GET_SRC_PORT(ipbuf));
			(*(r + 3)) = (uint8_t) (IPV6_UDP_GET_DEST_PORT(ipbuf) & 0xff);

			r += 4;
		}
		else if(((IPV6_UDP_GET_SRC_PORT(ipbuf) & 0xff00) == 0xf000))
		{
			(*r) = NHC_UDP_10;
			(*(r + 1)) = (uint8_t) (IPV6_UDP_GET_SRC_PORT(ipbuf) & 0xff);
			SET16(r, 2, IPV6_UDP_GET_DEST_PORT(ipbuf));

			r += 4;
		}
		else
		{
			(*r) = NHC_UDP_00;
			SET16(r, 1, IPV6_UDP_GET_SRC_PORT(ipbuf));
			SET16(r, 3, IPV6_UDP_GET_DEST_PORT(ipbuf));

			r += 5;
		}
		temp = 8;
	}

	//checksum inline
	SET16(r, 0, IPV6_UDP_GET_CHECKSUM(ipbuf));
	r += 2;

	resbuf[0] = iphc[0];
	resbuf[1] = iphc[1];

	(*ressize) = ipsize - 40 - temp;

	//copy payload
	memcpy(r, ipbuf + 40 + temp, *ressize);

	(*ressize) += r - resbuf;

}

///this is the opposite of IPHC06 Compression
///args:: buf: compressed packet buffer
///       bsize: size of compressed packet
///       resbuf: pointer to the buffer for uncompressed packet
///       rsize: pointer to uint16_t for size of uncompressed packet
///NOTE: context based IP address Decompression is not supported
void IPHC06Decompression(uint8_t* buf, uint16_t bsize, uint8_t* resbuf, uint16_t* rsize);
void IPHC06Decompression(uint8_t* buf, uint16_t bsize, uint8_t* resbuf, uint16_t* rsize)
{
	uint8_t iphc[2];
	uint8_t temp;

	iphc[0] = buf[0];
	iphc[1] = buf[1];

	uint8_t* r = buf + 2;
	(*rsize) = 0;

	if(IPHC_GET_CID(iphc))
		return; //Contexts are not supported yet

	IPV6_SET_VERSION(resbuf, 6);
	if(IPHC_GET_TF(iphc) == IPHC_TF_ELIDED) //elided
	{
		IPV6_SET_FLOW_LABLE(resbuf, 0);
		IPV6_SET_Traffic_Class(resbuf, 0);
	}
	else if(IPHC_GET_TF(iphc) == IPHC_TF_ECN_FL) //flow label inline
	{
		IPV6_SET_FLOW_LABLE(resbuf, (((r[0] << 16) | (r[1] << 8) | r[2]) & 0x000fffff));
		IPV6_SET_Traffic_Class(resbuf, 0);

		r += 3;
	}
	else if(IPHC_GET_TF(iphc) == IPHC_TF_ECD_DSCP) //traffic class inline
	{
		temp = (*r);
		temp = (((temp & 0xc0) >> 6) | ((temp & 0x3f) << 2));

		IPV6_SET_Traffic_Class(resbuf, temp);

		r += 1;
	}
	else if(IPHC_GET_TF(iphc) == IPHC_TF_INLINE) //both inline
	{
		temp = (*r);
		temp = (((temp & 0xc0) >> 6) | ((temp & 0x3f) << 2));

		IPV6_SET_Traffic_Class(resbuf, temp);
		IPV6_SET_FLOW_LABLE(resbuf, (((r[1] << 16) | (r[2] << 8) | r[3]) & 0x000fffff));

		r += 4;
	}

	if(IPHC_GET_NH(iphc) == IPHC_NH_NOTCOMPRESSED)
	{
		IPV6_SET_NEXT_HEADER(resbuf, (*r));
		r += 1;
	}

	switch(IPHC_GET_HLIM(iphc))
	{
		case IPHC_HLIM_1:
			IPV6_SET_HOP_LIMIT(resbuf, 1);
		break;
		case IPHC_HLIM_64:
			IPV6_SET_HOP_LIMIT(resbuf, 64);
		break;
		case IPHC_HLIM_255:
			IPV6_SET_HOP_LIMIT(resbuf, 255);
		break;
		case IPHC_HLIM_INLINE:
		{
			IPV6_SET_HOP_LIMIT(resbuf, (*r));

			r += 1;
		}
		break;
	}


	//SRC
	if(IPHC_GET_SAC(iphc) == 1 && IPHC_GET_SAM(iphc) == 0)
	{
		// ip is unspecified
		memset(IPV6_GET_SRC_ADDR_PTR(resbuf), 0, 16);
	}
	//else if(){//contexts are not supported in this version}
	else if(IPHC_GET_SAC(iphc) == 0)
	{
		(IPV6_GET_SRC_ADDR_PTR(resbuf))[0] = 0xfe; //link local
		(IPV6_GET_SRC_ADDR_PTR(resbuf))[1] = 0x80;
		memset(IPV6_GET_SRC_ADDR_PTR(resbuf) + 2, 0, 14); //zero padding

		if(IPHC_GET_SAM(iphc) == IPHC_SAM_0)
		{
			memcpy(&((IPV6_GET_SRC_ADDR_PTR(resbuf))[8]), srcAddr802154, 8);
			((IPV6_GET_SRC_ADDR_PTR(resbuf))[8]) ^= 0x02;
		}
		else if(IPHC_GET_SAM(iphc) == IPHC_SAM_16)
		{
			(IPV6_GET_SRC_ADDR_PTR(resbuf))[11] = 0xff;
			(IPV6_GET_SRC_ADDR_PTR(resbuf))[12] = 0xfe;

			memcpy(IPV6_GET_SRC_ADDR_PTR(resbuf) + 14, r, 2);
			r += 2;
		}
		else if(IPHC_GET_SAM(iphc) == IPHC_SAM_64)
		{
			memcpy(IPV6_GET_SRC_ADDR_PTR(resbuf) + 8, r, 8);
			r += 8;
		}
		else if(IPHC_GET_SAM(iphc) == IPHC_SAM_128)
		{
			memcpy(IPV6_GET_SRC_ADDR_PTR(resbuf), r, 16);
			r += 16;
		}
	}

	//DEST
	if(IPHC_GET_M(iphc) == 1)
	{
		memset(IPV6_GET_DEST_ADDR_PTR(resbuf), 0, 16);
		(IPV6_GET_DEST_ADDR_PTR(resbuf))[0] = 0xff;

		if(IPHC_GET_DAM(iphc) == IPHC_DAM_11) // mcast 8 compressed
		{
			(IPV6_GET_DEST_ADDR_PTR(resbuf))[1] = 0x02;
			(IPV6_GET_DEST_ADDR_PTR(resbuf))[15] = (*r);

			r += 1;
		}
		else if(IPHC_GET_DAM(iphc) == IPHC_DAM_10) // mcast 32 compressed
		{
			(IPV6_GET_DEST_ADDR_PTR(resbuf))[1] = r[0];
			(IPV6_GET_DEST_ADDR_PTR(resbuf))[13] = r[1];
			(IPV6_GET_DEST_ADDR_PTR(resbuf))[14] = r[2];
			(IPV6_GET_DEST_ADDR_PTR(resbuf))[15] = r[3];

			r += 4;
		}
		else if(IPHC_GET_DAM(iphc) == IPHC_DAM_01) // mcast 48 compressed
		{
			(IPV6_GET_DEST_ADDR_PTR(resbuf))[1] = r[0];
			(IPV6_GET_DEST_ADDR_PTR(resbuf))[11] = r[1];
			(IPV6_GET_DEST_ADDR_PTR(resbuf))[12] = r[2];
			(IPV6_GET_DEST_ADDR_PTR(resbuf))[13] = r[3];
			(IPV6_GET_DEST_ADDR_PTR(resbuf))[14] = r[4];
			(IPV6_GET_DEST_ADDR_PTR(resbuf))[15] = r[5];

			r += 6;
		}
		else if(IPHC_GET_DAM(iphc) == IPHC_DAM_00) // mcast 128 compressed
		{
			memcpy(IPV6_GET_DEST_ADDR_PTR(resbuf), r, 16);
			r += 16;
		}
	}
	else //if addr is not multicast
	{
		(IPV6_GET_DEST_ADDR_PTR(resbuf))[0] = 0xfe; //link local
		(IPV6_GET_DEST_ADDR_PTR(resbuf))[1] = 0x80;
		memset(IPV6_GET_DEST_ADDR_PTR(resbuf) + 2, 0, 14); //zero padding

		//if(//context is not supported in this version) else
		if(IPHC_GET_DAC(iphc) == 0)
		{
			if(IPHC_GET_DAM(iphc) == IPHC_DAM_0)
			{
				memcpy(&((IPV6_GET_DEST_ADDR_PTR(resbuf))[8]), destAddr802154, 8);
				(IPV6_GET_DEST_ADDR_PTR(resbuf))[8] ^= 0x02;
			}
			else if(IPHC_GET_DAM(iphc) == IPHC_DAM_16)
			{
				(IPV6_GET_DEST_ADDR_PTR(resbuf))[11] = 0xff;
				(IPV6_GET_DEST_ADDR_PTR(resbuf))[12] = 0xfe;

				memcpy(IPV6_GET_DEST_ADDR_PTR(resbuf) + 14, r, 2);
				r += 2;
			}
			else if(IPHC_GET_DAM(iphc) == IPHC_DAM_64)
			{
				memcpy(IPV6_GET_DEST_ADDR_PTR(resbuf) + 8, r, 8);
				r += 8;
			}
			else if(IPHC_GET_DAM(iphc) == IPHC_DAM_128)
			{
				memcpy(IPV6_GET_DEST_ADDR_PTR(resbuf), r, 16);
				r += 16;
			}
		}
	}

	//udp
	if(IPHC_GET_NH(iphc) == IPHC_NH_COMPRESSED)
	{
		if(((*r) & 0xf8) == 0xf0)
		{
			IPV6_SET_NEXT_HEADER(resbuf, UIP_PROTO_UDP);

			temp = (*r) & 0x04;
			(*r) &= 0xfb;

			if((*r) == NHC_UDP_11)
			{
				IPV6_UDP_SET_SRC_PORT(resbuf, ((((*(r + 1)) >> 4) & 0x0f) | 0xf0b0));
				IPV6_UDP_SET_DEST_PORT(resbuf, (((*(r + 1)) & 0x0f) | 0xf0b0));
				r += 2;
			}
			else if((*r) == NHC_UDP_10)
			{
				IPV6_UDP_SET_SRC_PORT(resbuf, (((*(r + 1 )) & 0xff) | 0xf000));
				IPV6_UDP_SET_DEST_PORT(resbuf, GET16(r, 2));

				r += 4;
			}
			else if((*r) == NHC_UDP_01)
			{
				IPV6_UDP_SET_SRC_PORT(resbuf, GET16(r, 1));
				IPV6_UDP_SET_DEST_PORT(resbuf, (((*(r + 3 )) & 0xff) | 0xf000));

				r += 4;
			}
			else
			{
				IPV6_UDP_SET_SRC_PORT(resbuf, GET16(r, 1));
				IPV6_UDP_SET_DEST_PORT(resbuf, GET16(r, 3));

				r += 5;
			}

			if(temp)
				return; //we don't compress the checksum

			IPV6_UDP_SET_CHECKSUM(resbuf, GET16(r, 0));
			r += 2;

			temp = 8;
		}
	}

	uint16_t len = bsize - (r - buf) + temp;

	IPV6_UDP_SET_LENGTH(resbuf, len);
	IPV6_SET_PAYLOAD_LENGTH(resbuf, len);

	//copy payload
	memcpy((resbuf + 40 + temp), r, (len - temp));

	(*rsize) = len + 40;

}

/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////

//compression mode types
typedef enum compressionMode
{
	IPHC06 = 0,
	HC1 = 1,
	NOCOMPRESSION = 2
} compressionMode;

//changing this global variable will cause switching betweeen compression methods
compressionMode comMode;

void init_lowPANcompression(void);
void init_lowPANcompression()
{
	comMode = IPHC06; //default mode
}
void finalize_lowPANcompression(void);
void finalize_lowPANcompression()
{
}

///the handle function for user! you should call this function from outside
///args:: ipbuf: original IPv6 buffer
///       ipsize: size of IPv6 packet
///       resbuf: pointer to buffer for compressed packet
///       ressize: pointer to uint16_t for size of compressed packet
void compress(uint8_t* ipbuf, uint16_t ipsize, uint8_t* resbuf, uint16_t* ressize);
void compress(uint8_t* ipbuf, uint16_t ipsize, uint8_t* resbuf, uint16_t* ressize)
{
	switch(comMode)
	{
		case NOCOMPRESSION:
		{
		    resbuf[0] = 0x41; //setting the dispatch of uncompressed IPv6
            memcpy(&resbuf[1], ipbuf, ipsize);
            (*ressize) = ipsize + 1;
		}break;
		case IPHC06:
		{
			IPHC06Compression(ipbuf, ipsize, resbuf, ressize);
		}break;
		case HC1:
		{

		}break;
		default:
		{

		}
	}
}

///opposite of compress function
///args:: buf: compressed packet buffer
///       bsize: size of compressed packet
///       resbuf: pointer to the buffer for uncompressed packet
///       rsize: pointer to uint16_t for size of uncompressed packet
void uncompress(uint8_t* buf, uint16_t bsize, uint8_t* resbuf, uint16_t* rsize);
void uncompress(uint8_t* buf, uint16_t bsize, uint8_t* resbuf, uint16_t* rsize)
{
	switch(comMode)
	{
		case NOCOMPRESSION:
		{
            if(buf[0] == 0x41)  //if it is a ipv6 packet
            {
                *rsize = bsize - 1;
                memcpy(resbuf, &buf[1], (*rsize));
            }
		}break;
		case IPHC06:
		{
			IPHC06Decompression(buf, bsize, resbuf, rsize);
		}break;
		case HC1:
		{

		}break;
		default:
		{

		}
	}
}

#endif
