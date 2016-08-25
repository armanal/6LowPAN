
#ifndef IPV6_HEADER
#define IPV6_HEADER

#include "types.h"

//IP get data
#if ARCHITECT == BIG_ENDIAN_ARC

#elif ARCHITECT == LITTLE_ENDIAN_ARCH

#define IPV6_GET_VERSION(_BUF) ((_BUF[0] >> 4) & 0x0f)
#define IPV6_GET_Traffic_Class(_BUF) (((_BUF[0] << 4) & 0xf0) | ((_BUF[1] >> 4) & 0x0f))
#define IPV6_GET_FLOW_LABLE(_BUF) (((uint32_t)(_BUF[1] << 16 | _BUF[2] << 8 | _BUF[3])) & 0x000fffff)
#define IPV6_GET_PAYLOAD_LENGTH(_BUF) ((uint16_t) (_BUF[4] << 8 | _BUF[5]))
#define IPV6_GET_NEXT_HEADER(_BUF) (_BUF[6])
#define IPV6_GET_HOP_LIMIT(_BUF) (_BUF[7])


#define IPV6_SET_VERSION(_BUF, _VAL) (_BUF[0] ^= ((_VAL << 4) ^ _BUF[0]) & 0xf0)
#define IPV6_SET_Traffic_Class(_BUF, _VAL) ({ _BUF[0] ^= (((_VAL >> 4) ^ _BUF[0]) & 0x0f); 		\
										 _BUF[1] ^= ((_VAL ^ _BUF[1]) & 0xf0); })
#define IPV6_SET_FLOW_LABLE(_BUF, _VAL) ({ _BUF[1] ^= ((((_VAL >> 16) & 0x0f) ^ _BUF[1]) & 0x0f);\
                                           _BUF[2] = ((_VAL >>8) & 0xff);						 \
                                           _BUF[3] = (_VAL & 0xff); })
#define IPV6_SET_PAYLOAD_LENGTH(_BUF, _VAL) ({ _BUF[4] = ((_VAL >> 8) & 0xff);					\
                                               _BUF[5] = (_VAL & 0xff); })
#define IPV6_SET_NEXT_HEADER(_BUF, _VAL) (_BUF[6] = _VAL)
#define IPV6_SET_HOP_LIMIT(_BUF, _VAL) (_BUF[7] = _VAL)


#define IPV6_GET_SRC_ADDR_PTR(_BUF) (_BUF + 8)
#define IPV6_GET_DEST_ADDR_PTR(_BUF) (_BUF + 24)
#define IPV6_SET_SRC_ADDR(_BUF, _ADDR) ({ uint8_t* buf = IPV6_GET_SRC_ADDR_PTR(_BUF); \
										  int i;									  \
										  for(i = 0; i < 16; i++)				  	  \
										  	buf[i] = _ADDR.a[i];  })
#define IPV6_GET_SRC_ADDR(_BUF, _ADDR) ({ uint8_t* buf = IPV6_GET_SRC_ADDR_PTR(_BUF); \
										  int i;									  \
										  for(i = 0; i < 16; i++)				  	  \
										  	_ADDR.a[i] = buf[i]; })
#define IPV6_SET_DEST_ADDR(_BUF, _ADDR) ({ uint8_t* buf = IPV6_GET_DEST_ADDR_PTR(_BUF); \
										  int i;									  	\
										  for(i = 0; i < 16; i++)				  	  	\
										  	buf[i] = _ADDR.a[i];  })
#define IPV6_GET_DEST_ADDR(_BUF, _ADDR) ({ uint8_t* buf = IPV6_GET_DEST_ADDR_PTR(_BUF); \
										  int i;									  	\
										  for(i = 0; i < 16; i++)				  	  	\
										  	_ADDR.a[i] = buf[i];  })

#endif

#define IPV6_ADDR_UNSPECIFIED(_ADDR) ((_ADDR[0] == 0) 	&& 	\
									  (_ADDR[1] == 0) 	&& 	\
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
									  (_ADDR[14] == 0) 	&& 	\
									  (_ADDR[15] == 0))
#define IPV6_ADDR_UNICAST_LINK_LOCAL(_ADDR) ( (_ADDR[0] == 0xfe) 	&&	\
											  (_ADDR[1] == 0x80))
#define IPV6_ADDR_UNICAST_DEST_CONDISION(_ADDR) ((_ADDR[2] == 0) 	&& 	\
                                              (_ADDR[3] == 0) 	&& 	\
											  (_ADDR[4] == 0) 	&& 	\
											  (_ADDR[5] == 0) 	&& 	\
											  (_ADDR[6] == 0) 	&& 	\
											  (_ADDR[7] == 0))
#define IPV6_ADDR_MULTICAST(_ADDR) ((_ADDR[0] == 0xff))


#define UIP_PROTO_ICMP  1
#define UIP_PROTO_TCP   6
#define UIP_PROTO_UDP   17
#define UIP_PROTO_ICMP6 58

typedef struct ip6Addr_t
{
	uint8_t a[16];
} ip6Addr_t;

//udp
#define IPV6_UDP_GET_SRC_PORT(_BUF) (GET16(_BUF, 40))
#define IPV6_UDP_GET_DEST_PORT(_BUF) (GET16(_BUF, 42))
#define IPV6_UDP_GET_LENGTH(_BUF) (GET16(_BUF, 44))
#define IPV6_UDP_GET_CHECKSUM(_BUF) (GET16(_BUF, 46))

#define IPV6_UDP_SET_SRC_PORT(_BUF, _VAL) (SET16(_BUF, 40, _VAL))
#define IPV6_UDP_SET_DEST_PORT(_BUF, _VAL) (SET16(_BUF, 42, _VAL))
#define IPV6_UDP_SET_LENGTH(_BUF, _VAL) (SET16(_BUF, 44, _VAL))
#define IPV6_UDP_SET_CHECKSUM(_BUF, _VAL) (SET16(_BUF, 46, _VAL))

uint8_t stn(char n);
uint8_t stn(char n)
{
    switch(n)
    {
        case '0':
            return 0;
        case '1':
            return 1;
        case '2':
            return 2;
        case '3':
            return 3;
        case '4':
            return 4;
        case '5':
            return 5;
        case '6':
            return 6;
        case '7':
            return 7;
        case '8':
            return 8;
        case '9':
            return 9;
        case 'a':
            return 10;
        case 'b':
            return 11;
        case 'c':
            return 12;
        case 'd':
            return 13;
        case 'e':
            return 14;
        case 'f':
            return 15;
    }
    return 20;
}

void setipv6addr(char* as, ip6Addr_t* ad);
void setipv6addr(char* as, ip6Addr_t* ad)
{
    int i = strlen(as) -1;
    int c = 0;
    int l = 15;
    uint16_t temp = 0;
    int a = 0;

    while( i >= -1 && l >= 0)
    {
        if(as[i] == ':' || c > 0)
        {
            (*ad).a[l] = temp & 0xff;
            l--;
            (*ad).a[l] = (temp >> 8) & 0xff;

            c = 0;
            l--;
            temp = 0;
            i--;
        }
        else
        {
            for(; i >= 0 && c <= 3 && as[i] != ':'; c++, i--)
            {
                a = (stn(as[i]) & 0xf);
                temp |= ((stn(as[i]) & 0xf) << (c * 4));
            }
        }
    }
}

//////////////////////////////////////////////////////////////////////////////////
#endif
