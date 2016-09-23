#ifndef SIXLOWPAN_FRAGMENTATION
#define SIXLOWPAN_FRAGMENTATION

#ifndef FREEBSD
#include <string.h>
#include <time.h>
#include <math.h>
#else
#endif

#include "utilities.h"
#include "types.h"
#include "MAC.h"


/*  -----------------------------------------------------------
    6lowpan packet header types pattern detection macros
    -----------------------------------------------------------  */
/// - Not a LoWPAN frame
#define NALP(_FIRST_BYTE) ((GET_BIT(_FIRST_BYTE, 7) ^ 1) & (GET_BIT(_FIRST_BYTE, 6) ^ 1))  //0x00xxxxxx

/// - Uncompressed IPv6 Addresses
#define UIPv6(_FIRST_BYTE) (_FIRST_BYTE == 0x41 ? 1 : 0)  //0x01000001

/// - LOWPAN_IPHC compressed IPv6
#define IPHC(_FIRST_BYTE) (IPHC_DISPATCH(_FIRST_BYTE))

/// - LOWPAN_HC1 compressed IPv6
#define LOWPAN_HC1(_FIRST_BYTE) (_FIRST_BYTE == 0x42 ? 1 : 0)  //0x01000010

/// - LOWPAN_BC0 broadcast
#define LOWPAN_BC0(_FIRST_BYTE) (_FIRST_BYTE == 0x50 ? 1 : 0)  //0x01010000

/// - Additional Dispatch byte follows
#define ESC(_FIRST_BYTE) (_FIRST_BYTE == 0x7f ? 1 : 0)  //0x01111111

/// - Mesh Header
#define MESH(_FIRST_BYTE) (GET_BIT(_FIRST_BYTE, 7) && (GET_BIT(_FIRST_BYTE, 6) ^ 1))  //0x10xxxxxx

/// - Fragmentation Header (first)
#define FRAG1(_FIRST_BYTE) (GET_BIT(_FIRST_BYTE, 7) && GET_BIT(_FIRST_BYTE, 6) && (GET_BIT(_FIRST_BYTE, 5) ^ 1) && (GET_BIT(_FIRST_BYTE, 4) ^ 1) && (GET_BIT(_FIRST_BYTE, 3) ^ 1)) //0x11000xxx

/// - Fragmentation Header (subsequent)
#define FRAGN(_FIRST_BYTE) (GET_BIT(_FIRST_BYTE, 7) && GET_BIT(_FIRST_BYTE, 6) && GET_BIT(_FIRST_BYTE, 5) && (GET_BIT(_FIRST_BYTE, 4) ^ 1) && (GET_BIT(_FIRST_BYTE, 3) ^ 1)) //0x11100xxx

///   End of Patern detection Macros   ////////////////////////
///////////////////////////////////////////////////////////////

/*  -------------------------------------------------------------------
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
	|1 1 1 0 0|    datagram_size    |         datagram_tag          | |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
	|datagram_offset|                                                 |
	+-+-+-+-+-+-+-+-+                                                 |
    -------------------------------------------------------------------  */
///  max fragment size is 127B - minimume of frag hdr which is 4B
#ifndef FRAME_SIZE
#define FRAME_SIZE 128
#endif // FRAME_SIZE

#ifndef MAX_FRAG_SIZE
	#ifdef MAC_MAX_PAYLOAD_LENGTH
		#define MAX_FRAG_SIZE MAC_MAX_PAYLOAD_LENGTH
	#else
		#define MAX_FRAG_SIZE 117
	#endif // MAC_MAX_PAYLOAD_LENGTH
#endif // MAX_FRAG_SIZE

#ifndef MAX_IP_SIZE
#define MAX_IP_SIZE 2048
#endif // MAX_IP_SIZE

#define CREATE_IP_BUFFER(_PTR, _LEN) do{                                                            \
                                        _PTR = (uint8_t*) malloc(sizeof(uint8_t) * MAX_IP_SIZE);    \
                                        _LEN = MAX_IP_SIZE;                                         \
                                       }while(0)
#define DESTRUCT_IP_BUFFER(_PTR) free((void*)_PTR);

static uint8_t* IPv6_buf;
static uint16_t IPv6_length;

//last sent packet tag: increment with macro for current packet
//Note: do not use this directly but only through GET_PACKET_TAG macro
static uint16_t Sending_Packet_TAG;
static uint8_t* Sending_buf;
static uint16_t Sending_length;
static uint16_t Sending_sent_offset;

#ifndef FREEBSD
static clock_t Sending_Start_Time;

#ifndef TIMER_MS_INTERVALS
#define TIMER_MS_INTERVALS (30000) //ms = 30 seconds
#endif // TIMER_MS_INTERVALS

#define RESET_TIMER(_CLK) (_CLK = clock())
#define ELAPSED_TIMER(_CLK) ({                                                                                              \
                              bool_t f;                                                                                       \
                              if((fabs(clock()-_CLK) * (1000 / CLOCKS_PER_SEC)) >= TIMER_MS_INTERVALS) f = TRUE;   \
                              else f = FALSE;                                                                               \
                              f;                                                                                            \
                             })
#endif

///Packet Tag Incrementation for assigning to current packet
#define GET_NEXT_PACKET_TAG (Sending_Packet_TAG == UINT16_MAX ? Sending_Packet_TAG = 0 : ++Sending_Packet_TAG)
#define GET_PACKET_TAG (Sending_Packet_TAG)

#define RESET_SEND  do{                             \
                    Sending_buf = IPv6_buf;         \
                    Sending_length = IPv6_length;   \
                    Sending_sent_offset = 0;        \
                    GET_NEXT_PACKET_TAG;            \
                    }while(0)
///set dispatch and size (see rfc 4944) in frag buffer
///args:: _PTR: pointer to frag buffer
///        _SIZE: (uint16_t) size of frag payload
#define SET_FRAG1_DATAGRAM_SIZE(_PTR, _SIZE) do{if(!(_SIZE > MAX_IP_SIZE)){ SET16(_PTR, 0, ((_SIZE & 0x07ff) | 0xc000));}}while(0)
#define SET_FRAGN_DATAGRAM_SIZE(_PTR, _SIZE) do{if(!(_SIZE > MAX_IP_SIZE)){ SET16(_PTR, 0, ((_SIZE & 0x07ff) | 0xe000));}}while(0)

///set datagram tag in frag buffer
///arg:: _PTR: pointer to frag buffer
#define SET_DATAGRAM_TAG(_PTR) SET16(_PTR, 2, GET_PACKET_TAG)

///set's the offset of frag from begining of original IP paket
///for more detailes see: rfc 4944
///args:: _PTR: pointer to frag buffer
///       _OFFSET: *see rfc 4944
#define SET_DATAGRAM_OFFSET(_PTR, _OFFSET) (_PTR[4] = _OFFSET)

///read data from frag buffer
///args:: _PTR: pointer to frag buffer
///return type of uint16_t
#define GET_FRAG_DATAGRAM_SIZE(_PTR) (GET16(_PTR, 0) & 0x07ff)
#define GET_FRAG_DATAGRAM_TAG(_PTR) (GET16(fragment, 2))
///return type of uint8_t
#define GET_DATAGRAM_OFFSET(_PTR) ((_PTR)[4])

#define FRAG1_PAYLOAD_PTR(_PTR) (&(_PTR)[4])
#define FRAGN_PAYLOAD_PTR(_PTR) (&(_PTR)[5])

void init_frag(void);
void init_frag()
{
    //CREATE_IP_BUFFER(IPv6_buf, IPv6_length);

    Sending_buf = IPv6_buf;
    Sending_length = IPv6_length;
    Sending_Packet_TAG = 0;
    Sending_sent_offset = 0;
}

void finalize_frag(void);
void finalize_frag()
{
    //DESTRUCT_IP_BUFFER(IPv6_buf)
}

///take's a buffer and it's size and use it as output buffer
///args:: buf: pointer to buffer
///       len: size of buffer (valid part if buffer is large)
uint8_t setSendIPpacket(uint8_t* buf, uint16_t len);
uint8_t setSendIPpacket(uint8_t* buf, uint16_t len)
{
    if(len > MAX_IP_SIZE)
        return 2;
    IPv6_length = len;
    IPv6_buf = buf; //memcpy(IPv6_buf,buf,len);
    RESET_SEND;
#ifndef FREEBSD
    RESET_TIMER(Sending_Start_Time);
#endif
    return 1;
}


///cut's next frag from output buffer into next fragment. take *resFragLen
///as maxumum expected frag size for next fragment. return 0 if extra fragments are 
///remaining, 1 if fragmentation of current buffer is completed and 2 for error
///args:: resFragBuf: pointer to frag buffer
///       resFragLen: pointer variable containing the size of next frag
///                   after execution it wiil contain actual size of frag
uint8_t LoWPAN_nextFrag(uint8_t* resFragBuf, uint8_t* resFragLen);
uint8_t LoWPAN_nextFrag(uint8_t* resFragBuf, uint8_t* resFragLen)
{
    if((*resFragLen) <= 5 || (*resFragLen) > MAX_FRAG_SIZE)
        return 2;   //2 for error
#ifndef FREEBSD
    if(ELAPSED_TIMER(Sending_Start_Time))
		return 2;	//2 for error
#endif

    uint8_t fraglen = (*resFragLen);
    if(Sending_sent_offset == 0)
    {
       if(Sending_length <= (*resFragLen)) //we dont need fragmentation
       {
           memcpy(resFragBuf, Sending_buf, Sending_length);
           Sending_sent_offset = Sending_length;
           (*resFragLen) = Sending_length;

           NoFramePending802154;

           return 0;
       }
       else
       {
       		framePending802154;
       }

        SET_FRAG1_DATAGRAM_SIZE(resFragBuf, Sending_length);
        SET_DATAGRAM_TAG(resFragBuf);
        fraglen-=4;

        //offset must increment in multiples of 8 octets (see rfc 4944)
		//this causes result fragment size to be exactly multiples of 8 octets
		fraglen /= 8;
		fraglen *= 8;

		if(fraglen >= Sending_length)
		{
			fraglen = Sending_length;
			memcpy(&resFragBuf[4], &Sending_buf[Sending_sent_offset], fraglen);
			Sending_sent_offset += fraglen;
		}
		else
        {
            memcpy(&resFragBuf[4], &Sending_buf[Sending_sent_offset], fraglen);
            Sending_sent_offset += fraglen;
        }

		if(fraglen+4 < (*resFragLen))
            (*resFragLen) = fraglen+4;

		return 0;
    }
    else
    {
        SET_FRAGN_DATAGRAM_SIZE(resFragBuf, Sending_length);
        SET_DATAGRAM_TAG(resFragBuf);
        SET_DATAGRAM_OFFSET(resFragBuf, Sending_sent_offset / 8);
        fraglen -= 5;

        //offset must increment in multiples of 8 octets (see rfc 4944)
		//this causes result fragment size to be exactly multiples of 8 octets
		fraglen /= 8;
		fraglen *= 8;

		if(Sending_sent_offset == Sending_length)
            return 1;

        if(fraglen+Sending_sent_offset >= Sending_length)
		{
			fraglen = Sending_length - Sending_sent_offset;
			memcpy(&resFragBuf[5], &Sending_buf[Sending_sent_offset], fraglen);
			Sending_sent_offset += fraglen;

		}
		else
		{
            memcpy(&resFragBuf[5], &Sending_buf[Sending_sent_offset], fraglen);
            Sending_sent_offset += fraglen;
		}

		if(fraglen+5 < (*resFragLen))
            (*resFragLen) = fraglen+5;

		return 0;
    }
}

////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////

//6LoWPAN reassembling buffer and status info holder
typedef struct
{
	//if this buffer is in use it should set to true
	//and free buffer by setting it to false
	bool_t inUse;

    //clock_t timer;
	//11-bit entier IP packet length before fragmentation
	uint16_t size;
	//reassembled size
	uint16_t ra_size;
	//datagram tag
	uint16_t tag;
	//Packet reassembling buffer in max size
	uint8_t buffer[MAX_IP_SIZE];
} LoWPAN_RA_info;


///  for first fragment offset is zero
typedef struct
{
	//11-bit actual number stored here in a 16-bit uint
	uint16_t size;
	//datagram tag
	uint16_t tag;
	//datagram offset: this specify offset increments in multiples of eight
	uint8_t offset;
	//data payload len
	uint8_t len;
	//have no idea about this
	uint8_t data[MAX_FRAG_SIZE];
} LoWPAN_frag_t;

//NUMBER OF SIMULTANEOUS INPUT REASSEMBLY BUFFERS
#ifndef STACK_BUFFERS_NUM
#define STACK_BUFFERS_NUM 10
#endif // STACK_BUFFERS_NUM

#define RA_BUFFER_ALLOC(_BUF, _TAG) do{                             \
                                        (_BUF).inUse = TRUE;        \
                                        (_BUF).ra_size = 0;         \
                                        (_BUF).size = 0;            \
                                        (_BUF).tag = _TAG;          \
                                    }while(0)
#ifndef FREEBSD
#define RA_BUFFER_DEALLOC(_BUF) do{                             \
                                    (_BUF).inUse = FALSE;       \
                                    (_BUF).ra_size = 0;         \
                                    (_BUF).size = 0;            \
                                    RESET_TIMER((_BUF).timer);  \
                                }while(0)
#else            
//RESET_TIMER((_BUF).timer);    must go in above macro
#define RA_BUFFER_DEALLOC(_BUF) do{                             \
                                    (_BUF).inUse = FALSE;       \
                                    (_BUF).ra_size = 0;         \
                                    (_BUF).size = 0;            \
                                }while(0)
#endif                                

//reassembling buffers area : 2047B max size for each buffer
//for now 10 buffer(s) simultaneously
static LoWPAN_RA_info buffers_stack[STACK_BUFFERS_NUM];

//received and parsed fragments emerge here
static LoWPAN_frag_t frag_buf;

void firstFragScan(uint8_t* fragment, uint8_t len, LoWPAN_frag_t* resPack);
void firstFragScan(uint8_t* fragment, uint8_t len, LoWPAN_frag_t* resPack)
{
    resPack->size = GET_FRAG_DATAGRAM_SIZE(fragment);
    resPack->tag = GET_FRAG_DATAGRAM_TAG(fragment);
    resPack->offset = 0;
    resPack->len = len - 4;
    memcpy(resPack->data, FRAG1_PAYLOAD_PTR(fragment), resPack->len);
}

void subsqFragScan(uint8_t* fragment, uint8_t len, LoWPAN_frag_t* resPack);
void subsqFragScan(uint8_t* fragment, uint8_t len, LoWPAN_frag_t* resPack)
{
    resPack->size = GET_FRAG_DATAGRAM_SIZE(fragment);
    resPack->tag = GET_FRAG_DATAGRAM_TAG(fragment);
    resPack->offset = GET_DATAGRAM_OFFSET(fragment);
    resPack->len = len - 5;
    memcpy(resPack->data, FRAGN_PAYLOAD_PTR(fragment), resPack->len);
}

///store's recieved fragmnet into given reassembling buffer
///args:: RAbuf: pointer to reassembling buffer
///       frag: pointer to parsed fragment
uint8_t storeFrag(LoWPAN_RA_info* RAbuf, LoWPAN_frag_t* frag);
uint8_t storeFrag(LoWPAN_RA_info* RAbuf, LoWPAN_frag_t* frag)
{
    RAbuf->ra_size += frag->len;

    if(RAbuf->size == 0)
        RAbuf->size = frag->size;
    else if(RAbuf->size != frag->size)
        return 2;

    memcpy(&RAbuf->buffer[frag->offset * 8], frag->data, frag->len);

    if(RAbuf->ra_size >= RAbuf->size)
        return 1;
    return 0;
}

///store a non fragmented packet into givn reassembling buffer
///args:: RAbuf: pointer to reassembling buffer
///       buf: packet buffer
///       len: packet length
uint8_t storePack(LoWPAN_RA_info* RAbuf, uint8_t* buf, uint8_t len);
uint8_t storePack(LoWPAN_RA_info* RAbuf, uint8_t* buf, uint8_t len)
{
    RAbuf->size = len;
    memcpy(RAbuf->buffer, buf, len);
    return 1;
}

///find available reassembling buffer from RA-buf-pool and retur
///pointer to it
///arg:: tag: tag of recieved fragment, it should not be zero
LoWPAN_RA_info* getRAbuffer(uint16_t tag);
LoWPAN_RA_info* getRAbuffer(uint16_t tag)
{
    LoWPAN_RA_info* temp = NULL;
    for(int i = 0; i < STACK_BUFFERS_NUM; i++)
    {
        if(buffers_stack[i].inUse)
        {
#ifndef FREEBSD        
            if(ELAPSED_TIMER(buffers_stack[i].timer))
            {
                RA_BUFFER_DEALLOC(buffers_stack[i]);
            }
            else
#endif                
            	if(buffers_stack[i].tag == tag)
            {
                temp = &buffers_stack[i];
                break;
            }
        }
        if(!buffers_stack[i].inUse)
        {
            RA_BUFFER_ALLOC(buffers_stack[i], tag);
            temp = &buffers_stack[i];
            break;
        }
    }
    return temp;
}

///find available reassembling buffer from RA-buf-pool and retur
///pointer to it. this buffer is specially for not fragmented packets
LoWPAN_RA_info* getRAbuffersp(void);
LoWPAN_RA_info* getRAbuffersp()
{
    LoWPAN_RA_info* temp = NULL;
    for(int i = 0; i < STACK_BUFFERS_NUM; i++)
    {
        if(!buffers_stack[i].inUse)
        {
            RA_BUFFER_ALLOC(buffers_stack[i], 0);
            temp = &buffers_stack[i];
            break;
        }
    }
    return temp;
}

///take recieved packet and put it in it's right place
LoWPAN_RA_info* LoWPAN_FragRA(uint8_t* buf, uint8_t len);
LoWPAN_RA_info* LoWPAN_FragRA(uint8_t* buf, uint8_t len)
{
	if(!lifframePending802154)
	{
		LoWPAN_RA_info* RA_buf = getRAbuffersp();

		if(RA_buf != NULL)
		{
	        storePack(RA_buf, buf, len);
	        return RA_buf;
	    }
	}
    else if(FRAG1(buf[0]))
    {
        firstFragScan(buf, len, &frag_buf);
        LoWPAN_RA_info* RA_buf = getRAbuffer(frag_buf.tag);

        if(RA_buf != NULL)
            if(storeFrag(RA_buf, &frag_buf) == 1)
                return RA_buf;
    }
    else if(FRAGN(buf[0]))
    {
        subsqFragScan(buf, len, &frag_buf);
        LoWPAN_RA_info* RA_buf = getRAbuffer(frag_buf.tag);

        if(RA_buf != NULL)
            if(storeFrag(RA_buf, &frag_buf) == 1)
                return RA_buf;
    }
    return NULL;
}

void copyReleaseRAbuffer(LoWPAN_RA_info* rabuf, uint8_t* resIPv6pack, uint16_t* resIPv6len);
void copyReleaseRAbuffer(LoWPAN_RA_info* rabuf, uint8_t* resIPv6pack, uint16_t* resIPv6len)
{
    (*resIPv6len) = rabuf->size;
    memcpy(resIPv6pack, rabuf->buffer, rabuf->size);
    RA_BUFFER_DEALLOC(*rabuf);
}

///handle function for recieved packets. it will do every thing! you just need to call this
///from outside. if recieved packet is the last part, the reassembled packet will be copied 
///into resIPv6pack and the packet size into resIPv6len
///args:: buf: recieved packet
///       length: recieved packet length
///       resIPv6pack: pointer to result buffer. it must be an allocated buffer. you can use 
///                    CREATE_IP_BUFFER macro to allocat this buffer
///       resIPv6len: pointer to variable appropriate for length of result buffer
uint8_t LoWPAN_savePacket(uint8_t* buf, uint8_t length, uint8_t* resIPv6pack, uint16_t* resIPv6len);
uint8_t LoWPAN_savePacket(uint8_t* buf, uint8_t length, uint8_t* resIPv6pack, uint16_t* resIPv6len)
{
    LoWPAN_RA_info* rabuf = LoWPAN_FragRA(buf, length);
    if(rabuf != NULL)
    {
        copyReleaseRAbuffer(rabuf, resIPv6pack, resIPv6len);
        return 1;
    }
    return 0;
}

#endif // SIXLOWPAN_FRAGMENTATION
