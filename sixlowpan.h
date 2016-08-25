#ifndef GLUE_H_INCLUDED
#define GLUE_H_INCLUDED

//#include <stdio.h>
//#include <time.h>
//#include <math.h>

//#define FREEBSD

/* AS 802.15.4 standard convention is lettle endian based. data transmitted over network
   must determined as little endian so you should define ARCHITECT based on your device's
   endianness. if you compile this code on Intel machine set # ARCHITECT LITTLE_ENDIAN_ARCH
   or you can use BIG_ENDIAN_ARC based on your machine type*/
   #define BIG_ENDIAN_ARC 1
   #define LITTLE_ENDIAN_ARCH 2

#define ARCHITECT LITTLE_ENDIAN_ARCH
#define DEBUG

#include "MAC.h"
#include "HCc.h"
#include "frag.h"



void init(void);
void init()
{
    init_frag();
    init_framer();
    init_lowPANcompression();
}

void finalize(void);
void finalize()
{
    finalize_frag();
    finalize_lowPANcompression();
}

void setIPpack(uint8_t* ipbuf, uint16_t ipsize);
void setIPpack(uint8_t* ipbuf, uint16_t ipsize)
{
    setSendIPpacket(ipbuf, ipsize);
}

uint8_t get_next_pack(uint8_t* , uint8_t* );
uint8_t get_next_pack(uint8_t* lpanpack, uint8_t* lpansize)
{

    /*uint8_t srcaddr[8];
    uint8_t destaddr[8];
    srcaddr[0] = 0x00;
    srcaddr[1] = 0x12;
    srcaddr[2] = 0x4b;
    srcaddr[3] = 0x00;
    srcaddr[4] = 0x05;
    srcaddr[5] = 0xad;
    srcaddr[6] = 0x91;
    srcaddr[7] = 0xc1;

    destaddr[0] = 0x00;
    destaddr[1] = 0x12;
    destaddr[2] = 0x4b;
    destaddr[3] = 0x00;
    destaddr[4] = 0x05;
    destaddr[5] = 0xad;
    destaddr[6] = 0x92;
    destaddr[7] = 0x8c;

    MAC_Frame_t frameData;
    frameData.FCF.FrameType = DATA;
    frameData.FCF.SecurityEnabled = TRUE;
    frameData.FCF.FramePend = FALSE;
    frameData.FCF.AckRequset = FALSE;
    frameData.FCF.PanIDCompression = TRUE;
    frameData.FCF.RSVD = 0;
    frameData.FCF.DestAddrMode = EXTENDED_ADDRESS;
    frameData.FCF.FrameVersion = 0;
    frameData.FCF.SrcAddrMode = EXTENDED_ADDRESS;

    frameData.SequenceNumber = 1;
    frameData.DestPANID = 0x5449;
    MAC_SET_ADDRESS(frameData.DestAddr, destaddr, 8);
    //frameData.SrcPANID = 0x5449;
    MAC_SET_ADDRESS(frameData.SrcAddr, srcaddr, 8);*/


    asDataFrame802154;
    AckRequest802154;
    dataLen802154 = maxPayload802154;

    if(LoWPAN_nextFrag(data802154, &dataLen802154) == 0)
    {
        framerOut802154(lpanpack, lpansize);
        dataLen802154 = maxPayload802154;
        return 0;
    }
    return 1;
}

uint8_t set_next_pack(uint8_t* lpanpack, uint8_t lpansize, uint8_t* resipv6, uint16_t* ressize);
uint8_t set_next_pack(uint8_t* lpanpack, uint8_t lpansize, uint8_t* resipv6, uint16_t* ressize)
{
    framerIn802154(lpanpack, lpansize);

    if(LoWPAN_savePacket(lifdata802154, lifdataLen802154, resipv6,  ressize) != 1)
    {
        return 0;
    }
    return 1;
}


#endif // GLUE_H_INCLUDED
