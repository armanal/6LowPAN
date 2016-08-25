#include <stdio.h>
#include <assert.h>
//#include <time.h>
//#include <math.h>
#include "sixlowpan.h"

/* AS 802.15.4 standard convention is lettle endian based. data transmitted over network
   must determined as little endian so you should define ARCHITECT based on your device's
   endianness. if you compile this code on Intel machine set # ARCHITECT LITTLE_ENDIAN_ARCH
   or you can use BIG_ENDIAN_ARC based on your machine type*/
   #define BIG_ENDIAN_ARC 1
   #define LITTLE_ENDIAN_ARCH 2

#define ARCHITECT LITTLE_ENDIAN_ARCH
#define DEBUG

#include "MAC.h"
#include "sixlowpan.h"
#include "IPv6.h"

//#include <windows.h>

void test1_Fragmentation()
{
    init_frag();
    uint8_t* ipbuf;
    uint16_t ipsize;
    uint8_t* ripbuf;
    uint16_t ripsize;

    CREATE_IP_BUFFER(ipbuf, ipsize);
    CREATE_IP_BUFFER(ripbuf, ripsize);

    memset(ipbuf, 0, ipsize);
    memset(ripbuf, 1, ripsize);

    uint8_t* data = (uint8_t*) "salam man dobare ooomadam hahahahaha! in barname 6lowPAN ghader be enteghale baste haye IP bar ruye 802.15.4 mibashad. az in roo man An ra neveshtam ta ba kar karde shabake ashna shawam. be omide didar ;) .";
    uint16_t dsize = 209;
    memcpy(ipbuf, data, dsize);
    ipsize = dsize;

    setSendIPpacket(ipbuf, ipsize);

    uint8_t lpanpack[MAX_FRAG_SIZE];
    uint8_t lpansize = MAX_FRAG_SIZE;

    while(LoWPAN_nextFrag(lpanpack, &lpansize) == 0)
    {
        if(LoWPAN_savePacket(lpanpack, lpansize, ripbuf, &ripsize) == 1)
        {
            break;
        }
        lpansize = MAX_FRAG_SIZE;
    }

    if(ipsize == ripsize)
        if(memcmp(ipbuf, ripbuf, ipsize) == 0){
            printf("test1 passed +1 \n");
        }
        else{
                printf("test1 fail \n");
        }
    else
        printf("test1 fail \n");

    DESTRUCT_IP_BUFFER(ipbuf);
    DESTRUCT_IP_BUFFER(ripbuf);

    finalize_frag();
}


void test2_MAC()
{
    uint8_t srcaddr[8];
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
    MAC_SET_ADDRESS(frameData.SrcAddr, srcaddr, 8);

    uint8_t* data = (uint8_t*) "salam man dobare ooomadam hahahahaha! in barname 6lowPAN ghader be enteghale baste haye IP bar ruye 802.15.4 mibash";
    uint8_t dsize = 100;
    memcpy(frameData.Payload, data, dsize);
    frameData.length = dsize;

    uint8_t buf[128];
    uint8_t len;



    MACframecreate(&frameData, buf, &len);

    printf("packet in hexadecimal: \n");
    for(int i = 0; i < len; i++)
    {
        printf("%x ", buf[i]);
    }
    printf("\n\n");
    printf("packet in text: \n");
    for(int i = 0; i < len; i++)
    {
        printf("%c ", buf[i]);
    }
    printf("\n\n");
    ///////////////////receive//////////////////////////
    uint8_t r_srcaddr[8];
    uint8_t r_destaddr[8];
    MAC_Frame_t r_frameData;

    MACframeparser(buf, len, &r_frameData);

    printf("FCF.FrameType        %x  :  %x\n",frameData.FCF.FrameType, r_frameData.FCF.FrameType);
    assert(frameData.FCF.FrameType == r_frameData.FCF.FrameType);
    printf("FCF.SecurityEnabled  %x  :  %x\n",frameData.FCF.SecurityEnabled, r_frameData.FCF.SecurityEnabled);
    assert(frameData.FCF.SecurityEnabled == r_frameData.FCF.SecurityEnabled);
    printf("FCF.FramePend        %x  :  %x\n",frameData.FCF.FramePend, r_frameData.FCF.FramePend);
    assert(frameData.FCF.FramePend == r_frameData.FCF.FramePend);
    printf("FCF.AckRequset       %x  :  %x\n",frameData.FCF.AckRequset, r_frameData.FCF.AckRequset);
    assert(frameData.FCF.AckRequset == r_frameData.FCF.AckRequset);
    printf("FCF.PanIDCompression %x  :  %x\n",frameData.FCF.PanIDCompression, r_frameData.FCF.PanIDCompression);
    assert(frameData.FCF.PanIDCompression == r_frameData.FCF.PanIDCompression);
    printf("FCF.RSVD             %x  :  %x\n",frameData.FCF.RSVD, r_frameData.FCF.RSVD);
    assert(frameData.FCF.RSVD == r_frameData.FCF.RSVD);
    printf("FCF.DestAddrMode     %x  :  %x\n",frameData.FCF.DestAddrMode, r_frameData.FCF.DestAddrMode);
    assert(frameData.FCF.DestAddrMode == r_frameData.FCF.DestAddrMode);
    printf("FCF.FrameVersion     %x  :  %x\n",frameData.FCF.FrameVersion, r_frameData.FCF.FrameVersion);
    assert(frameData.FCF.FrameVersion == r_frameData.FCF.FrameVersion);
    printf("FCF.SrcAddrMode      %x  :  %x\n",frameData.FCF.SrcAddrMode, r_frameData.FCF.SrcAddrMode);
    assert(frameData.FCF.SrcAddrMode == r_frameData.FCF.SrcAddrMode);

    printf("SequenceNumber       %x  :  %x\n",frameData.SequenceNumber, r_frameData.SequenceNumber);
    assert(frameData.SequenceNumber == r_frameData.SequenceNumber);
    printf("DestPANID            %x  :  %x\n",frameData.DestPANID, r_frameData.DestPANID);
    assert(frameData.DestPANID == r_frameData.DestPANID);
    for(int i = 0; i< 8; i++)
    {
        assert(frameData.DestAddr[i] == r_frameData.DestAddr[i]);
    }

    //frameData.SrcPANID = 0x5449;
    for(int i = 0; i< 8; i++)
    {
        assert(frameData.SrcAddr[i] == r_frameData.SrcAddr[i]);
    }

}

void test3_gluecode()
{
    uint8_t* ipbuf;
    uint16_t ipsize;
    CREATE_IP_BUFFER(ipbuf, ipsize);

    memset(ipbuf, 0, ipsize);
    uint8_t* data = (uint8_t*) "salam man dobare ooomadam hahahahaha! in barname 6lowPAN ghader be enteghale baste haye IP bar ruye 802.15.4 mibashad. az in roo man An ra neveshtam ta ba kar karde shabake ashna shawam. be omide didar ;) .";
    uint16_t dsize = 206;
    memcpy(ipbuf, data, dsize);
    ipsize = dsize;

    uint8_t lpanpack[MAC_MAX_LENGTH];
    uint8_t lpansize = MAC_MAX_LENGTH;

    init();
    setIPpack(ipbuf, ipsize);
    while(get_next_pack(lpanpack, &lpansize) == 0)
    {
        //send data here

        printf("packet in hexadecimal with len of %u: \n", lpansize);
        for(int i = 0; i < lpansize; i++)
        {
            printf("%c (%u)  ", lpanpack[i],i);
        }
        printf("\n\n");

        lpansize = MAC_MAX_LENGTH;
    }

    DESTRUCT_IP_BUFFER(ipbuf);
    finalize();
}

void test4_gluecode2()
{
	uint8_t* ipbuf;
    uint16_t ipsize;
    uint8_t* ripbuf;
    uint16_t ripsize;

    CREATE_IP_BUFFER(ipbuf, ipsize);
    CREATE_IP_BUFFER(ripbuf, ripsize);

    memset(ipbuf, 0, ipsize);
    memset(ripbuf, 1, ripsize);

    uint8_t* data = (uint8_t*) "salam man dobare ooomadam hahahahaha! in barname 6lowPAN ghader be enteghale baste haye IP bar ruye 802.15.4 mibashad. az in roo man An ra neveshtam ta ba kar karde shabake ashna shawam. be omide didar ;) . 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6";
    uint16_t dsize = 300;
    memcpy(ipbuf, data, dsize);
    ipsize = dsize;

    init();

    uint8_t lpanpack[MAC_MAX_LENGTH];
    uint8_t lpansize = MAC_MAX_LENGTH;

    setIPpack(ipbuf, ipsize);

    while(get_next_pack(lpanpack, &lpansize) == 0)
    {
        if(set_next_pack(lpanpack, lpansize, ripbuf, &ripsize) == 1)
        {
            break;
        }
        lpansize = MAC_MAX_LENGTH;
    }

    if(ipsize == ripsize)
        if(memcmp(ipbuf, ripbuf, ipsize) == 0){
            printf("test4 passed +1 \n");
        }
        else{
                printf("test4 fail \n");
        }
    else
        printf("test4 fail \n");

    DESTRUCT_IP_BUFFER(ipbuf);
    DESTRUCT_IP_BUFFER(ripbuf);

    finalize();
}

void createipv6(uint8_t* data, uint16_t size, uint8_t* ip, uint16_t* ips)
{
    IPV6_SET_VERSION(ip, 6);
    IPV6_SET_Traffic_Class(ip, 0);
    IPV6_SET_FLOW_LABLE(ip, 0);
    IPV6_SET_HOP_LIMIT(ip, 0x40);
    IPV6_SET_NEXT_HEADER(ip, UIP_PROTO_UDP);

    ip6Addr_t asrc;
    //fe80:0:0:0:8a01:3d4b:0:2
    setipv6addr("2607:f2f8:100:999:0:0:0:2", &asrc);
    IPV6_SET_SRC_ADDR(ip, asrc);

    ip6Addr_t adest;
    setipv6addr("2607:f2f8:100:999:0:0:0:7", &adest);
    IPV6_SET_DEST_ADDR(ip, adest);

    IPV6_UDP_SET_SRC_PORT(ip, 0x81b7);
    IPV6_UDP_SET_DEST_PORT(ip, 0x0050);
    IPV6_UDP_SET_LENGTH(ip, (size + 8));
    IPV6_UDP_SET_CHECKSUM(ip, 0x73a7);

    IPV6_SET_PAYLOAD_LENGTH(ip, IPV6_UDP_GET_LENGTH(ip));

    memcpy(&ip[48], data, size);

    (*ips) = (size + 8) + 40;
}

void test5_compression()
{
	uint8_t* ipbuf;
    uint16_t ipsize;
    uint8_t* mbuf;
    uint16_t mbufsize;
    uint8_t* ripbuf;
    uint16_t ripsize;

    CREATE_IP_BUFFER(ipbuf, ipsize);
    CREATE_IP_BUFFER(ripbuf, ripsize);
    CREATE_IP_BUFFER(mbuf, mbufsize);

    memset(ipbuf, 0, ipsize);
    memset(ripbuf, 1, ripsize);
    memset(mbuf, 2, mbufsize);

    uint8_t* data = (uint8_t*) "salam man dobare ooomadam hahahahaha! in barname 6lowPAN ghader be enteghale baste haye IP bar ruye 802.15.4 mibashad. az in roo man An ra neveshtam ta ba kar karde shabake ashna shawam. be omide didar ;) . 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6";
    uint16_t dsize = 300;
//    memcpy(ipbuf, data, dsize);
//    ipsize = dsize;
    createipv6(data, dsize, ipbuf, &ipsize);

    init();

    compress(ipbuf, ipsize, mbuf, &mbufsize);

    uint8_t lpanpack[MAC_MAX_LENGTH];
    uint8_t lpansize = MAC_MAX_LENGTH;

    setIPpack(mbuf, mbufsize);

    while(get_next_pack(lpanpack, &lpansize) == 0)
    {
        if(set_next_pack(lpanpack, lpansize, ripbuf, &ripsize) == 1)
        {
            break;
        }
        lpansize = MAC_MAX_LENGTH;
    }


    uncompress(ripbuf, ripsize, mbuf, &mbufsize);


    if(ipsize == mbufsize)
        if(memcmp(ipbuf, mbuf, ipsize) == 0){
            printf("test5 passed +1 \n");
        }
        else{
                printf("test5 fail \n");
        }
    else
        printf("test5 fail \n");

    DESTRUCT_IP_BUFFER(ipbuf);
    DESTRUCT_IP_BUFFER(ripbuf);
    DESTRUCT_IP_BUFFER(mbuf);

    finalize();
}

void test6_freebsdcmpar()
{
	uint8_t* ipbuf;
    uint16_t ipsize;
    uint8_t* mbuf;
    uint16_t mbufsize;
    uint8_t* ripbuf;
    uint16_t ripsize;

    init();

    CREATE_IP_BUFFER(ipbuf, ipsize);
    CREATE_IP_BUFFER(ripbuf, ripsize);
    CREATE_IP_BUFFER(mbuf, mbufsize);

    memset(ipbuf, 0, ipsize);
    memset(ripbuf, 1, ripsize);
    memset(mbuf, 2, mbufsize);

    uint8_t data[4] = {0x61, 0x72, 0x61, 0x7a};
    uint16_t dsize = 4;
//    memcpy(ipbuf, data, dsize);
//    ipsize = dsize;

    createipv6(data, dsize, ipbuf, &ipsize);

    printf("original packet in hexadecimal: \n");
    for(int i = 0; i < ipsize; i++)
    {
        printf("%x ", ipbuf[i]);
    }
    printf("\n\n");

    comMode = NOCOMPRESSION;

    compress(ipbuf, ipsize, mbuf, &mbufsize);

    printf("packet in hexadecimal: \n");
    for(int i = 0; i < mbufsize; i++)
    {
        printf("%x ", mbuf[i]);
    }
    printf("\n\n");



    uint8_t lpanpack[MAC_MAX_LENGTH];
    uint8_t lpansize = MAC_MAX_LENGTH;

    setIPpack(mbuf, mbufsize);

    while(get_next_pack(lpanpack, &lpansize) == 0)
    {

            printf("next packet in hexadecimal: \n");
            for(int i = 0; i < lpansize; i++)
            {
                printf("%x ", lpanpack[i]);
            }
            printf("\n\n");


        if(set_next_pack(lpanpack, lpansize, ripbuf, &ripsize) == 1)
        {
            break;
        }
        lpansize = MAC_MAX_LENGTH;
    }


    uncompress(ripbuf, ripsize, mbuf, &mbufsize);


    if(ipsize == mbufsize)
        if(memcmp(ipbuf, mbuf, ipsize) == 0){
            printf("test6 passed +1 \n");
        }
        else{
                printf("test6 fail \n");
        }
    else
        printf("test6 fail \n");

    DESTRUCT_IP_BUFFER(ipbuf);
    DESTRUCT_IP_BUFFER(ripbuf);
    DESTRUCT_IP_BUFFER(mbuf);

    finalize();
}

int main()
{
//    test1_Fragmentation();
//    test2_MAC();
//
//    test3_gluecode();
//    test4_gluecode2();

//    test5_compression();

    test6_freebsdcmpar();

    getchar();

    return 0;
}
