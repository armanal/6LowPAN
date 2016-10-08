#ifndef MAC_FRAME_CONTROL
#define MAC_FRAME_CONTROL

#ifndef FREEBSD
#include <stdio.h>
#include <string.h>
#else
#endif

#include "utilities.h"
#include "types.h"


/*  -----------------------------------------------------------
    In 802.15.4 General Frame: Frame Control Field (FCF) read
    and write macros
    -----------------------------------------------------------  */
///for supporting contiki based devices define this macro
///because of the method that contiki fills and reads MAC frames
#if ARCHITECT == BIG_ENDIAN_ARC
/// all get 16 bit uint
#define GET_FRAME_TYPE(_FCF_BYTE) ((_FCF_BYTE & 0xE000) >> 13)
#define GET_SECURITY_ENABLE(_FCF_BYTE) GET_BIT(_FCF_BYTE, 12)
#define GET_FRAME_PEND(_FCF_BYTE) GET_BIT(_FCF_BYTE, 11)
#define GET_ACK_REQUEST(_FCF_BYTE) GET_BIT(_FCF_BYTE, 10)
#define GET_PAN_ID_COMPRESSION(_FCF_BYTE) GET_BIT(_FCF_BYTE, 9)
#define GET_RSVD(_FCF_BYTE) ((_FCF_BYTE & 0x01C0) >> 6)
#define GET_DESTINATION_ADDRESS_MODE(_FCF_BYTE) ((_FCF_BYTE & 0x0030) >> 4)
#define GET_FRAME_VERSION(_FCF_BYTE) ((_FCF_BYTE & 0x000C) >> 2)
#define GET_SOURCE_ADDRESS_MODE(_FCF_BYTE) (_FCF_BYTE & 0x0003)

///be careful with _VAL. it should be in defined range
#define SET_FRAME_TYPE(_FCF_BYTE, _VAL) _FCF_BYTE ^= (((_VAL<<13)^_FCF_BYTE) & 0xE000)
#define SET_SECURITY_ENABLE(_FCF_BYTE, _VAL) _FCF_BYTE ^= (((_VAL<<12)^_FCF_BYTE) & 0x1000)
#define SET_FRAME_PEND(_FCF_BYTE, _VAL) _FCF_BYTE ^= (((_VAL<<11)^_FCF_BYTE) & 0x0800)
#define SET_ACK_REQUEST(_FCF_BYTE, _VAL) _FCF_BYTE ^= (((_VAL<<10)^_FCF_BYTE) & 0x0400)
#define SET_PAN_ID_COMPRESSION(_FCF_BYTE, _VAL) _FCF_BYTE ^= (((_VAL<<9)^_FCF_BYTE) & 0x0200)
#define SET_RSVD(_FCF_BYTE, _VAL) _FCF_BYTE ^= (((_VAL<<6)^_FCF_BYTE) & 0x01C0)
#define SET_DESTINATION_ADDRESS_MODE(_FCF_BYTE, _VAL) _FCF_BYTE ^= (((_VAL<<4)^_FCF_BYTE) & 0x0030)
#define SET_FRAME_VERSION(_FCF_BYTE, _VAL) _FCF_BYTE ^= (((_VAL<<2)^_FCF_BYTE) & 0x000C)
#define SET_SOURCE_ADDRESS_MODE(_FCF_BYTE, _VAL) _FCF_BYTE ^= (((_VAL)^_FCF_BYTE) & 0x0003)

#elif ARCHITECT == LITTLE_ENDIAN_ARCH

/// all get 16 bit uint
#define GET_FRAME_TYPE(_FCF_BYTE) ((_FCF_BYTE & 7))
#define GET_SECURITY_ENABLE(_FCF_BYTE) GET_BIT(_FCF_BYTE, 3)
#define GET_FRAME_PEND(_FCF_BYTE) GET_BIT(_FCF_BYTE, 4)
#define GET_ACK_REQUEST(_FCF_BYTE) GET_BIT(_FCF_BYTE, 5)
#define GET_PAN_ID_COMPRESSION(_FCF_BYTE) GET_BIT(_FCF_BYTE, 6)
#define GET_RSVD(_FCF_BYTE) ((_FCF_BYTE & 0x0380) >> 7)
#define GET_DESTINATION_ADDRESS_MODE(_FCF_BYTE) ((_FCF_BYTE & 0x0C00) >> 10)
#define GET_FRAME_VERSION(_FCF_BYTE) ((_FCF_BYTE & 0x0300) >> 12)
#define GET_SOURCE_ADDRESS_MODE(_FCF_BYTE) ((_FCF_BYTE & 0XC000) >> 14)

///be careful with _VAL. it should be in defined range
#define SET_FRAME_TYPE(_FCF_BYTE, _VAL) _FCF_BYTE ^= (((_VAL & 7)^_FCF_BYTE) & 0x0007)
#define SET_SECURITY_ENABLE(_FCF_BYTE, _VAL) _FCF_BYTE ^= ((((_VAL & 1) << 3)^_FCF_BYTE) & 0X0008)
#define SET_FRAME_PEND(_FCF_BYTE, _VAL) _FCF_BYTE ^= ((((_VAL & 1) << 4)^_FCF_BYTE) & 0x0010)
#define SET_ACK_REQUEST(_FCF_BYTE, _VAL) _FCF_BYTE ^= ((((_VAL & 1) << 5)^_FCF_BYTE) & 0x0020)
#define SET_PAN_ID_COMPRESSION(_FCF_BYTE, _VAL) _FCF_BYTE ^= ((((_VAL & 1) << 6)^_FCF_BYTE) & 0x0040)
#define SET_RSVD(_FCF_BYTE, _VAL) _FCF_BYTE ^= ((((_VAL & 7) << 7)^_FCF_BYTE) & 0x0380)
#define SET_DESTINATION_ADDRESS_MODE(_FCF_BYTE, _VAL) _FCF_BYTE ^= ((((_VAL & 3) << 10)^_FCF_BYTE) & 0x0c00)
#define SET_FRAME_VERSION(_FCF_BYTE, _VAL) _FCF_BYTE ^= ((((_VAL & 3) << 12)^_FCF_BYTE) & 0x3000)
#define SET_SOURCE_ADDRESS_MODE(_FCF_BYTE, _VAL) _FCF_BYTE ^= ((((_VAL & 7) << 14)^_FCF_BYTE) & 0xc000)

#endif

///   End of FCF read & write macros   ////////////////////////
///////////////////////////////////////////////////////////////

#if ARCHITECT == BIG_ENDIAN_ARC
// set dest addr for struct MAC_Frame_t. The first two aguments must be uint8_t*, and the last one must be uint8_t
#define MAC_SET_ADDRESS(_ADDR_DST, _ADDR_SRC, _LEN) ({	for(int i = 0, j = _LEN - 1; i<_LEN; i++, j--){		\
															_ADDR_DST[i] = _ADDR_SRC[j];	\
														} })

#elif ARCHITECT == LITTLE_ENDIAN_ARCH
// set dest addr for struct MAC_Frame_t. The first two aguments must be uint8_t*, and the last one must be uint8_t
#define MAC_SET_ADDRESS(_ADDR_DST, _ADDR_SRC, _LEN) ({	for(int i = 0, j = _LEN - 1; i<_LEN; i++, j--){		\
															_ADDR_DST[i] = _ADDR_SRC[j];	\
														} })
/*#define MAC_SET_ADDRESS(_ADDR_DST, _ADDR_SRC, _LEN) ({	for(int i = 0; i<_LEN; i++){		\
															_ADDR_DST[i] = _ADDR_SRC[i];	\
														} })*/
#endif

///////////////////////////////////////////////////////////////
///  Here's where structs are defined //////////////////////////////////

typedef enum MAC_Frame_Type_t{
	BEACON = 0,
	DATA = 1,
	ACKNOWLEDGEMENT = 2,
	MAC_COMMAND = 3
} MAC_Frame_Type_t;

typedef enum {
	PAN_IDENTIFIER = 0,
	SHORT_AdDDRESS = 2,
	EXTENDED_ADDRESS = 3
} MAC_Addressing_Mode_t;

/*  ---------------------------------------------------------------------------------------------------
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
	| Frame | Security | Frame | ACK     | PAN ID       | RSVD | Dest. Addr. | Frame   | Src. Addr. | |
	| Type  | Enable   | Pend  | Request | Comparession |      | Mode        | Version | Mode       | |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
    ---------------------------------------------------------------------------------------------------  */
typedef struct {
	MAC_Frame_Type_t FrameType;
	bool_t SecurityEnabled;
	bool_t FramePend;
	bool_t AckRequset;
	bool_t PanIDCompression;
	uint8_t RSVD;
	MAC_Addressing_Mode_t DestAddrMode;
	uint8_t FrameVersion;
	MAC_Addressing_Mode_t SrcAddrMode;
} MAC_FCF_t;


/*  ----------------------------------------------------------------
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- |
	| FCF | Secuence | Dest.  | Dest. | Src.   | Src.  | Payload | |
	|     | Number   | PAN ID | Addr. | PAN ID | Addr. |         | |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- |
    ----------------------------------------------------------------  */
#define MAC_MAX_LENGTH 124
#define MAC_MAX_PAYLOAD_LENGTH (MAC_MAX_LENGTH - 5)
typedef struct {
	// Payload length; it should be calculated based on the mac header length
	uint8_t length;
	//frame control field
	MAC_FCF_t FCF;
	uint8_t SequenceNumber;
	uint16_t DestPANID;
	// we assume that the least significant byte is stored in the adder with the index of 0
	// this means that addr must be stored in a little-endian order
	uint8_t DestAddr[8];
	uint16_t SrcPANID;
	uint8_t SrcAddr[8];
	// 127 - MAC Frame Header minimum length
	uint8_t Payload[MAC_MAX_PAYLOAD_LENGTH];
} MAC_Frame_t;


///////////////////////////////////////////////////////////////
///  Here's where the variables are defined ////////////////////////////////

//static MAC_Frame_t* output_frame;
//static MAC_Frame_t* input_frame;

///////////////////////////////////////////////////////////////
///   Functions implementations ///////////////////////////////


///takes a MAC_Frame_t struct and calculates the MAC header length
///arg:: f: MAC_Frame_t struct filled with valid data
uint8_t MACgethdrLen(MAC_Frame_t f);
uint8_t MACgethdrLen(MAC_Frame_t f)
{
    uint8_t l;

    l = 3;

    if(f.FCF.PanIDCompression == TRUE)
        l += 2;
    else
        l += 4;

    switch(f.FCF.DestAddrMode)
	{
		case PAN_IDENTIFIER:{
		}break;
		case SHORT_AdDDRESS:{
			l += 2;
		}break;
		case EXTENDED_ADDRESS:{
			l += 8;
		}break;
	}
	switch(f.FCF.SrcAddrMode)
	{
		case PAN_IDENTIFIER:{
		}break;
		case SHORT_AdDDRESS:{
			l += 2;
		}break;
		case EXTENDED_ADDRESS:{
			l += 8;
		}break;
	}

	return l;
}


///take's MAC_Frame_t struct and calculates the MAC payload length according to the MAC header length 
///arg:: f: MAC_Frame_t struct filled with valid data
uint8_t MACgetPayloadLength(MAC_Frame_t f);
uint8_t MACgetPayloadLength(MAC_Frame_t f)
{
    return MAC_MAX_LENGTH - MACgethdrLen(f);
}


///takes a 16bits FCF field and extracts it's data into a MAC_FCF_t struct
///this struct should be provided before, function just gets a pointer
///args:: FCF_field: 2B FCF field of MAC frame
void MACfcfparser(uint16_t FCF_field, MAC_FCF_t* FCF_result);
void MACfcfparser(uint16_t FCF_field, MAC_FCF_t* FCF_result)
{
	uint8_t temp = GET_FRAME_TYPE(FCF_field);
	switch(temp)
	{
		case 0:{
			FCF_result->FrameType = BEACON;
		}break;
		case 1:{
			FCF_result->FrameType = DATA;
		}break;
		case 2:{
			FCF_result->FrameType = ACKNOWLEDGEMENT;
		}break;
		case 3:{
			FCF_result->FrameType = MAC_COMMAND;
		}break;
	}

	FCF_result->SecurityEnabled = GET_SECURITY_ENABLE(FCF_field);
	FCF_result->FramePend = GET_FRAME_PEND(FCF_field);
	FCF_result->AckRequset = GET_ACK_REQUEST(FCF_field);
	FCF_result->PanIDCompression = GET_PAN_ID_COMPRESSION(FCF_field);
	FCF_result->RSVD = GET_RSVD(FCF_field);

	temp = GET_DESTINATION_ADDRESS_MODE(FCF_field);
	switch(temp)
	{
		case 0:{
			FCF_result->DestAddrMode = PAN_IDENTIFIER;
		}break;
		case 2:{
			FCF_result->DestAddrMode = SHORT_AdDDRESS;
		}break;
		case 3:{
			FCF_result->DestAddrMode = EXTENDED_ADDRESS;
		}break;
	}

	FCF_result->FrameVersion = GET_FRAME_VERSION(FCF_field);

	temp = GET_SOURCE_ADDRESS_MODE(FCF_field);
	switch(temp)
	{
		case 0:{
			FCF_result->SrcAddrMode = PAN_IDENTIFIER;
		}break;
		case 2:{
			FCF_result->SrcAddrMode = SHORT_AdDDRESS;
		}break;
		case 3:{
			FCF_result->SrcAddrMode = EXTENDED_ADDRESS;
		}break;
	}
}

///takes a MAC frame and parses it into MAC_Frame_t struct
///args:: buffer: pointer to the received MAC frame
///       len: is the mac frame length in bytes without considering the FCS and frame length fields
///       frame: parsed frame will take place in this struct as result
void MACframeparser(uint8_t* buffer, uint8_t len, MAC_Frame_t* frame);
void MACframeparser(uint8_t* buffer, uint8_t len, MAC_Frame_t* frame)
{
	if(frame == NULL || buffer == NULL || len <= 0){
		return;
	}
	// handle
	uint8_t h = 0;
	int c;

	MACfcfparser(GET16_802154(buffer, h), &(frame->FCF));
	h += 2;

	//calculating MAC frame payload length based on addressing modes
	//continued in address fields parsing
	frame->length = len - MACgethdrLen(*frame);

	frame->SequenceNumber = buffer[h];
	h++;

	frame->DestPANID = GET16_802154(buffer, h);
	h += 2;

	memset(frame->DestAddr, 0x0, 8);
	switch(frame->FCF.DestAddrMode)
	{
		case PAN_IDENTIFIER:{
			frame->length -= 0;
		}break;
		case SHORT_AdDDRESS:{
			frame->DestAddr[0] = buffer[h++];
			frame->DestAddr[1] = buffer[h++];
		}break;
		case EXTENDED_ADDRESS:{
			for(c = 0; c <= 7; c++) {
		    	frame->DestAddr[c] = buffer[h++];
		  	}
		}break;
	}

    if(frame->FCF.PanIDCompression == FALSE)
    {
        frame->SrcPANID = GET16_802154(buffer, h);
        h += 2;
    }
    else
    {
    	frame->SrcPANID = frame->DestPANID;
    }

	memset(frame->SrcAddr, 0x0, 8);
	switch(frame->FCF.SrcAddrMode)
	{
		case PAN_IDENTIFIER:{
			frame->length -= 0;
		}break;
		case SHORT_AdDDRESS:{
			frame->SrcAddr[0] = buffer[h++];
			frame->SrcAddr[1] = buffer[h++];
		}break;
		case EXTENDED_ADDRESS:{
			for(c = 0; c <= 7; c++) {
		    	frame->SrcAddr[c] = buffer[h++];
		  	}
		}break;
	}

	if(frame->length > MAC_MAX_PAYLOAD_LENGTH)
        frame->length = MAC_MAX_PAYLOAD_LENGTH;
    if(frame->length > MAC_MAX_LENGTH - MACgethdrLen(*frame))
        return;

    memcpy(frame->Payload, &buffer[h], frame->length);
}

///takes a MAC_FCF_t struct containing FCF data and converts it to 2B FCF Field
///args:: FCF_data: pointer to the MAC_FCF_t struct
///       FCF_result: the 2B FCF field will take place here
void MACfcfgenerate(MAC_FCF_t* FCF_data, uint16_t* FCF_result);
void MACfcfgenerate(MAC_FCF_t* FCF_data, uint16_t* FCF_result)
{
	switch(FCF_data->FrameType)
	{
		case BEACON:{
			SET_FRAME_TYPE(*FCF_result, 0);
		}break;
		case DATA:{
			SET_FRAME_TYPE(*FCF_result, 1);
		}break;
		case ACKNOWLEDGEMENT:{
			SET_FRAME_TYPE(*FCF_result, 2);
		}break;
		case MAC_COMMAND:{
			SET_FRAME_TYPE(*FCF_result, 2);
		}break;
	}

	SET_SECURITY_ENABLE(*FCF_result, FCF_data->SecurityEnabled);
	SET_FRAME_PEND(*FCF_result, FCF_data->FramePend);
	SET_ACK_REQUEST(*FCF_result, FCF_data->AckRequset);
	SET_PAN_ID_COMPRESSION(*FCF_result, FCF_data->PanIDCompression);
	SET_RSVD(*FCF_result, FCF_data->RSVD);

	switch(FCF_data->DestAddrMode)
	{
		case PAN_IDENTIFIER:{
		    SET_DESTINATION_ADDRESS_MODE(*FCF_result, 0);
		}break;
		case SHORT_AdDDRESS:{
			SET_DESTINATION_ADDRESS_MODE(*FCF_result, 2);
		}break;
		case EXTENDED_ADDRESS:{
			SET_DESTINATION_ADDRESS_MODE(*FCF_result, 3);
		}break;
	}

	SET_FRAME_VERSION(*FCF_result, FCF_data->FrameVersion);

	switch(FCF_data->SrcAddrMode)
	{
		case PAN_IDENTIFIER:{
		    SET_SOURCE_ADDRESS_MODE(*FCF_result, 0);
		}break;
		case SHORT_AdDDRESS:{
			SET_SOURCE_ADDRESS_MODE(*FCF_result, 2);
		}break;
		case EXTENDED_ADDRESS:{
			SET_SOURCE_ADDRESS_MODE(*FCF_result, 3);
		}break;
	}
}

///takes a MAC_Frame_t struct and converts it to MAC standard frame
///args:: frame: MAC_Frame_t struct which contains the MAC frame data
///       buffer: pointer to the reault frame buffer
///       len: result data length in buffer
void MACframecreate(MAC_Frame_t* frame, uint8_t* buffer, uint8_t* len);
void MACframecreate(MAC_Frame_t* frame, uint8_t* buffer, uint8_t* len)
{
	if(frame == NULL || buffer == NULL || len == NULL){
		return;
	}
	//uint8_t templen;
	// handle
	uint8_t h = 0;
	int c;

	uint16_t fcf;
	MACfcfgenerate(&(frame->FCF), &fcf);
	SET16_802154(buffer, h, fcf);
	h += 2;

#ifdef DEBUG
    //printf("    MAC FCF is : %x -> 0:%x  1:%x\n", fcf, fcf&0xff, (fcf>>8)&0xff);
#endif // DEBUG

	buffer[h] = frame->SequenceNumber;
	h++;

	SET16_802154(buffer, h, frame->DestPANID);
	h += 2;


	switch(frame->FCF.DestAddrMode)
	{
		case PAN_IDENTIFIER:{
		}break;
		case SHORT_AdDDRESS:{
			buffer[h++] = frame->DestAddr[0];
			buffer[h++] = frame->DestAddr[1];
		}break;
		case EXTENDED_ADDRESS:{
			for(c = 0; c <= 7; c++) {
		    	buffer[h++] = frame->DestAddr[c];
		  	}
		}break;
	}

    if(frame->FCF.PanIDCompression == FALSE)
    {
        SET16_802154(buffer, h, frame->SrcPANID);
        h += 2;
    }

	switch(frame->FCF.SrcAddrMode)
	{
		case PAN_IDENTIFIER:{
		}break;
		case SHORT_AdDDRESS:{
			buffer[h++] = frame->SrcAddr[0];
			buffer[h++] = frame->SrcAddr[1];
		}break;
		case EXTENDED_ADDRESS:{
			for(c = 0; c <= 7; c++) {
		    	buffer[h++] = frame->SrcAddr[c];
		  	}
		}break;
	}

	if(frame->length > MAC_MAX_PAYLOAD_LENGTH)
        frame->length = MAC_MAX_PAYLOAD_LENGTH;
    if(frame->length > MAC_MAX_LENGTH - MACgethdrLen(*frame))
        return;

    (*len) = frame->length + MACgethdrLen(*frame);

    memcpy(&buffer[h], frame->Payload, frame->length);
//    for(int i = 0; i < frame->length; i++)
//    {
//        buffer[h + i] = frame->Payload[i];
//    }
}

/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/* ----------------------------------------------------------------
	User space: global variables and handler macro/function 
	definition
   ---------------------------------------------------------------- */

//Output MAC frame Info holder
MAC_Frame_t FrameOut;
//Input MAC frame Info holder
MAC_Frame_t FrameIn;

///initializes MAC layer with default values. takes no arguments
///these values could be changed obviously, by macro's defined
void init_framer(void);
void init_framer()
{
	uint8_t srcaddr[8];
    uint8_t destaddr[8];
    srcaddr[0] = 0x02;
    srcaddr[1] = 0x12;
    srcaddr[2] = 0x4b;
    srcaddr[3] = 0x00;
    srcaddr[4] = 0x05;
    srcaddr[5] = 0xad;
    srcaddr[6] = 0x92;
    srcaddr[7] = 0x8b;

    destaddr[0] = 0x02;
    destaddr[1] = 0x12;
    destaddr[2] = 0x4b;
    destaddr[3] = 0x00;
    destaddr[4] = 0x05;
    destaddr[5] = 0xad;
    destaddr[6] = 0x92;
    destaddr[7] = 0x8c;

    FrameOut.FCF.FrameType = DATA;
    FrameOut.FCF.SecurityEnabled = FALSE;
    FrameOut.FCF.FramePend = FALSE;
    FrameOut.FCF.AckRequset = FALSE;
    FrameOut.FCF.PanIDCompression = TRUE;
    FrameOut.FCF.RSVD = 0;
    FrameOut.FCF.DestAddrMode = EXTENDED_ADDRESS;
    FrameOut.FCF.FrameVersion = 0;
    FrameOut.FCF.SrcAddrMode = EXTENDED_ADDRESS;

    FrameOut.SequenceNumber = 0;
    FrameOut.DestPANID = 0x5449;
    MAC_SET_ADDRESS(FrameOut.DestAddr, destaddr, 8);
    FrameOut.SrcPANID = 0x5449;
    MAC_SET_ADDRESS(FrameOut.SrcAddr, srcaddr, 8);
    FrameOut.length = MACgetPayloadLength(FrameOut);
}


///takes a pointer to output buffer and a pointer to it's size
///args:: _buffer: pointer to output buffer, generated frame will be placed here
///       _len: pointer to the variable containing maximum size of frame that is expected from MAC layer
///             after execution this will contain actual size of the generated frame
#define framerOut802154(_buffer, _len) ({ FrameOut.FCF.RSVD = 0;																\
									   FrameOut.SequenceNumber = (FrameOut.SequenceNumber % 254) + 1;						\
									   if(FrameOut.DestPANID == FrameOut.SrcPANID) FrameOut.FCF.PanIDCompression = TRUE;	\
									   else FrameOut.FCF.PanIDCompression = FALSE;											\
									   MACframecreate(&FrameOut, _buffer, _len); })
//frame type can be determined by calling ecah of these macros respectively
#define asBeaconFrame802154 ({FrameOut.FCF.FrameType = BEACON;})
#define asDataFrame802154 ({FrameOut.FCF.FrameType = DATA;})
#define asAcknowledgementFrame802154 ({FrameOut.FCF.FrameType = ACKNOWLEDGEMENT;})
#define asCommandFrame802154 ({FrameOut.FCF.FrameType = MAC_COMMAND;})
//frame pending state can be determined by calling these macros respectively
#define framePending802154 ({ FrameOut.FCF.FramePend = TRUE; })
#define NoFramePending802154 ({ FrameOut.FCF.FramePend = FALSE; })
//ACK request state can be detemined by calling these macros respectively
#define AckRequest802154 ({FrameOut.FCF.AckRequset = TRUE;})
#define NoAckRequest802154 ({FrameOut.FCF.AckRequset = FALSE;})
///takes a pointer to 64byte memory which contains the address. it can also be short address with zeros added to its end
///arg's:: _addr: pointer(uint8_t*) to 64byte address array
#define setSrcAddr802154(_addr) (MAC_SET_ADDRESS(FrameOut.SrcAddr, _addr, 8))
#define setDestAddr802154(_addr) (MAC_SET_ADDRESS(FrameOut.DestAddr, _addr, 8))
//addresses are accessible with these macros
#define srcAddr802154 (FrameOut.SrcAddr)
#define destAddr802154 (FrameOut.DestAddr)
///sets PAN IDs which are given to it by a 16bit uint16_t variable _ID
///arg's:: _ID: uint16_t PAN ID
#define srcPanID(_ID) (FrameOut.SrcPANID = _ID)
#define destPanID(_ID) (FrameOut.DestPANID = _ID)
//with this macro you can access maximum payload length which is available for MAC layer
#define maxPayload802154 (MACgetPayloadLength(FrameOut))
//access output frame payload
#define data802154 (FrameOut.Payload)
//access output frame payload length
#define dataLen802154 (FrameOut.length)


///takes a pointer input frame and it's length as arguments
///args:: _buffer: pointer(uint8_t*) to the received frame
///       _len: lenght of received frame which is a uint8_t type
#define framerIn802154(_buffer, _len) ({ MACframeparser(_buffer, _len, &FrameIn); })
/////last input frame/////////
//frame type can be determined by calling ecah of these macros respectively
#define lifIsBeaconFrame802154 (FrameIn.FCF.FrameType == BEACON)
#define lifIsDataFrame802154 (FrameIn.FCF.FrameType == DATA)
#define lifIsAcknowledgementFrame802154 (FrameIn.FCF.FrameType == ACKNOWLEDGEMENT)
#define lifIsCommandFrame802154 (FrameIn.FCF.FrameType == MAC_COMMAND)
//frame pending state can be determined by calling this macro
#define lifframePending802154 (FrameIn.FCF.FramePend == TRUE)
//ACK request state can be determined by calling these macros
#define lifAckRequest802154 (FrameIn.FCF.AckRequset == TRUE)
#define lifNoAckRequest802154 ({FrameOut.FCF.AckRequset == FALSE)
//addresses are accessible with these macros
#define lifSrcAddr802154 (FrameIn.SrcAddr)
#define lifDestAddr802154 (FrameIn.DestAddr)
//PAN IDs are accessible by these macros respectively
#define lifsrcPanID (FrameIn.SrcPANID)
#define lifdestPanID (FrameOut.DestPANID)
//with this macro you can access maximum payload length which is available for the received frame
#define lifmaxPayload802154 (MACgetPayloadLength(FrameIn))
//access input frame payload
#define lifdata802154 (FrameIn.Payload)
//access input frame payload length
#define lifdataLen802154 (FrameIn.length)

//////////////// End of handler macros/functions ////////////////////////
/////////////////////////////////////////////////////////////////////////

#endif
