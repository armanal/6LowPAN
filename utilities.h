#ifndef UTILITIES
#define UTILITIES

/*  -----------------------------------------------------------
    Converting from one ST type to another
    -----------------------------------------------------------  */
#define GET_BIT(_BYTE, _BIT) ((_BYTE >> _BIT) & 1)

/* ARCHITECT == 1 is BigEndian and ARCHITECT == 2 is LittleEndian
EX. usage: use precompiler ARCHITECT with LITTLE_ENDIAN_ARCH & BIG_ENDIAN_ARC*/
#if ARCHITECT == BIG_ENDIAN_ARC
#define GET16(ptr,index) (((uint16_t)((ptr)[index] << 8)) | ((ptr)[(index) + 1]))

#define SET16(ptr,index,value) do {     \
  (ptr)[index] = ((value) >> 8) & 0xff; \
  (ptr)[index + 1] = (value) & 0xff;    \
} while(0)

#elif ARCHITECT == LITTLE_ENDIAN_ARCH

#define GET16_802154(ptr,index) (((uint16_t)((ptr)[(index) + 1] << 8)) | ((ptr)[index]))

#define SET16_802154(ptr,index,value) do {     \
  (ptr)[index] = (value) & 0xff; \
  (ptr)[index + 1] = ((value) >> 8) & 0xff;    \
} while(0)

#define GET16(ptr,index) (((uint16_t)((ptr)[index] << 8)) | ((ptr)[(index) + 1]))

#define SET16(ptr,index,value) ({     \
  (ptr)[index] = ((value) >> 8) & 0xff; \
  (ptr)[index + 1] = (value) & 0xff;})

#endif // ARCHITECT

///   End of Conversion Macros     ////////////////////////////
///////////////////////////////////////////////////////////////

#endif // UTILITIES
