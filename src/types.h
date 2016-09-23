#ifndef TYPES
#define TYPES

//Standard Types for EASE OF USE ;)

typedef unsigned char  bool_t;

#ifndef FREEBSD

typedef signed char		int8_t;
typedef short int		int16_t;
typedef int			int32_t;
typedef long long  int64_t;
typedef unsigned char		uint8_t;
typedef unsigned short int	uint16_t;
typedef unsigned int		uint32_t;
typedef unsigned long long   uint64_t;
#endif
typedef unsigned int   PointerType;

#ifndef FREEBSD

# define TRUE 			(1)
# define FALSE 			(0)

# define INT8_MIN		(-128)
# define INT16_MIN		(-32767-1)
# define INT32_MIN		(-2147483647-1)
# define INT64_MIN      (-9223372036854775807LL - 1)

# define INT8_MAX		(127)
# define INT16_MAX		(32767)
# define INT32_MAX		(2147483647)
# define INT64_MAX      (9223372036854775807LL)

# define UINT8_MAX		(255)
# define UINT16_MAX		(65535)
# define UINT32_MAX		(4294967295U)
# define UINT64_MAX     (0xffffffffffffffffULL)

#endif

//End of standard types

#endif // TYPES
