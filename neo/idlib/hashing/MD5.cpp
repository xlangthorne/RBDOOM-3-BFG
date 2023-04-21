// module;

// #include <cstring>
#include "../precompiled.h"
#pragma hdrstop

// MD5 hashing -- updated for 64 bit

// module Lib.Hashing;

// import Sys.Types;

// =============================================================================================
// Contains the MD5BlockChecksum implementation.
// =============================================================================================

// POINTER defines a generic pointer type
typedef unsigned char* POINTER;

// UINT2 defines a two byte word
typedef unsigned short int UINT2;

// UINT4 defines a four byte word
typedef unsigned int UINT4;

//	XML: converted macros to constexpr

//------------------------
// The four core functions - F1 is optimized somewhat
// JDC: I wouldn't have condoned the change in something as sensitive as a hash function,
// but it looks ok and a random test function checked it out.
//------------------------
//	#define F1(x, y, z) (x & y | ~x & z) 
template<typename T1, typename T2, typename T3>
constexpr auto F1(T1 x, T2  y, T3  z) {
	return (z ^ (x & (y ^ z)));
}

template<typename T1, typename T2, typename T3>
constexpr auto F2(T1 x, T2  y, T3  z) {
	return F1(z, x, y);
}

template<typename T1, typename T2, typename T3>
constexpr auto F3(T1 x, T2  y, T3  z) {
	return (x ^ y ^ z);
}

template<typename T1, typename T2, typename T3>
constexpr auto F4(T1 x, T2  y, T3  z) {
	return (y ^ (x | ~z));
}
//	XML end


// This is the central step in the MD5 algorithm. */

//	XML: commented out, since it's been expanded inline for the entirety of the file.
//	If something breaks, I'll revert; for now this seems the most hygenic option.

//	#define MD5STEP(f, w, x, y, z, data, s) ( w += f(x, y, z) + data,  w = w<<s | w>>(32-s),  w += x )

//	XML end


static unsigned char PADDING[64] = {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

// ========================
// Encode
// 
// Encodes input (UINT4) into output (unsigned char). Assumes len is a multiple of 4.
// ========================
static void Encode( unsigned char* output, UINT4* input, unsigned int len ) {
	unsigned int i, j;

	for ( i = 0, j = 0; j < len; i++, j += 4 ) {
		output[j] = ( unsigned char )( input[i] & 0xff );
		output[j + 1] = ( unsigned char )( ( input[i] >> 8 ) & 0xff );
		output[j + 2] = ( unsigned char )( ( input[i] >> 16 ) & 0xff );
		output[j + 3] = ( unsigned char )( ( input[i] >> 24 ) & 0xff );
	}
}


// ========================
// Decode
// 
// Decodes input (unsigned char) into output (UINT4). Assumes len is a multiple of 4.
// ========================
static void Decode( UINT4* output, const unsigned char* input, unsigned int len )
{
	unsigned int i, j;

	for ( i = 0, j = 0; j < len; i++, j += 4 )	{
		output[i] = ( ( UINT4 )input[j] ) | ( ( ( UINT4 )input[j + 1] ) << 8 ) | ( ( ( UINT4 )input[j + 2] ) << 16 ) | ( ( ( UINT4 )input[j + 3] ) << 24 );
	}
}


// ====================================================================
// MD5_Transform
// 
// The core of the MD5 algorithm, this alters an existing MD5 hash to
// reflect the addition of 16 longwords of new data.  MD5Update blocks
// the data and converts bytes into longwords for this routine.
// ====================================================================

void MD5_Transform( unsigned int state[4], const unsigned char block[64] ) {
	unsigned int a, b, c, d, x[16];

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];

	Decode( x, block, 64 );

	//	XML: expanded macros on general principles

	( a += F1(b, c, d) + x[0]  + 0xd76aa478, a = a << 7  | a >> (32 - 7),  a += b );
	( d += F1(a, b, c) + x[1]  + 0xe8c7b756, d = d << 12 | d >> (32 - 12), d += a );
	( c += F1(d, a, b) + x[2]  + 0x242070db, c = c << 17 | c >> (32 - 17), c += d );
	( b += F1(c, d, a) + x[3]  + 0xc1bdceee, b = b << 22 | b >> (32 - 22), b += c );
	( a += F1(b, c, d) + x[4]  + 0xf57c0faf, a = a << 7  | a >> (32 - 7),  a += b );
	( d += F1(a, b, c) + x[5]  + 0x4787c62a, d = d << 12 | d >> (32 - 12), d += a );
	( c += F1(d, a, b) + x[6]  + 0xa8304613, c = c << 17 | c >> (32 - 17), c += d );
	( b += F1(c, d, a) + x[7]  + 0xfd469501, b = b << 22 | b >> (32 - 22), b += c );
	( a += F1(b, c, d) + x[8]  + 0x698098d8, a = a << 7  | a >> (32 - 7),  a += b );
	( d += F1(a, b, c) + x[9]  + 0x8b44f7af, d = d << 12 | d >> (32 - 12), d += a );
	( c += F1(d, a, b) + x[10] + 0xffff5bb1, c = c << 17 | c >> (32 - 17), c += d );
	( b += F1(c, d, a) + x[11] + 0x895cd7be, b = b << 22 | b >> (32 - 22), b += c );
	( a += F1(b, c, d) + x[12] + 0x6b901122, a = a << 7  | a >> (32 - 7),  a += b );
	( d += F1(a, b, c) + x[13] + 0xfd987193, d = d << 12 | d >> (32 - 12), d += a );
	( c += F1(d, a, b) + x[14] + 0xa679438e, c = c << 17 | c >> (32 - 17), c += d );
	( b += F1(c, d, a) + x[15] + 0x49b40821, b = b << 22 | b >> (32 - 22), b += c );
	  																			  
	( a += F2(b, c, d) + x[1]  + 0xf61e2562, a = a << 5  | a >> (32 - 5),  a += b );
	( d += F2(a, b, c) + x[6]  + 0xc040b340, d = d << 9  | d >> (32 - 9),  d += a );
	( c += F2(d, a, b) + x[11] + 0x265e5a51, c = c << 14 | c >> (32 - 14), c += d );
	( b += F2(c, d, a) + x[0]  + 0xe9b6c7aa, b = b << 20 | b >> (32 - 20), b += c );
	( a += F2(b, c, d) + x[5]  + 0xd62f105d, a = a << 5	 | a >> (32 - 5),  a += b );
	( d += F2(a, b, c) + x[10] + 0x02441453, d = d << 9  | d >> (32 - 9),  d += a );
	( c += F2(d, a, b) + x[15] + 0xd8a1e681, c = c << 14 | c >> (32 - 14), c += d );
	( b += F2(c, d, a) + x[4]  + 0xe7d3fbc8, b = b << 20 | b >> (32 - 20), b += c );
	( a += F2(b, c, d) + x[9]  + 0x21e1cde6, a = a << 5  | a >> (32 - 5),  a += b );
	( d += F2(a, b, c) + x[14] + 0xc33707d6, d = d << 9  | d >> (32 - 9),  d += a );
	( c += F2(d, a, b) + x[3]  + 0xf4d50d87, c = c << 14 | c >> (32 - 14), c += d );
	( b += F2(c, d, a) + x[8]  + 0x455a14ed, b = b << 20 | b >> (32 - 20), b += c );
	( a += F2(b, c, d) + x[13] + 0xa9e3e905, a = a << 5  | a >> (32 - 5),  a += b );
	( d += F2(a, b, c) + x[2]  + 0xfcefa3f8, d = d << 9  | d >> (32 - 9),  d += a );
	( c += F2(d, a, b) + x[7]  + 0x676f02d9, c = c << 14 | c >> (32 - 14), c += d );
	( b += F2(c, d, a) + x[12] + 0x8d2a4c8a, b = b << 20 | b >> (32 - 20), b += c );
	  																			  
	( a += F3(b, c, d) + x[5]  + 0xfffa3942, a = a << 4  | a >> (32 - 4),  a += b );
	( d += F3(a, b, c) + x[8]  + 0x8771f681, d = d << 11 | d >> (32 - 11), d += a );
	( c += F3(d, a, b) + x[11] + 0x6d9d6122, c = c << 16 | c >> (32 - 16), c += d );
	( b += F3(c, d, a) + x[14] + 0xfde5380c, b = b << 23 | b >> (32 - 23), b += c );
	( a += F3(b, c, d) + x[1]  + 0xa4beea44, a = a << 4  | a >> (32 - 4),  a += b );
	( d += F3(a, b, c) + x[4]  + 0x4bdecfa9, d = d << 11 | d >> (32 - 11), d += a );
	( c += F3(d, a, b) + x[7]  + 0xf6bb4b60, c = c << 16 | c >> (32 - 16), c += d );
	( b += F3(c, d, a) + x[10] + 0xbebfbc70, b = b << 23 | b >> (32 - 23), b += c );
	( a += F3(b, c, d) + x[13] + 0x289b7ec6, a = a << 4  | a >> (32 - 4),  a += b );
	( d += F3(a, b, c) + x[0]  + 0xeaa127fa, d = d << 11 | d >> (32 - 11), d += a );
	( c += F3(d, a, b) + x[3]  + 0xd4ef3085, c = c << 16 | c >> (32 - 16), c += d );
	( b += F3(c, d, a) + x[6]  + 0x04881d05, b = b << 23 | b >> (32 - 23), b += c );
	( a += F3(b, c, d) + x[9]  + 0xd9d4d039, a = a << 4  | a >> (32 - 4),  a += b );
	( d += F3(a, b, c) + x[12] + 0xe6db99e5, d = d << 11 | d >> (32 - 11), d += a );
	( c += F3(d, a, b) + x[15] + 0x1fa27cf8, c = c << 16 | c >> (32 - 16), c += d );
	( b += F3(c, d, a) + x[2]  + 0xc4ac5665, b = b << 23 | b >> (32 - 23), b += c );
	  																			  
	( a += F4(b, c, d) + x[0]  + 0xf4292244, a = a << 6  | a >> (32 - 6),  a += b );
	( d += F4(a, b, c) + x[7]  + 0x432aff97, d = d << 10 | d >> (32 - 10), d += a );
	( c += F4(d, a, b) + x[14] + 0xab9423a7, c = c << 15 | c >> (32 - 15), c += d );
	( b += F4(c, d, a) + x[5]  + 0xfc93a039, b = b << 21 | b >> (32 - 21), b += c );
	( a += F4(b, c, d) + x[12] + 0x655b59c3, a = a << 6  | a >> (32 - 6),  a += b );
	( d += F4(a, b, c) + x[3]  + 0x8f0ccc92, d = d << 10 | d >> (32 - 10), d += a );
	( c += F4(d, a, b) + x[10] + 0xffeff47d, c = c << 15 | c >> (32 - 15), c += d );
	( b += F4(c, d, a) + x[1]  + 0x85845dd1, b = b << 21 | b >> (32 - 21), b += c );
	( a += F4(b, c, d) + x[8]  + 0x6fa87e4f, a = a << 6  | a >> (32 - 6),  a += b );
	( d += F4(a, b, c) + x[15] + 0xfe2ce6e0, d = d << 10 | d >> (32 - 10), d += a );
	( c += F4(d, a, b) + x[6]  + 0xa3014314, c = c << 15 | c >> (32 - 15), c += d );
	( b += F4(c, d, a) + x[13] + 0x4e0811a1, b = b << 21 | b >> (32 - 21), b += c );
	( a += F4(b, c, d) + x[4]  + 0xf7537e82, a = a << 6  | a >> (32 - 6),  a += b );
	( d += F4(a, b, c) + x[11] + 0xbd3af235, d = d << 10 | d >> (32 - 10), d += a );
	( c += F4(d, a, b) + x[2]  + 0x2ad7d2bb, c = c << 15 | c >> (32 - 15), c += d );
	( b += F4(c, d, a) + x[9]  + 0xeb86d391, b = b << 21 | b >> (32 - 21), b += c );
																				  
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;

	// Zeroize sensitive information.
	memset((POINTER)x, 0, sizeof(x));
}

/*
========================
MD5_Init

MD5 initialization. Begins an MD5 operation, writing a new context.
========================
*/
void MD5_Init( MD5_CTX* ctx )
{
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xefcdab89;
	ctx->state[2] = 0x98badcfe;
	ctx->state[3] = 0x10325476;

	ctx->bits[0] = 0;
	ctx->bits[1] = 0;
}

/*
========================
MD5_Update

MD5 block update operation. Continues an MD5 message-digest operation, processing another
message block, and updating the context.
========================
*/
void MD5_Update(MD5_CTX* context, unsigned char const* input, size_t inputLen)
{
	unsigned int i, index, partLen;

	// Compute number of bytes mod 64
	index = (unsigned int)((context->bits[0] >> 3) & 0x3F);

	// Update number of bits
	if ((context->bits[0] += ((UINT4)inputLen << 3)) < ((UINT4)inputLen << 3)) 	{
		context->bits[1]++;
	}

	context->bits[1] += ((UINT4)inputLen >> 29);

	partLen = 64 - index;

	// Transform as many times as possible.
	if ( inputLen >= partLen ) 	{
		memcpy((POINTER)&context->in[index], (POINTER)input, partLen);
		MD5_Transform(context->state, context->in);

		for (i = partLen; i + 63 < inputLen; i += 64) 		{
			MD5_Transform(context->state, &input[i]);
		}

		index = 0;
	}
	else {
		i = 0;
	}

	// Buffer remaining input
	memcpy( ( POINTER )&context->in[index], (POINTER)&input[i], inputLen - i );
}

/*
========================
MD5_Final

MD5 finalization. Ends an MD5 message-digest operation, writing the message digest and
zero-izing the context.
========================
*/
void MD5_Final( MD5_CTX* context, unsigned char digest[16] )
{
	unsigned char bits[8];
	unsigned int index, padLen;

	// Save number of bits
	Encode(bits, context->bits, 8);

	// Pad out to 56 mod 64.
	index = (unsigned int)((context->bits[0] >> 3) & 0x3f);
	padLen = (index < 56) ? (56 - index) : (120 - index);
	MD5_Update(context, PADDING, padLen);

	// Append length (before padding)
	MD5_Update(context, bits, 8);

	// Store state in digest
	Encode(digest, context->state, 16);

	// Zeroize sensitive information.
	memset( (POINTER)context, 0, sizeof(*context) );
}

/*
========================
MD5_BlockChecksum
========================
*/

unsigned int MD5_BlockChecksum(const void* data, size_t length) {
	unsigned char	digest[16];
	unsigned int	val;
	MD5_CTX			ctx;

	MD5_Init(&ctx);
	MD5_Update(&ctx, ( unsigned char* )data, length );
	MD5_Final(&ctx, ( unsigned char* )digest );

	// Handle it manually to be endian-safe since we don't have access to idSwap.
	val =	(digest[3] << 24  | digest[2] << 16  | digest[1] << 8  | digest[0]) ^
			(digest[7] << 24  | digest[6] << 16  | digest[5] << 8  | digest[4]) ^
			(digest[11] << 24 | digest[10] << 16 | digest[9] << 8  | digest[8]) ^
			(digest[15] << 24 | digest[14] << 16 | digest[13] << 8 | digest[12]);

	return val;
}
