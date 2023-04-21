// module;

#include "../precompiled.h"
#pragma hdrstop


// #include <cstring>

// module Lib.Hashing;

//   RSA Data Security, Inc., MD4 message-digest algorithm. (RFC1320)


// ====================================================================

// Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
// rights reserved.
// 
// License to copy and use this software is granted provided that it
// is identified as the "RSA Data Security, Inc. MD4 Message-Digest
// Algorithm" in all material mentioning or referencing this software
// or this function.
// 
// License is also granted to make and use derivative works provided
// that such works are identified as "derived from the RSA Data
// Security, Inc. MD4 Message-Digest Algorithm" in all material
// mentioning or referencing the derived work.
// 
// RSA Data Security, Inc. makes no representations concerning either
// the merchantability of this software or the suitability of this
// software for any particular purpose. It is provided "as is"
// without express or implied warranty of any kind.
// 
// These notices must be retained in any copies of any part of this
// documentation and/or software.
// 

// ====================================================================


/// POINTER defines a generic pointer type 
typedef unsigned char* POINTER;

/// UINT2 defines a two byte word 
typedef unsigned short int UINT2;

/// UINT4 defines a four byte word 
// RB: 64 bit fix, changed long int to int
typedef unsigned int UINT4;
// RB end

/// MD4 context. 
typedef struct {
	UINT4 state[4];				// state (ABCD) 
	UINT4 count[2];				// number of bits, modulo 2^64 (lsb first)
	unsigned char buffer[64];	// input buffer
} MD4_CTX;

/// Constants for MD4Transform routine. 
constexpr auto S11 = 3;
constexpr auto S12 = 7;
constexpr auto S13 = 11;
constexpr auto S14 = 19;
constexpr auto S21 = 3;
constexpr auto S22 = 5;
constexpr auto S23 = 9;
constexpr auto S24 = 13;
constexpr auto S31 = 3;
constexpr auto S32 = 9;
constexpr auto S33 = 11;
constexpr auto S34 = 15;

static unsigned char PADDING[64] = {
0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

// F, G and H are basic MD4 functions. 
template<typename T1, typename T2, typename T3>
constexpr auto F(T1 x, T2  y, T3  z) {
	return ((x & y) | (~x & z));
}
template<typename T1, typename T2, typename T3>
constexpr auto G(T1 x, T2  y, T3  z) {
	return ((x & y) | (x & z) | (y & z));
}
template<typename T1, typename T2, typename T3>
constexpr auto H(T1 x, T2  y, T3  z) {
	return (x ^ y ^ z);
}

/// ROTATE_LEFT rotates x left n bits.
template<typename T1, typename T2>
constexpr auto ROTATE_LEFT(T1 x, T2  n) {
	return ((x << n) | (x >> (32 - n)));
}

/// FF, GG and HH are transformations for rounds 1, 2 and 3
/// Rotation is separate from addition to prevent recomputation
//
//	XML: commented out after expanding inline
// #define FF(a, b, c, d, x, s) {(a) += F ((b), (c), (d)) + (x); (a) = ROTATE_LEFT ((a), (s));}

// #define GG(a, b, c, d, x, s) {(a) += G ((b), (c), (d)) + (x) + (UINT4)0x5a827999; (a) = ROTATE_LEFT ((a), (s));}

// #define HH(a, b, c, d, x, s) {(a) += H ((b), (c), (d)) + (x) + (UINT4)0x6ed9eba1; (a) = ROTATE_LEFT ((a), (s));}


// Encodes input (UINT4) into output (unsigned char). Assumes len is a multiple of 4. 
static void Encode(unsigned char* output, UINT4* input, unsigned int len) {
	unsigned int i, j;

	for (i = 0, j = 0; j < len; i++, j += 4) {
		output[j] = (unsigned char)(input[i] & 0xff);
		output[j + 1] = (unsigned char)((input[i] >> 8) & 0xff);
		output[j + 2] = (unsigned char)((input[i] >> 16) & 0xff);
		output[j + 3] = (unsigned char)((input[i] >> 24) & 0xff);
	}
}

// Decodes input (unsigned char) into output (UINT4). Assumes len is a multiple of 4. 
static void Decode(UINT4* output, const unsigned char* input, unsigned int len) {
	unsigned int i, j;

	for (i = 0, j = 0; j < len; i++, j += 4) {
		output[i] = ((UINT4)input[j]) | (((UINT4)input[j + 1]) << 8) | (
			((UINT4)input[j + 2]) << 16) | (((UINT4)input[j + 3]) << 24);
	}
}

// MD4 basic transformation. Transforms state based on block. 
static void MD4_Transform(UINT4 state[4], const unsigned char block[64]) {
	UINT4 a = state[0], b = state[1], c = state[2], d = state[3], x[16];

	Decode(x, block, 64);

	// Round 1 
	{(a) += F((b), (c), (d)) + (x[0]); (a) = ROTATE_LEFT((a), (S11)); };			// 1  //
	{(d) += F((a), (b), (c)) + (x[1]); (d) = ROTATE_LEFT((d), (S12)); };			// 2  //
	{(c) += F((d), (a), (b)) + (x[2]); (c) = ROTATE_LEFT((c), (S13)); };			// 3  //
	{(b) += F((c), (d), (a)) + (x[3]); (b) = ROTATE_LEFT((b), (S14)); };			// 4  //
	{(a) += F((b), (c), (d)) + (x[4]); (a) = ROTATE_LEFT((a), (S11)); };			// 5  //
	{(d) += F((a), (b), (c)) + (x[5]); (d) = ROTATE_LEFT((d), (S12)); };			// 6  //
	{(c) += F((d), (a), (b)) + (x[6]); (c) = ROTATE_LEFT((c), (S13)); };			// 7  //
	{(b) += F((c), (d), (a)) + (x[7]); (b) = ROTATE_LEFT((b), (S14)); };			// 8  //
	{(a) += F((b), (c), (d)) + (x[8]); (a) = ROTATE_LEFT((a), (S11)); };			// 9  //
	{(d) += F((a), (b), (c)) + (x[9]); (d) = ROTATE_LEFT((d), (S12)); };			// 10 //
	{(c) += F((d), (a), (b)) + (x[10]); (c) = ROTATE_LEFT((c), (S13)); };			// 11 //
	{(b) += F((c), (d), (a)) + (x[11]); (b) = ROTATE_LEFT((b), (S14)); };			// 12 //
	{(a) += F((b), (c), (d)) + (x[12]); (a) = ROTATE_LEFT((a), (S11)); };			// 13 //
	{(d) += F((a), (b), (c)) + (x[13]); (d) = ROTATE_LEFT((d), (S12)); };			// 14 //
	{(c) += F((d), (a), (b)) + (x[14]); (c) = ROTATE_LEFT((c), (S13)); };			// 15 //
	{(b) += F((c), (d), (a)) + (x[15]); (b) = ROTATE_LEFT((b), (S14)); };			// 16 //

	// Round 2 
	{(a) += G((b), (c), (d)) + (x[0]) + (UINT4)0x5a827999; (a) = ROTATE_LEFT((a), (S21)); };			// 17 //
	{(d) += G((a), (b), (c)) + (x[4]) + (UINT4)0x5a827999; (d) = ROTATE_LEFT((d), (S22)); };			// 18 //
	{(c) += G((d), (a), (b)) + (x[8]) + (UINT4)0x5a827999; (c) = ROTATE_LEFT((c), (S23)); };			// 19 //
	{(b) += G((c), (d), (a)) + (x[12]) + (UINT4)0x5a827999; (b) = ROTATE_LEFT((b), (S24)); };			// 20 //
	{(a) += G((b), (c), (d)) + (x[1]) + (UINT4)0x5a827999; (a) = ROTATE_LEFT((a), (S21)); };			// 21 //
	{(d) += G((a), (b), (c)) + (x[5]) + (UINT4)0x5a827999; (d) = ROTATE_LEFT((d), (S22)); };			// 22 //
	{(c) += G((d), (a), (b)) + (x[9]) + (UINT4)0x5a827999; (c) = ROTATE_LEFT((c), (S23)); };			// 23 //
	{(b) += G((c), (d), (a)) + (x[13]) + (UINT4)0x5a827999; (b) = ROTATE_LEFT((b), (S24)); };			// 24 //
	{(a) += G((b), (c), (d)) + (x[2]) + (UINT4)0x5a827999; (a) = ROTATE_LEFT((a), (S21)); };			// 25 //
	{(d) += G((a), (b), (c)) + (x[6]) + (UINT4)0x5a827999; (d) = ROTATE_LEFT((d), (S22)); };			// 26 //
	{(c) += G((d), (a), (b)) + (x[10]) + (UINT4)0x5a827999; (c) = ROTATE_LEFT((c), (S23)); };			// 27 //
	{(b) += G((c), (d), (a)) + (x[14]) + (UINT4)0x5a827999; (b) = ROTATE_LEFT((b), (S24)); };			// 28 //
	{(a) += G((b), (c), (d)) + (x[3]) + (UINT4)0x5a827999; (a) = ROTATE_LEFT((a), (S21)); };			// 29 //
	{(d) += G((a), (b), (c)) + (x[7]) + (UINT4)0x5a827999; (d) = ROTATE_LEFT((d), (S22)); };			// 30 //
	{(c) += G((d), (a), (b)) + (x[11]) + (UINT4)0x5a827999; (c) = ROTATE_LEFT((c), (S23)); };			// 31 //
	{(b) += G((c), (d), (a)) + (x[15]) + (UINT4)0x5a827999; (b) = ROTATE_LEFT((b), (S24)); };			// 32 //

	// Round 3 
	{(a) += H((b), (c), (d)) + (x[0]) + (UINT4)0x6ed9eba1; (a) = ROTATE_LEFT((a), (S31)); };			// 33 //
	{(d) += H((a), (b), (c)) + (x[8]) + (UINT4)0x6ed9eba1; (d) = ROTATE_LEFT((d), (S32)); };			// 34 //
	{(c) += H((d), (a), (b)) + (x[4]) + (UINT4)0x6ed9eba1; (c) = ROTATE_LEFT((c), (S33)); };			// 35 //
	{(b) += H((c), (d), (a)) + (x[12]) + (UINT4)0x6ed9eba1; (b) = ROTATE_LEFT((b), (S34)); };			// 36 //
	{(a) += H((b), (c), (d)) + (x[2]) + (UINT4)0x6ed9eba1; (a) = ROTATE_LEFT((a), (S31)); };			// 37 //
	{(d) += H((a), (b), (c)) + (x[10]) + (UINT4)0x6ed9eba1; (d) = ROTATE_LEFT((d), (S32)); };			// 38 //
	{(c) += H((d), (a), (b)) + (x[6]) + (UINT4)0x6ed9eba1; (c) = ROTATE_LEFT((c), (S33)); };			// 39 //
	{(b) += H((c), (d), (a)) + (x[14]) + (UINT4)0x6ed9eba1; (b) = ROTATE_LEFT((b), (S34)); };			// 40 //
	{(a) += H((b), (c), (d)) + (x[1]) + (UINT4)0x6ed9eba1; (a) = ROTATE_LEFT((a), (S31)); };			// 41 //
	{(d) += H((a), (b), (c)) + (x[9]) + (UINT4)0x6ed9eba1; (d) = ROTATE_LEFT((d), (S32)); };			// 42 //
	{(c) += H((d), (a), (b)) + (x[5]) + (UINT4)0x6ed9eba1; (c) = ROTATE_LEFT((c), (S33)); };			// 43 //
	{(b) += H((c), (d), (a)) + (x[13]) + (UINT4)0x6ed9eba1; (b) = ROTATE_LEFT((b), (S34)); };			// 44 //
	{(a) += H((b), (c), (d)) + (x[3]) + (UINT4)0x6ed9eba1; (a) = ROTATE_LEFT((a), (S31)); };			// 45 //
	{(d) += H((a), (b), (c)) + (x[11]) + (UINT4)0x6ed9eba1; (d) = ROTATE_LEFT((d), (S32)); };			// 46 //
	{(c) += H((d), (a), (b)) + (x[7]) + (UINT4)0x6ed9eba1; (c) = ROTATE_LEFT((c), (S33)); };			// 47 //
	{(b) += H((c), (d), (a)) + (x[15]) + (UINT4)0x6ed9eba1; (b) = ROTATE_LEFT((b), (S34)); };			// 48 //

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;

	// Zeroize sensitive information.
	memset((POINTER)x, 0, sizeof(x));
}

//	XML end

// MD4 initialization. Begins an MD4 operation, writing a new context. 
void MD4_Init(MD4_CTX* context) {
	context->count[0] = context->count[1] = 0;

	// Load magic initialization constants.
	context->state[0] = 0x67452301;
	context->state[1] = 0xefcdab89;
	context->state[2] = 0x98badcfe;
	context->state[3] = 0x10325476;
}

// MD4 block update operation. Continues an MD4 message-digest operation, processing another 
// message block, and updating the context. 
void MD4_Update(MD4_CTX* context, const unsigned char* input, unsigned int inputLen) {
	unsigned int i, index, partLen;

	// Compute number of bytes mod 64 
	index = (unsigned int)((context->count[0] >> 3) & 0x3F);

	// Update number of bits
	if ((context->count[0] += ((UINT4)inputLen << 3)) < ((UINT4)inputLen << 3)) {
		context->count[1]++;
	}

	context->count[1] += ((UINT4)inputLen >> 29);

	partLen = 64 - index;

	// Transform as many times as possible.
	if (inputLen >= partLen) {
		memcpy((POINTER)&context->buffer[index], (POINTER)input, partLen);
		MD4_Transform(context->state, context->buffer);

		for (i = partLen; i + 63 < inputLen; i += 64) {
			MD4_Transform(context->state, &input[i]);
		}

		index = 0;
	}
	else {
		i = 0;
	}

	// Buffer remaining input 
	memcpy((POINTER)&context->buffer[index], (POINTER)&input[i], inputLen - i);
}

// MD4 finalization. Ends an MD4 message-digest operation, writing the message digest and 
// zeroizing the context. 
void MD4_Final(MD4_CTX* context, unsigned char digest[16]) {
	unsigned char bits[8];
	unsigned int index, padLen;

	// Save number of bits 
	Encode(bits, context->count, 8);

	// Pad out to 56 mod 64.
	index = (unsigned int)((context->count[0] >> 3) & 0x3f);
	padLen = (index < 56) ? (56 - index) : (120 - index);
	MD4_Update(context, PADDING, padLen);

	// Append length (before padding) 
	MD4_Update(context, bits, 8);

	// Store state in digest 
	Encode(digest, context->state, 16);

	// Zeroize sensitive information.
	memset((POINTER)context, 0, sizeof(*context));
}


// ===============
// MD4_BlockChecksum
// ===============

// RB: 64 bit fixes, changed long to int
unsigned int MD4_BlockChecksum(const void* data, int length) {
	unsigned int	digest[4];
	unsigned int	val;
	MD4_CTX			ctx;

	MD4_Init(&ctx);
	MD4_Update(&ctx, (unsigned char*)data, length);
	MD4_Final(&ctx, (unsigned char*)digest);

	val = digest[0] ^ digest[1] ^ digest[2] ^ digest[3];

	return val;
}
// RB end