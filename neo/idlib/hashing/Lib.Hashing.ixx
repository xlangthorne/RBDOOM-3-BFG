export module Lib.Hashing;

export
{

	// 	Calculates a checksum for a block of data using the CRC-32 algorithm.

	void CRC32_InitChecksum(unsigned int& crcvalue);
	void CRC32_UpdateChecksum(unsigned int& crcvalue, const void* data, int length);
	void CRC32_FinishChecksum(unsigned int& crcvalue);
	unsigned int CRC32_BlockChecksum(const void* data, int length);

	//	Calculates a checksum for a block of data using the MD4 message-digest algorithm.
	unsigned int MD4_BlockChecksum(const void* data, int length);

	//	Calculates a checksum for a block of data using the MD5 message-digest algorithm.
	struct MD5_CTX
	{
		unsigned int	state[4];
		unsigned int	bits[2];
		unsigned char	in[64];
	};

	void MD5_Init(MD5_CTX* ctx);
	void MD5_Update(MD5_CTX* context, unsigned char const* input, size_t inputLen);
	void MD5_Final(MD5_CTX* context, unsigned char digest[16]);

	unsigned int MD5_BlockChecksum(const void* data, size_t length);

	//	TODO: add SHA256?  Replace CRC32?
};