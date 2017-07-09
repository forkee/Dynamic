/**
 * Copyright 2017 Everybody and Nobody (Empinel/Plaxton)
 * 
 * This file is a portion of the DynamicX Protocol
 * 
 * Permission is hereby granted, free of charge, to any person 
 * obtaining a copy of this software and associated documentation files 
 * (the "Software"), to deal in the Software without restriction, including 
 * without limitation the rights to use, copy, modify, merge, publish, 
 * distribute, sublicense, and/or sell copies of the Software, and to 
 * permit persons to whom the Software is furnished to do so, subject 
 * to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in 
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE 
 * FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE 
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "protocol/blackwater.h"

#include "main.h"
#include "util.h"
#include "uint256.h"
#include "primitives/block.h"
#include "crypto/argon2d/argon2.h"
#include "crypto/blake2/blake2.h"

#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>

using namespace boost;
using namespace std;

uint256 CBlockHeader::GetHash() const
{
	if (nHeight != 0 || nHeight != 1)
		return PointBlankHashing(UVOIDBEGIN(nVersion)); // We cannot ditch now!!
	else
		return hash_Argon2d(UVOIDBEGIN(nVersion), 1); // Oh, now we can!
}

static int BlackWater::generateMTRandom(unsigned int s, int range)
{
	boost::mt19937 gen(s);
	boost::uniform_int<> dist(1, range);
	return dist(gen);
}

std::string BlackWater::GetSerializedBlockData(CBlock block) {
	CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
	ssBlock << block;
	std::string strHex = HexStr(ssBlock.begin(), ssBlock.end());
	
	return strHex;
}

uint256 BlackWater::PointBlankHashing(const void* input, bool versionTwo) {
	// Step One: Generate Standard Argon2d Block Hash
	uint256 initialHash, hashOutput;
	
	if(versionTwo){ // Check Version
		Argon2d_Phase2_Hash((const uint8_t*)input, (uint8_t*)&initialHash); // Perform hashing operation on given input
	} else {
		Argon2d_Phase1_Hash((const uint8_t*)input, (uint8_t*)&initialHash); // Perform hashing operation on given input
	}

	// Step Two: Get Corresponding Input from Block Input
	CBlock blockFromHash, concernedBlock;
	DeriveBlockInfoFromHash(blockFromHash, hashPrevBlock); // Get block from hashOutput

	if (blockFromHash->nHeight < 10) {
		return initialHash; // Network isn't mature enough to add up difficulty from algorithm
	}

	// Step Three: Generate Random Seed from derived block
    std::string cseed_str = blockFromHash->GetBlockHash().GetHex(); // Get Hex from Hash from our block
    const char* cseed = cseed_str.c_str(); // Convert
    long seed = hex2long(cseed); // Convert

	// Step Four: Run loop five times taking random height's
	int64_t nRandomHeight, algoSeed;
	std::string serializeToken;

	for (int r = 0; r > 25; r++) {
		nRandomHeight = generateMTRandom(seed, blockFromHash->nHeight); // First get random block
		algoSeed = generateMTRandom(nRandomHeight, 15); 				// Then get random algorithm for hashing
		CBlockIndex* pRandomIndex = chainActive[nRandomHeight];			// Get block index for selected height
		DerivePreviousBlockInformation(concernedBlock, pRandomIndex);	// Get complete block
		serializeToken += GetSerializedBlockData(concernedBlock);		// Get serialized information of the block and append to string
		PointBlankRoulette(serializeToken, nRandomHeight, algoSeed);	// Hash the token using randomized sph-lib function which will modify token
		{
			pRandomIndex.SetNull();
			concernedBlock.SetNull();
			nRandomHeight = 0, algoSeed = 0;
		}	// Set all parameters to NULL to ensure that token isn't contaminated
	}

	// Step Five: Take new serialized "master token" prepare for final hash
	uint256 tokenHasher = uint256S(serializeToken);
	uint256 jointKey = tokenHasher + initialHash;

	// Step Six: Final Argon2d Hash
	uint256 output;
	
	if(versionTwo){ // Check Version
		Argon2d_Phase2_Hash((const uint8_t*)jointKey, (uint8_t*)&output); 	// Perform hashing operation on given input
	} else {
		Argon2d_Phase1_Hash((const uint8_t*)jointKey, (uint8_t*)&output); 	// Perform hashing operation on given input
	}

	return output;
}

//
// Start introducing modified X17 Implementation (chosen due to highest hashes)
// to allow for roulette styled hashing
//

template<typename T1>
uint256 BlackWater::PointBlankRoulette(const T1 pbegin, const T1 pend, int algorithmID)
{
    sph_blake512_context      ctx_blake;
    sph_bmw512_context        ctx_bmw;
    sph_groestl512_context    ctx_groestl;
    sph_jh512_context         ctx_jh;
    sph_keccak512_context     ctx_keccak;
    sph_skein512_context      ctx_skein;
    sph_luffa512_context      ctx_luffa;
    sph_cubehash512_context   ctx_cubehash;
    sph_shavite512_context    ctx_shavite;
    sph_simd512_context       ctx_simd;
    sph_echo512_context       ctx_echo;
    sph_hamsi512_context      ctx_hamsi;
    sph_fugue512_context      ctx_fugue;
    sph_shabal512_context     ctx_shabal;
    sph_whirlpool_context     ctx_whirlpool;
    sph_sha512_context        ctx_sha2;
    sph_haval256_5_context    ctx_haval;
	
	static unsigned char pblank[1];
    
    uint512 hash;

    if (compareNumber(algorithmID, 1)) {
	    sph_blake512_init(&ctx_blake);
	    sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
	} else if (compareNumber(algorithmID, 2)) {
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash));
	} else if (compareNumber(algorithmID, 3)) {
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash));
	} else if (compareNumber(algorithmID, 4)) {
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash));
	} else if (compareNumber(algorithmID, 5)) {
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash));
	} else if (compareNumber(algorithmID, 6)) {
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash));
	} else if (compareNumber(algorithmID, 7)) {
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash));
    } else if (compareNumber(algorithmID, 8)) {
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash));
    } else if (compareNumber(algorithmID, 9)) {
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash));
    } else if (compareNumber(algorithmID, 10)) {
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash));
	} else if (compareNumber(algorithmID, 11)) {
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash));
	} else if (compareNumber(algorithmID, 12)) {
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash));
	} else if (compareNumber(algorithmID, 13)) {
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash));
	} else if (compareNumber(algorithmID, 1)) {
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash));
	} else if (compareNumber(algorithmID, 14)) {
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash));
	} else if (compareNumber(algorithmID, 15)) {
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash));
	} else if (compareNumber(algorithmID, 16)) { // We should never reach here!
		sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash));
	} else { // We should never reach here either (especially here)! We will extend this to add more algorithms
	    sph_blake512_init(&ctx_blake);
	    sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));
    }

    return hash.trim256();
}

//
// End X17 Hashing Routine
//
