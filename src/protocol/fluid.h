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

#ifndef FLUID_PROTOCOL_H
#define FLUID_PROTOCOL_H

#include "base58.h"
#include "amount.h"
#include "chain.h"
#include "script/script.h"
#include "consensus/validation.h"

#include <stdint.h>
#include <string.h>
#include <algorithm>

#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>

class CBlock;
class CBlockTemplate;

static const CAmount BLOCKCHAIN_INIT_REWARD = COIN * 0;
static const CAmount PHASE_1_POW_REWARD = COIN * 1;
static const CAmount PHASE_1_DYNODE_PAYMENT = COIN * 0.382;
static const CAmount PHASE_2_DYNODE_PAYMENT = COIN * 0.618;

//
// Ideal Mintage Script Formation Example:
//
// OP_MINT 3130303030303030303030303a3a313439393336353333363a3a445148697036443655376d46335761795a32747337794478737a71687779367a5a6a20494f42447a557167773
//         82b41426a39536b62656a6b47754773536a69556c6b6c616832514b314a676258525642613379515a33785a586b5249632f6633526951526458794552724a36595979764c306b
//         787945786573733d
//

enum KeyNumber {
	KEY_UNE = 1,
	KEY_DEUX = 2,
	KEY_TROIS = 3,
	
	KEY_MAX = 0
};

class Fluid {
private:
	CAmount DeriveSupplyPercentage(int64_t percentage, CBlockIndex* pindex);
		
	CAmount DeriveSupplyBurnt() {
		return 0 * COIN; // We create trackable money supply
	}
	
	// TODO: Switch to CryptoPP
	std::string StringToHex(std::string input) {
		static const char* const lut = "0123456789ABCDEF";
		size_t len = input.length();
		std::string output;
		output.reserve(2 * len);
		for (size_t i = 0; i < len; ++i)
		{
			const unsigned char c = input[i];
			output.push_back(lut[c >> 4]);
			output.push_back(lut[c & 15]);
		}
		
		return output;
	}
	
	// TODO: Switch to CryptoPP
	std::string HexToString(std::string in) {
		std::string output;
		if ((in.length() % 2) != 0) {
			throw std::runtime_error("Provided Hex String is not valid");
		}
			size_t cnt = in.length() / 2;
			for (size_t i = 0; cnt > i; ++i) {
				uint32_t s = 0;
				std::stringstream ss;
				ss << std::hex << in.substr(i * 2, 2);
				ss >> s;
					output.push_back(static_cast<unsigned char>(s));
		}
		return output;
	}

	/*
	 * The three keys controlling the multiple signature system
	 */
	std::string defaultFluidAddressX = "DEmrYUjVeLQnuvLnZjqzCex9azDRAtPzUa"; // MnjEkYWghQhBqSQSixDGVPpzrtYWrg1s1BZVuvznK3SF7s5dRmzd
	std::string defaultFluidAddressY = "DM1sv8zT529d7rYPtGX5kKM2MjD8YrHg5D"; // Mn64HNSDehPY4KKP8bZCMvcweYS7wrNszNWGvPHamcyPhjoZABSp
	std::string defaultFluidAddressZ = "DKPH9BdcrVyWwRsUVbPtaUQSwJWv2AMrph"; // MpPYgqNRGf8qQqkuds6si6UEfpddfps1NJ1uTVbp7P3g3imJLwAC

	enum OverrideType {
		MINING_OVERRIDE,
		DYNODE_OVERRIDE,
		MAX_OVERRIDE
	};

public:
	static const CAmount fluidMintingMinimum = 100 * COIN;
	CAmount fluidMintingMaximum = 99999; // DeriveSupplyPercentage(10); // Maximum 10% can be minted!
	
	void ConvertToHex(std::string &input) { std::string output = StringToHex(input); input = output; }
	void ConvertToString(std::string &input) { std::string output = HexToString(input); input = output; }

	const char* fluidImportantAddress(KeyNumber adr) {
		if (adr == KEY_UNE) { return (fluidAddressX.c_str()); }
		else if (adr == KEY_DEUX) { return (fluidAddressY.c_str()); }
		else if (adr == KEY_TROIS) { return (fluidAddressZ.c_str()); }
		else { return "Invalid Address Requested"; }
	}
	
	bool IsGivenKeyMaster(CDynamicAddress inputKey, int &whichOne);
	bool HowManyKeysWeHave(CDynamicAddress inputKey, bool &keyOne, bool &keyTwo, bool &keyThree);
	bool CheckIfQuorumExists(std::string token, std::string &message, bool individual = false);
	bool GenericConsentMessage(std::string message, std::string &signedString, CDynamicAddress signer);
//	bool DerivePreviousBlockInformation(CBlock &block, const CBlockIndex* fromDerive);

	bool IsItHardcoded(std::string givenScriptPubKey);
	bool InitiateFluidVerify(CDynamicAddress dynamicAddress);
	bool SignIntimateMessage(CDynamicAddress address, std::string unsignedMessage, std::string &stitchedMessage, bool stitch = true);
	
	bool GenericSignMessage(std::string message, std::string &signedString, CDynamicAddress signer);
	bool GenericParseNumber(std::string scriptString, CAmount &howMuch);
	bool GenericVerifyInstruction(std::string uniqueIdentifier, CDynamicAddress signer, std::string &messageTokenKey /* Added so the token key can be intercepted */, int whereToLook=1);
	
	bool GenerateFluidToken(CDynamicAddress sendToward, 
							CAmount tokenMintAmt, std::string &issuanceString);

	bool ParseMintKey(int64_t nTime, CDynamicAddress &destination, CAmount &coinAmount, std::string uniqueIdentifier);
	bool ParseDestructionAmount(std::string scriptString, CAmount coinsSpent, CAmount &coinsDestroyed);

	bool GetMintingInstructions(const CBlockHeader& block, CValidationState& state, CDynamicAddress &toMintAddress, CAmount &mintAmount);
	void GetDestructionTxes(const CBlockHeader& block, CValidationState& state, CAmount &amountDestroyed);
	
	bool GenerateKillToken(std::string &killString, CDynamicAddress signer);
	bool GetKillRequest(const CBlockHeader& block, CValidationState& state);
	
	bool GetProofOverrideRequest(const CBlockHeader& block, CValidationState& state, CAmount &howMuch);
	bool GetDynodeOverrideRequest(const CBlockHeader& block, CValidationState& state, CAmount &howMuch);
};

/** Standard Reward Payment Determination Functions */
CAmount GetPoWBlockPayment(const int& nHeight, CAmount nFees);
CAmount GetDynodePayment(bool fDynode = true);

/** Override Logic Switch for Reward Payment Determination Functions */
CAmount getBlockSubsidyWithOverride(const int& nHeight, CAmount nFees, CAmount lastOverrideCommand);
CAmount getDynodeSubsidyWithOverride(CAmount lastOverrideCommand, bool fDynode = true);

bool RecursiveVerifyIfValid(const CTransaction& tx);
bool CheckInstruction(const CTransaction& tx, CValidationState &state);

opcodetype getOpcodeFromString(std::string input);

extern Fluid fluid;

#endif // FLUID_PROTOCOL_H

