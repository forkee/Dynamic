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
			throw std::runtime_error("String is not valid length ...");
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
	std::string fluidPubkeyX = "0489da1b3ceab91599cf344babae29384e0eeefedfed9a56716eb6a4ec8b29079996ce27cc612b89cdeef7d4326d14e27e5d77c81e547110acefd998912b9b0b9a"; // 5KTRMPQLJqJmFQ5zFVxd4C8ws6YezrRpbxfCuufUfxLhzKYuPqJ
	std::string fluidPubkeyY = "04c6f6728aa5ab30f55577610e283c7be54bef80380d19acec7f47ee0c7bf7d0cb164d8f22c45a5e8af4577d4ba254214cd06716504df26b780687861fff803e2c"; // 5J27YF8ECMfV6NKTSwhj4UQ9NDAwRngH5vrrdkW2dmMFvSHyCyB
	std::string fluidPubkeyZ = "04a71372cd9291d1f14b998820922a8fe5b0a6636ea46dc8b969758baa6bca4485f285676b23d95497e7ab76f15de238d35f0c9aa266610f644d6ad0272e3c10b0"; // 5JacMzkr4DcCnnwiCu95eMKd1Nhod24cLD3i2PZF7oSn74R7FJy

	enum KeyNumber {
		KEY_UNE,
		KEY_DEUX,
		KEY_TROIS,
		
		KEY_MAX
	};

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
		if (adr == KEY_UNE) { return fluidPubkeyX.c_str(); }
		else if (adr == KEY_DEUX) { return fluidPubkeyY.c_str(); }
		else if (adr == KEY_TROIS) { return fluidPubkeyZ.c_str(); }
		else { return "Invalid Public Key Requested"; }
	}
	
	/*CDynamicAddress deriveMultisigAddress() {
	
	}*/
	
	CDynamicAddress sovreignAddress = "DDi79AEein1zEWsezqUKkFvLUjnbeS1Gbg"; // MmPzujU4zmjBzZpTxBr952Zyh6PETFhca1MPT5gGN8JrUeW3BuzJ
	
	CScript AssimilateMintingScript(CDynamicAddress reciever, CAmount howMuch) {
		std::string issuanceString;
		if(!GenerateFluidToken(reciever, howMuch, issuanceString))
			return CScript() << OP_RETURN;
		else return CScript() << OP_MINT << ParseHex(issuanceString);
	}
	
	CScript AssimilateKillScript() {
		std::string killToken;
		if(!GenerateKillToken(killToken))
			return CScript() << OP_RETURN;
		else return CScript() << OP_KILL << ParseHex(killToken);
	}
	
	CScript AssimiliateDestroyScript(CAmount howMuch) {
		std::ostringstream oss; oss << howMuch; std::string r = oss.str(); 
		ConvertToHex(r);
		return CScript() << OP_DESTROY << ParseHex(r);
	}
		
	CScript AssimilateOverrideToken(CAmount howMuch, OverrideType type) {
		std::string issuanceString;
		if (!GenericSignNumber(howMuch, issuanceString))
			return CScript() << OP_RETURN;
			
		switch(type) {
			case MINING_OVERRIDE:
				return CScript() << OP_REWARD_MINING << ParseHex(issuanceString);
			break;
			case DYNODE_OVERRIDE:
				return CScript() << OP_REWARD_DYNODE << ParseHex(issuanceString);
			break;
			default:
				return CScript() << OP_RETURN;
		}
		return CScript() << OP_RETURN;
	}

	bool IsItHardcoded(std::string givenScriptPubKey);
	bool InitiateFluidVerify(CDynamicAddress dynamicAddress);
	bool SignIntimateMessage(CDynamicAddress address, std::string unsignedMessage, std::string &stitchedMessage);
	
	bool DerivePreviousBlockInformation(CBlock &block, CBlockIndex* fromDerive);
	bool DerivePreviousBlockInformation(CBlock &block, const CBlockIndex* fromDerive);
	bool DeriveBlockInfoFromHash(CBlock &block, uint256 hash);
	
	bool GenericSignNumber(CAmount howMuch, std::string &signedString);
	bool GenericParseNumber(std::string scriptString, CAmount &howMuch);
	bool GenericVerifyInstruction(std::string uniqueIdentifier);
	
	bool GenerateFluidToken(CDynamicAddress sendToward, 
							CAmount tokenMintAmt, std::string &issuanceString);

	bool ParseMintKey(int64_t nTime, CDynamicAddress &destination, CAmount &coinAmount, std::string uniqueIdentifier);
	bool ParseDestructionAmount(std::string scriptString, CAmount coinsSpent, CAmount &coinsDestroyed);

	bool GetMintingInstructions(CBlockHeader& block, CValidationState& state, CDynamicAddress &toMintAddress, CAmount &mintAmount);
	void GetDestructionTxes(CBlockHeader& block, CValidationState& state, CAmount &amountDestroyed);
	
	bool GenerateKillToken(std::string &killString);
	bool GetKillRequest(CBlockHeader& block, CValidationState& state);
	
	bool GetProofOverrideRequest(CBlockHeader& block, CValidationState& state, CAmount &howMuch);
	bool GetDynodeOverrideRequest(CBlockHeader& block, CValidationState& state, CAmount &howMuch);
};

/** Standard Reward Payment Determination Functions */
CAmount GetPoWBlockPayment(const int& nHeight, CAmount nFees);
CAmount GetDynodePayment(bool fDynode = true);

/** Override Logic Switch for Reward Payment Determination Functions */
CAmount getBlockSubsidyWithOverride(const int& nHeight, CAmount nFees, CAmount lastOverrideCommand);
CAmount getDynodeSubsidyWithOverride(CAmount lastOverrideCommand, bool fDynode = true);

extern Fluid fluid;

#endif // FLUID_PROTOCOL_H

