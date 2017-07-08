/**
 * Copyright 2017 Everybody and Nobody (Empinel/Plaxton)
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

#include "base58.h"
#include "amount.h"
#include "chain.h"
#include "script/script.h"

#include <stdint.h>
#include <string.h>
#include <algorithm>

class CBlock;
class CBlockTemplate;

//
// CScript scriptCheck = CScript() << OP_MINT << ParseHex("3130303030303030303030303a3a313439393336353333363a3a445148697036443655376d46335761795a32747337794478737a71687779367a5a6a20494f42447a55716777382b41426a39536b62656a6b47754773536a69556c6b6c616832514b314a676258525642613379515a33785a586b5249632f6633526951526458794552724a36595979764c306b787945786573733d");
//

class Fluid {
private:
	CAmount DeriveSupplyPercentage(int64_t percentage) {
		return chainActive.Tip()->nMoneySupply * percentage / 100;
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

public:
	static const CAmount fluidMintingMinimum = 100 * COIN;
	static const CAmount fluidMintingMaximum = DeriveSupplyPercentage(10); // Maximum 10%

	void ConvertToHex(std::string &input) { std::string output = StringToHex(input); input = output; }
	void ConvertToString(std::string &input) { std::string output = HexToString(input); input = output; }
	
	CScript AssimilateMintingScript(CDynamicAddress reciever, CAmount howMuch) {
		std::string issuanceString;
		if(!GenerateFluidToken(reciever, howMuch, issuanceString))
			return CScript() << OP_RETURN;
		else return CScript() << OP_MINT << ParseHex(issuanceString);
	}
	
	bool GenerateFluidToken(CDynamicAddress sendToward, 
							CAmount tokenMintAmt, std::string &issuanceString);
	bool VerifyInstruction(std::string uniqueIdentifier);
	bool IsItHardcoded(std::string givenScriptPubKey);
	bool InitiateFluidVerify(CDynamicAddress dynamicAddress);
						
	bool ParseMintKey(int64_t nTime, CDynamicAddress &destination, CAmount &coinAmount, std::string uniqueIdentifier);
	bool DerivePreviousBlockInformation(CBlock &block, CBlockIndex* fromDerive);
	bool GetMintingInstructions(const CBlock& block, CValidationState& state, CDynamicAddress &toMintAddress, CAmount &mintAmount);
};

extern Fluid fluid;
