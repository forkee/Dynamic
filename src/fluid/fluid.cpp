/**
 * Copyright 2017 Everybody and Nobody Inc.
 * 
 * Permission is hereby granted, free of charge, to any person 
 * obtaining a copy of this software and associated documentation files 
 * (the "Software"), to deal in the Software without restriction, including 
 * without limitation the rights to use, copy, modify, merge, publish, 
 * distribute, sublicense, and/or sell copies of the Software, and to 
 * permit persons to whom the Software is furnished to do so, subject 
 * to the following conditions:
1 *
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
#include "core_io.h"
#include "util.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#include "script/script.h"
#include "main.h"
#include "init.h"
#include "keepass.h"
#include "main.h"
#include "net.h"
#include "netbase.h"
#include "policy/rbf.h"
#include "rpcserver.h"
#include "timedata.h"
#include "amount.h"
#include "base58.h"
#include "chain.h"
#include "core_io.h"
#include "init.h"
#include "keepass.h"
#include "main.h"
#include "net.h"
#include "netbase.h"
#include "policy/rbf.h"
#include "rpcserver.h"
#include "timedata.h"
#include "util.h"
#include "utilmoneystr.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"

#include <univalue.h>

#include <stdint.h>

#include <boost/algorithm/string.hpp>

static const int OP_FAILURE = 0x00;
static const CAmount MIN_MINTING = 100 * COIN;

static CScript failedOperation = OP_FAILURE;
extern bool EnsureWalletIsAvailable(bool avoidException);
extern void SendMintTransaction(CScript generatedScript, CWalletTx& wtxNew);

int64_t DeriveSupplyPercentage(int64_t percentage) {
	return 9999999 * COIN; // Pending Balance Monitoring Implementation
}
	
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


static const int64_t fluidMintingMinimum = 100 * COIN;
static const int64_t fluidMintingMaximum = DeriveSupplyPercentage(10); // Maximum 10%

void ConvertToHex(std::string &input) { std::string output = StringToHex(input); input = output; }
void ConvertToString(std::string &input) { std::string output = HexToString(input); input = output; }

bool GenerateFluidToken(CDynamicAddress sendToward, 
						CAmount tokenMintAmt, std::string &issuanceString) {
	CDynamicAddress sovreignAddress = "DL56874aKzfripr8qyatzymHmiignjqrdJ";
	
	if(!sendToward.IsValid())
		return false;
	
	std::string unsignedMessage;
	unsignedMessage = std::to_string(tokenMintAmt) + "::" + std::to_string(GetTime()) + "::" + sendToward.ToString();

	CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << unsignedMessage;
    
   	CDynamicAddress addr(sovreignAddress);

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
		return false;

	CKey key;
    if (!pwalletMain->GetKey(keyID, key))
		return false;

    std::vector<unsigned char> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig))
		return false;
	else
		issuanceString = unsignedMessage + " " + EncodeBase64(&vchSig[0], vchSig.size());
	
	if(tokenMintAmt < fluidMintingMinimum || tokenMintAmt > fluidMintingMaximum)
		return 0 * COIN;
	
	ConvertToHex(issuanceString);
		
    return true;
}

CScript AssimilateMintingScript(CDynamicAddress reciever, CAmount howMuch) {
	std::string issuanceString;
	if(!GenerateFluidToken(reciever, howMuch, issuanceString))
		return CScript() << OP_RETURN;
	else return CScript() << OP_MINT << ParseHex(issuanceString);
}

bool VerifyInstruction(std::string uniqueIdentifier)
{
	std::vector<std::string> transverser;
	boost::split(transverser, uniqueIdentifier, boost::is_any_of(" "));
	uniqueIdentifier = transverser.at(1);
	
	CDynamicAddress sovreignAddress = "DL56874aKzfripr8qyatzymHmiignjqrdJ";
	CDynamicAddress addr(sovreignAddress);
    
    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
		return false;

	ConvertToString(uniqueIdentifier);
	std::vector<std::string> strs;
	boost::split(strs, uniqueIdentifier, boost::is_any_of(" "));
	
	std::string messageTokenKey = strs.at(0);
	std::string digestSignature = strs.at(1);
		
    bool fInvalid = false;
    std::vector<unsigned char> vchSig = DecodeBase64(digestSignature.c_str(), &fInvalid);

    if (fInvalid)
		return false;
	    
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << messageTokenKey;

    CPubKey pubkey;
    
    if (!pubkey.RecoverCompact(ss.GetHash(), vchSig))
		return false;
		
    if (!(CDynamicAddress(pubkey.GetID()) == addr))
		return false;
	
	return true;
}

/** Checks if scriptPubKey is that of the hardcoded addresses */
bool IsItHardcoded(std::string givenScriptPubKey) {
	CDynamicAddress sovreignAddress = "DL56874aKzfripr8qyatzymHmiignjqrdJ";
	
#ifdef ENABLE_WALLET /// Assume that address is valid
	CDynamicAddress address(sovreignAddress);
	
	CTxDestination dest = address.Get();
	CScript scriptPubKey = GetScriptForDestination(dest);
		
	return (givenScriptPubKey == HexStr(scriptPubKey.begin(), scriptPubKey.end()));
#else /// Shouldn't happen as it musn't be called if no wallet
	return false;
#endif
}

/** Does client instance own address for engaging in processes - required for RPC (PS: NEEDS wallet) */
bool InitiateFluidVerify(CDynamicAddress dynamicAddress) {
#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwalletMain ? &pwalletMain->cs_wallet : NULL);
	CDynamicAddress address(dynamicAddress);
	
	if (address.IsValid()) {
		CTxDestination dest = address.Get();
		CScript scriptPubKey = GetScriptForDestination(dest);
		
		/** Additional layer of verification, is probably redundant */
		if (IsItHardcoded(HexStr(scriptPubKey.begin(), scriptPubKey.end()))) {
			isminetype mine = pwalletMain ? IsMine(*pwalletMain, dest) : ISMINE_NO;
			return ((mine & ISMINE_SPENDABLE) ? true : false);
		}
	}
	
	return false;
#else
	// Wallet cannot be accessed, cannot continue ahead!
    return false;
#endif
}

UniValue generatefluidissuetoken(const UniValue& params, bool fHelp)
{
	CScript finalScript;
	std::string processedMessage;

    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;
    
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw std::runtime_error(
            "generatefluidissuetoken \"dynamicaddress\" \"amount\"\n"
            "\Generate Fluid Issuance Token that can be broadcasted by the network\n"
            "\nArguments:\n"
            "1. \"dynamicaddress\"  (string, required) The dynamic address to mint the coins toward.\n"
            "2. \"account\"         (numeric or string, required) The amount of coins to be minted.\n"
            "\nExamples:\n"
            + HelpExampleCli("generatefluidissuetoken", "\"D5nRy9Tf7Zsef8gMGL2fhWA9ZslrP4K5tf\" \"123.456\"")
            + HelpExampleRpc("generatefluidissuetoken", "\"D5nRy9Tf7Zsef8gMGL2fhWA9ZslrP4K5tf\", \"123.456\"")
        );

    EnsureWalletIsUnlocked();
    
    CDynamicAddress sovreignAddress = "DL56874aKzfripr8qyatzymHmiignjqrdJ";
	
    CDynamicAddress address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Dynamic address");
    
    CAmount nAmount = AmountFromValue(params[1]);
    if (nAmount <= fluidMintingMinimum || nAmount >= fluidMintingMaximum)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send, outside bounds");
    
	if (!InitiateFluidVerify(sovreignAddress))
		throw JSONRPCError(RPC_TYPE_ERROR, "Attempting Illegal Operation - Credentials Absent!");
		    
    finalScript = AssimilateMintingScript(address, nAmount);
    
    if (!VerifyInstruction(ScriptToAsmStr(finalScript)))
		throw JSONRPCError(RPC_TYPE_ERROR, "Unknown Malformation! Script Unverifiable");
    
    
	CWalletTx wtx;
    SendMintTransaction(finalScript, wtx);

    return wtx.GetHash().GetHex();
}

bool ParseMintKey(int64_t nTime, CDynamicAddress &destination, CAmount &coinAmount, std::string uniqueIdentifier) {
	// Step 0: Check if token is even valid
	if (!VerifyInstruction(uniqueIdentifier))
		return false;
		
	// Step 1: Make sense out of ASM ScriptKey, split OP_MINT from Hex
	std::vector<std::string> transverser;
	boost::split(transverser, uniqueIdentifier, boost::is_any_of(" "));
	uniqueIdentifier = transverser.at(1);
	
	// Step 1.2: Convert new Hex Data to dehexed token
	std::string dehexString = HexToString(uniqueIdentifier);
	uniqueIdentifier = dehexString;
	
	// Step 2: Convert the Dehexed Token to sense
	std::vector<std::string> strs, ptrs;
	std::string::size_type size, sizeX;
	boost::split(strs, dehexString, boost::is_any_of(" "));
	boost::split(ptrs, strs.at(0), boost::is_any_of("::"));
	
	// Step 3: Convert the token to our variables
	coinAmount = std::stoi (ptrs.at(0),&size);
	int64_t issuanceTime = std::stoi (ptrs.at(2),&sizeX);
	std::string recipientAddress = ptrs.at(4);
	destination.SetString(recipientAddress);
	
	// if (GetTime() + 15 * 60 < issuanceTime || GetTime() - 15 * 60 > issuanceTime)
	//	return 0 * COIN;
		
	if(!destination.IsValid() || coinAmount < fluidMintingMinimum || coinAmount > fluidMintingMaximum)
		return false;
	
	return true;
}

bool GetMintingInstructions(const CBlock& block, CValidationState& state, CDynamicAddress &toMintAddress, CAmount &mintAmount) {
    BOOST_FOREACH(const CTransaction& tx, block.vtx) {
        if (!CheckTransaction(tx, state))
            return false;
		else {
			BOOST_FOREACH(const CTxOut& txout, tx.vout) {
				if (txout.scriptPubKey.IsMintInstruction()) {
					if (!VerifyInstruction(ScriptToAsmStr(txout.scriptPubKey)))
						return false;
					else {
						if (!ParseMintKey(GetTime(), toMintAddress, mintAmount, ScriptToAsmStr(txout.scriptPubKey)))
							return false;
						else return true; // Sweet, sweet minting!
					}
				} else return false;
			}
		}
	}
	return false;
}

bool DerivePreviousBlockInformation(CBlock &block, CBlockIndex* fromDerive) {
    uint256 hash = fromDerive->GetBlockHash();
    
    if (mapBlockIndex.count(hash) == 0)
        return false;
    
    CBlockIndex* pblockindex = mapBlockIndex[hash];

    if (fHavePruned && !(pblockindex->nStatus & BLOCK_HAVE_DATA) && pblockindex->nTx > 0)
        return false;

    if(!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus()))
        throw false;

    return true;
}
