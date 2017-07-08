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

#include "core_io.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#include "init.h"
#include "keepass.h"
#include "net.h"
#include "netbase.h"
#include "rpcserver.h"
#include "timedata.h"
#include "util.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"

#include <univalue.h>

#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>

extern bool EnsureWalletIsAvailable(bool avoidException);
extern void SendMintTransaction(CScript generatedScript, CWalletTx& wtxNew);

Fluid fluid;

bool Fluid::GenerateFluidToken(CDynamicAddress sendToward, 
						CAmount tokenMintAmt, std::string &issuanceString) {
	CDynamicAddress sovreignAddress = "DDi79AEein1zEWsezqUKkFvLUjnbeS1Gbg"; // MmPzujU4zmjBzZpTxBr952Zyh6PETFhca1MPT5gGN8JrUeW3BuzJ
	
	if(!sendToward.IsValid())
		return false;
	
	std::string unsignedMessage;
	unsignedMessage = std::to_string(tokenMintAmt) + "::" + std::to_string(GetTime()) + "::" + sendToward.ToString();
	LogPrintf("FluidMinting (GenerateFluidToken): Created Fluid Unsigned Token, %s \n", unsignedMessage);
	
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
	
	if(tokenMintAmt < fluidMintingMinimum || tokenMintAmt > fluidMintingMaximum) {
		LogPrintf("FluidMinting (GenerateFluidToken): Token Mint Quantity is either too big or too small, %s \n", tokenMintAmt);
		return false;
	}
	
	LogPrintf("FluidMinting (GenerateFluidToken): Created Fluid Signed Token, %s \n", issuanceString);
	
	ConvertToHex(issuanceString);
		
    return true;
}

bool Fluid::VerifyInstruction(std::string uniqueIdentifier)
{
	CDynamicAddress sovreignAddress = "DDi79AEein1zEWsezqUKkFvLUjnbeS1Gbg";
	
	std::vector<std::string> transverser;
	boost::split(transverser, uniqueIdentifier, boost::is_any_of(" "));
	uniqueIdentifier = transverser.at(1);
	CDynamicAddress addr(sovreignAddress);
    
   	LogPrintf("FluidMinting (VerifyInstruction): Instruction Verification Started! Hex String is %s \n", uniqueIdentifier);

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
		return false;

	ConvertToString(uniqueIdentifier);
	std::vector<std::string> strs;
	boost::split(strs, uniqueIdentifier, boost::is_any_of(" "));
	
	std::string messageTokenKey = strs.at(0);
   	LogPrintf("FluidMinting (VerifyInstruction): Instruction Verification, Message Token Key is %s \n", messageTokenKey);
	std::string digestSignature = strs.at(1);
   	LogPrintf("FluidMinting (VerifyInstruction): Instruction Verification, Digest Signature is %s \n", digestSignature);

    bool fInvalid = false;
    std::vector<unsigned char> vchSig = DecodeBase64(digestSignature.c_str(), &fInvalid);

    if (fInvalid) {
		LogPrintf("FluidMinting (VerifyInstruction): Instruction Verification, Digest Signature Found Invalid, Signature: %s \n", digestSignature);
		return false;
	}
	
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << messageTokenKey;

    CPubKey pubkey;
    
    if (!pubkey.RecoverCompact(ss.GetHash(), vchSig)) {
		LogPrintf("FluidMinting (VerifyInstruction): Instruction Verification, Public Key Recovery Failed! Hash: %s\n", ss.GetHash().ToString());
		return false;
	}
    
    if (!(CDynamicAddress(pubkey.GetID()) == addr)) {
		LogPrintf("FluidMinting (VerifyInstruction): Instruction Verification, Address Data Comparison Failed! Address 1: %s vs Address 2: %s \n", CDynamicAddress(pubkey.GetID()).ToString(), addr.ToString());
		return false;
	}
	
	LogPrintf("FluidMinting (VerifyInstruction): Verification Process Complete! Instruction Verification Complete\n");
	return true;
}

/** Checks if scriptPubKey is that of the hardcoded addresses */
bool Fluid::IsItHardcoded(std::string givenScriptPubKey) {
	CDynamicAddress sovreignAddress = "DDi79AEein1zEWsezqUKkFvLUjnbeS1Gbg";
	
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
bool Fluid::InitiateFluidVerify(CDynamicAddress dynamicAddress) {
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

bool Fluid::ParseMintKey(int64_t nTime, CDynamicAddress &destination, CAmount &coinAmount, std::string uniqueIdentifier) {
	int64_t issuanceTime;
	
	// Step 0: Check if token is even valid
	if (!VerifyInstruction(uniqueIdentifier)) {
		LogPrintf("FluidMinting (ParseMintKey): VerifyInstruction FAILED! Cannot continue!, identifier: %s\n", uniqueIdentifier);
		return false;
	} else {
		LogPrintf("FluidMinting (ParseMintKey): VerifyInstruction SUCCEEDED! Will continue!, identifier: %s\n", uniqueIdentifier);
	}
	
	// Step 1: Make sense out of ASM ScriptKey, split OP_MINT from Hex
	std::vector<std::string> transverser;
	boost::split(transverser, uniqueIdentifier, boost::is_any_of(" "));
	uniqueIdentifier = transverser.at(1);
	LogPrintf("FluidMinting (ParseMintKey): Derived unique identifier as %s\n", uniqueIdentifier);
	
	// Step 1.2: Convert new Hex Data to dehexed token
	std::string dehexString = HexToString(uniqueIdentifier);
	uniqueIdentifier = dehexString;
	LogPrintf("FluidMinting (ParseMintKey): Dehexed string as %s\n", uniqueIdentifier);
	
	// Step 2: Convert the Dehexed Token to sense
	std::vector<std::string> strs, ptrs;
	std::string::size_type size, sizeX;
	boost::split(strs, dehexString, boost::is_any_of(" "));
	boost::split(ptrs, strs.at(0), boost::is_any_of("::"));
	
	LogPrintf("FluidMinting (ParseMintKey): Attempt to derive information is as such, coinAmount: %s, issuanceTime: %s, recipientAddress: %s\n", ptrs.at(0), ptrs.at(2), ptrs.at(4));
	
	// Step 3: Convert the token to our variables
	std::string lr = ptrs.at(0); std::string::iterator end_pos = std::remove(lr.begin(), lr.end(), ' '); lr.erase(end_pos, lr.end());
	std::string ls = ptrs.at(2); std::string::iterator end_posX = std::remove(ls.begin(), ls.end(), ' '); ls.erase(end_posX, ls.end());
	
	try {
		coinAmount			 	= boost::lexical_cast<int64_t>(lr);
		issuanceTime 			= boost::lexical_cast<int64_t>(ls);
	}
	catch( boost::bad_lexical_cast const& ) {
		LogPrintf("FluidMinting (ParseMintKey): Either amount string or issuance time string are incorrect! Parsing cannot continue!\n");
		return false;
	}

	std::string recipientAddress = ptrs.at(4);
	destination.SetString(recipientAddress);
	LogPrintf("FluidMinting (ParseMintKey): Derived information is as such, coinAmount: %s, issuanceTime: %s, recipientAddress: %s\n", coinAmount, issuanceTime, recipientAddress);
	
	// if (GetTime() + 15 * 60 < issuanceTime || GetTime() - 15 * 60 > issuanceTime)
	//	return 0 * COIN;
		
	if(!destination.IsValid() || coinAmount < fluidMintingMinimum || coinAmount > fluidMintingMaximum)
		return false;
	
	return true;
}

bool Fluid::GetMintingInstructions(const CBlock& block, CValidationState& state, CDynamicAddress &toMintAddress, CAmount &mintAmount) {
    BOOST_FOREACH(const CTransaction& tx, block.vtx) {
		LogPrintf("FluidMinting (GetMintingInstructions): Starting process of verification! %s\n", "STARTED!");
        if (!CheckTransaction(tx, state))
			LogPrintf("FluidMinting (GetMintingInstructions): Failed preliminary transaction verification!\n");
		else {
			BOOST_FOREACH(const CTxOut& txout, tx.vout) {
				LogPrintf("FluidMinting (GetMintingInstructions): Successfully passed preliminary transaction verification!\n");
				if (txout.scriptPubKey.IsMintInstruction()) {
					LogPrintf("FluidMinting (GetMintingInstructions): We have found minting instruction, Script: %s\n", ScriptToAsmStr(txout.scriptPubKey)); 
					if (!VerifyInstruction(ScriptToAsmStr(txout.scriptPubKey)))
						LogPrintf("FluidMinting (GetMintingInstructions): FAILED instruction verification!\n");
					else {
						LogPrintf("FluidMinting (GetMintingInstructions): Successfully verified instruction, Script: %s\n", ScriptToAsmStr(txout.scriptPubKey));
						if (!ParseMintKey(GetTime(), toMintAddress, mintAmount, ScriptToAsmStr(txout.scriptPubKey)))
							LogPrintf("FluidMinting (GetMintingInstructions): Failed in parsing key as, Address: %s, Amount: %s, Script: %s\n", toMintAddress.ToString(), mintAmount, ScriptToAsmStr(txout.scriptPubKey));
						else { 
							LogPrintf("FluidMinting (GetMintingInstructions): Successfully parsed key as, Address: %s, Amount: %s, Script: %s\n", toMintAddress.ToString(), mintAmount, ScriptToAsmStr(txout.scriptPubKey)); 
							return true; // Sweet, sweet minting!
						}
					} 
				} else { LogPrintf("FluidMinting (GetMintingInstructions): No minting instruction, Script: %s\n", ScriptToAsmStr(txout.scriptPubKey)); }
			 }
		}
	}
	LogPrintf("FluidMinting (GetMintingInstructions): FAILED! Unknown Reason\n");
	return false;
}

bool Fluid::DerivePreviousBlockInformation(CBlock &block, CBlockIndex* fromDerive) {
    uint256 hash = fromDerive->GetBlockHash();
    LogPrintf("FluidMinting (DerivePreviousBlockInformation): Starting to extract block from hash: %s\n", hash.ToString());
    
    if (mapBlockIndex.count(hash) == 0) {
      	LogPrintf("FluidMinting (DerivePreviousBlockInformation): Failed in extracting block - block does not exist!, hash: %s\n", hash.ToString());
        return false;
    }
    
    CBlockIndex* pblockindex = mapBlockIndex[hash];

    if (fHavePruned && !(pblockindex->nStatus & BLOCK_HAVE_DATA) && pblockindex->nTx > 0) {
		LogPrintf("FluidMinting (DerivePreviousBlockInformation): Failed in extracting block due to pruning, hash: %s\n", hash.ToString());
        return false;
	}
    
    if(!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus())) {
		LogPrintf("FluidMinting (DerivePreviousBlockInformation): Failed in extracting block - unable to read database, hash: %s\n", hash.ToString());
        return false;
	}
    return true;
}

UniValue generatefluidissuetoken(const UniValue& params, bool fHelp)
{
	CDynamicAddress sovreignAddress = "DDi79AEein1zEWsezqUKkFvLUjnbeS1Gbg";
	
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
	LogPrintf("FluidMinting (RPCCommand): Generated Final Script to be broadcasted: %s\n", ScriptToAsmStr(finalScript));
    SendMintTransaction(finalScript, wtx);

    return wtx.GetHash().GetHex();
}

