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
#include "fluid.h"
#include "main.h"

#include <algorithm>
#include <univalue.h>

extern bool EnsureWalletIsAvailable(bool avoidException);
extern void SendCustomTransaction(CScript generatedScript, CWalletTx& wtxNew, CAmount nValue = (1*COIN));

Fluid fluid;

bool getBlockFromHeader(const CBlockHeader& blockHeader, CBlock &block) {
	uint256 hash = blockHeader.GetHash();
	
    if (mapBlockIndex.count(hash) == 0)
        return false;

    CBlockIndex* pblockindex = mapBlockIndex[hash];

	/* This should never happen */
    if (fHavePruned && !(pblockindex->nStatus & BLOCK_HAVE_DATA) && pblockindex->nTx > 0)
        return false;

    if(!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus()))
        return false;
	
	return true;
}

opcodetype getOpcodeFromString(std::string input) {
    if ("OP_MINT") return OP_MINT;
	else if ("OP_DESTROY") return OP_DESTROY;
	else if ("OP_DROPLET") return OP_DROPLET;
	else if ("OP_REWARD_DYNODE") return OP_REWARD_DYNODE;
	else if ("OP_REWARD_MINING") return OP_REWARD_MINING;
	else if ("OP_STERILIZE") return OP_STERILIZE;
	else if ("OP_FLUID_DEACTIVATE") return OP_FLUID_DEACTIVATE;
	else if ("OP_FLUID_REACTIVATE") return OP_FLUID_REACTIVATE;
	
	return OP_RETURN;
};

bool RecursiveVerifyIfValid(const CTransaction& tx) {
	CAmount nFluidTransactions = 0;
	BOOST_FOREACH(const CTxOut& txout, tx.vout)
    {
		if (// (txout.scriptPubKey.IsProtocolInstruction(DESTROY_TX) && tx.IsCoinBase()) ||
			txout.scriptPubKey.IsProtocolInstruction(MINT_TX) ||
			txout.scriptPubKey.IsProtocolInstruction(DYNODE_MODFIY_TX) ||
			txout.scriptPubKey.IsProtocolInstruction(MINING_MODIFY_TX) ||
			txout.scriptPubKey.IsProtocolInstruction(ACTIVATE_TX) ||
			txout.scriptPubKey.IsProtocolInstruction(DEACTIVATE_TX))
			nFluidTransactions++;
	}
	LogPrintf("There are %s number of transactions.\n", std::to_string(nFluidTransactions));
	return (nFluidTransactions != 0);
}

bool CheckInstruction(const CTransaction& tx, CValidationState &state) {
	return RecursiveVerifyIfValid(tx) && CheckTransaction(tx, state);
}


/** Checks if any given address is a master key, and if so, which one */
bool Fluid::IsGivenKeyMaster(CDynamicAddress inputKey, int &whichOne) {
	whichOne = 0;
	bool addressOne;
	{
		CDynamicAddress considerX; considerX = fluidImportantAddress(KEY_UNE);
		addressOne = (considerX == inputKey);
		if(addressOne) whichOne = 1;
	}
	bool addressTwo;
	{
		CDynamicAddress considerY; considerY = fluidImportantAddress(KEY_DEUX);
		addressTwo = (considerY == inputKey);
		if(addressTwo) whichOne = 2;
	}
	bool addressThree;
	{
		CDynamicAddress considerZ; considerZ = fluidImportantAddress(KEY_TROIS);
		addressThree = (considerZ == inputKey);
		if(addressThree) whichOne = 3;
	}
	
	if (addressOne ||
		addressTwo ||
		addressThree)
		return true;
	else
		return false;
}

/** Checks how many Fluid Keys the wallet owns */
bool Fluid::HowManyKeysWeHave(CDynamicAddress inputKey, bool &keyOne, bool &keyTwo, bool &keyThree) {
	keyOne = false, keyTwo = false, keyThree = false; // Assume first
	int verifyNumber;
	
	for (int x = 0; x <= 3; x++) {
		if(IsGivenKeyMaster(inputKey, verifyNumber)) {
			if(InitiateFluidVerify(inputKey)) {
				if(verifyNumber == 1)
					keyOne = true;
				else if (verifyNumber == 2)
					keyTwo = true;
				else if (verifyNumber == 3)
					keyThree = true;
				else {
					// ...
				}
			}
		}
	}
	
	if (keyOne == true || keyTwo == true || keyThree == true)
		return true;
	else
		return false;
}

/** Does client instance own address for engaging in processes - required for RPC (PS: NEEDS wallet) */
bool Fluid::InitiateFluidVerify(CDynamicAddress dynamicAddress) {
#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwalletMain ? &pwalletMain->cs_wallet : NULL);
	CDynamicAddress address(dynamicAddress);
	
	if (address.IsValid()) {
		CTxDestination dest = address.Get();
		CScript scriptPubKey = GetScriptForDestination(dest);
		isminetype mine = pwalletMain ? IsMine(*pwalletMain, dest) : ISMINE_NO;
		
		return ((mine & ISMINE_SPENDABLE) ? true : false);
	}
	
	return false;
#else
	// Wallet cannot be accessed, cannot continue ahead!
    return false;
#endif
}

/** Because some things in life are meant to be intimate, like socks in a drawer */
bool Fluid::SignIntimateMessage(CDynamicAddress address, std::string unsignedMessage, std::string &stitchedMessage, bool stitch) {
	
	CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << unsignedMessage;
    
   	CDynamicAddress addr(address);

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
		if(stitch)
			stitchedMessage = StitchString(unsignedMessage, EncodeBase64(&vchSig[0], vchSig.size()), false);
		else
			stitchedMessage = EncodeBase64(&vchSig[0], vchSig.size());
	
	return true;
}

/** It will perform basic message signing functions */
bool Fluid::GenericSignMessage(std::string message, std::string &signedString, CDynamicAddress signer) {
	if(!SignIntimateMessage(signer, message, signedString, true))
		return false;
	else 
		ConvertToHex(signedString);

    return true;
}

/** It will append a signature of the new information */
bool Fluid::GenericConsentMessage(std::string message, std::string &signedString, CDynamicAddress signer) {
	std::string token, digest;
	
	// First, is the consent message a hex?
	if (!IsHex(message))
		return false;
	
	// Is the consent message consented by one of the parties already?
	if(!CheckNonScriptQuorum(message, token, true))
		return false;
	
	// Token cannot be empty
	if(token == "")
		return false;
	
	// It is, now get back the message
	ConvertToString(message);
	
	// Sign the token of the message to append the key
	if(!SignIntimateMessage(signer, token, digest, false))
		return false;
	
	// Now actually append our new digest to the existing signed string
	signedString = StitchString(message, digest, false);
	
	ConvertToHex(signedString);

    return true;
}

/** It gets a number from the ASM of an OP_CODE without signature verification */
bool Fluid::GenericParseNumber(std::string scriptString, CAmount &howMuch) {
	// Step 1: Make sense out of ASM ScriptKey, split OP_MINT from Hex
	std::string r = getRidOfScriptStatement(scriptString); scriptString = r;
	
	// Step 1.1.1: Check if our key matches the required quorum
	std::string message;
	if (!CheckNonScriptQuorum(scriptString, message)) {
		LogPrintf("Fluid::ParseMintKey: GenericVerifyInstruction FAILED! Cannot continue!, identifier: %s\n", scriptString);
		return false;
	}
	
	// Step 1.2: Convert new Hex Data to dehexed amount
	std::string dehexString = HexToString(scriptString);
	scriptString = dehexString;
	
	// Step 2: Take string and apply lexical cast to convert it to CAmount (int64_t)
	std::string lr = scriptString; ScrubString(lr, true);
	
	howMuch			= stringToInteger(lr);

	return true;
}

bool Fluid::GenericParseHash(std::string scriptString, uint256 &hash) {
	// Step 1: Make sense out of ASM ScriptKey, split OPCODE from Hex
	std::string r = getRidOfScriptStatement(scriptString); scriptString = r;
	
	// Step 1.1.1: Check if our key matches the required quorum
	std::string message;
	if (!CheckNonScriptQuorum(scriptString, message)) {
		LogPrintf("Fluid::ParseMintKey: GenericVerifyInstruction FAILED! Cannot continue!, identifier: %s\n", scriptString);
		return false;
	}
	
	// Step 1.2: Convert new Hex Data to dehexed token
	std::string dehexString = HexToString(scriptString);
	scriptString = dehexString;
	
	// Step 2: Convert the Dehexed Token to sense
	std::vector<std::string> strs, ptrs; 
	SeperateString(dehexString, strs, false);
	scriptString = strs.at(0);
	
	// Step 3: Get hash
	hash = uint256S(scriptString);
	
	return true;
}

/** Checks whether as to parties have actually signed it - please use this with ones **without** the OP_CODE */
bool Fluid::CheckNonScriptQuorum(std::string token, std::string &message, bool individual) {
	std::string result = "12345 " + token;
	return CheckIfQuorumExists(result, message, individual);
}

/** Checks whether as to parties have actually signed it - please use this with ones with the OP_CODE */
bool Fluid::CheckIfQuorumExists(std::string token, std::string &message, bool individual) {
	bool addressOneConsents, addressTwoConsents, addressThreeConsents;
	
	if (!GenericVerifyInstruction(token, fluidImportantAddress(KEY_UNE), message, 1))
		if (!GenericVerifyInstruction(token, fluidImportantAddress(KEY_UNE), message, 2))
			addressOneConsents = false;
		else 
			addressOneConsents = true;
	else 	addressOneConsents = true;

	if (!GenericVerifyInstruction(token, fluidImportantAddress(KEY_DEUX), message,1 ))
		if (!GenericVerifyInstruction(token, fluidImportantAddress(KEY_DEUX), message, 2))
			addressTwoConsents = false;
		else 
			addressTwoConsents = true;
	else 	addressTwoConsents = true;
		
	if (!GenericVerifyInstruction(token, fluidImportantAddress(KEY_TROIS), message, 1))
		if (!GenericVerifyInstruction(token, fluidImportantAddress(KEY_TROIS), message ,2))
			addressThreeConsents = false;
		else 
			addressThreeConsents = true;
	else 	addressThreeConsents = true;

	if (individual) {
		if (addressOneConsents == true ||
			addressTwoConsents == true ||
			addressThreeConsents == true)
			return true;
		else
			return false;
	} else {
	if 	( (addressOneConsents && addressTwoConsents) ||
		  (addressTwoConsents && addressThreeConsents) ||
		  (addressOneConsents && addressThreeConsents)
		)
		return true;
	else
		return false;
	}
}

/** Individually checks the validity of an instruction */
bool Fluid::GenericVerifyInstruction(std::string uniqueIdentifier, CDynamicAddress signer, std::string &messageTokenKey, int whereToLook)
{	
	std::string r = getRidOfScriptStatement(uniqueIdentifier); uniqueIdentifier = r; messageTokenKey = ""; 	std::vector<std::string> strs;
	CDynamicAddress addr(signer);
	CKeyID keyID;
    if (!addr.GetKeyID(keyID))
		return false;

	ConvertToString(uniqueIdentifier);
	SeperateString(uniqueIdentifier, strs, false);

	messageTokenKey = strs.at(0);
	
	/* Don't even bother looking there there aren't enough digest keys or we are checking in the wrong place */
	if(whereToLook >= (int)strs.size() || whereToLook == 0)
		return false;
	
	std::string digestSignature = strs.at(whereToLook);

    bool fInvalid = false;
    std::vector<unsigned char> vchSig = DecodeBase64(digestSignature.c_str(), &fInvalid);

    if (fInvalid) {
		LogPrintf("Fluid::GenericVerifyInstruction: Instruction Verification, Digest Signature Found Invalid, Signature: %s \n", digestSignature);
		return false;
	}
	
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << messageTokenKey;

    CPubKey pubkey;
    
    if (!pubkey.RecoverCompact(ss.GetHash(), vchSig)) {
		LogPrintf("Fluid::GenericVerifyInstruction: Instruction Verification, Public Key Recovery Failed! Hash: %s\n", ss.GetHash().ToString());
		return false;
	}
    
    if (!(CDynamicAddress(pubkey.GetID()) == addr)) {
		LogPrintf("Fluid::GenericVerifyInstruction: Instruction Verification, Address Data Comparison Failed! Address 1: %s vs Address 2: %s \n", CDynamicAddress(pubkey.GetID()).ToString(), addr.ToString());
		return false;
	}
	
	return true;
}

bool Fluid::ParseMintKey(int64_t nTime, CDynamicAddress &destination, CAmount &coinAmount, std::string uniqueIdentifier) {
	// Step 1: Make sense out of ASM ScriptKey, split OP_MINT from Hex
	std::string r = getRidOfScriptStatement(uniqueIdentifier); uniqueIdentifier = r;
	
	// Step 1.1.1: Check if our key matches the required quorum
	std::string message;
	if (!CheckNonScriptQuorum(uniqueIdentifier, message)) {
		LogPrintf("Fluid::ParseMintKey: GenericVerifyInstruction FAILED! Cannot continue!, identifier: %s\n", uniqueIdentifier);
		return false;
	}
		
	// Step 1.2: Convert new Hex Data to dehexed token
	std::string dehexString = HexToString(uniqueIdentifier);
	uniqueIdentifier = dehexString;
	
	// Step 2: Convert the Dehexed Token to sense
	std::vector<std::string> strs, ptrs; SeperateString(dehexString, strs, false); SeperateString(strs.at(0), ptrs, true);
	
	// Step 3: Convert the token to our variables
	std::string lr = ptrs.at(0); ScrubString(lr, true); 
	std::string ls = ptrs.at(2); ScrubString(ls, true);
	
	coinAmount			 	= stringToInteger(lr);

	std::string recipientAddress = ptrs.at(4);
	destination.SetString(recipientAddress);
		
	if(!destination.IsValid())
		return false;
	
	return true;
}

bool Fluid::GetMintingInstructions(const CBlockHeader& blockHeader, CValidationState& state, CDynamicAddress &toMintAddress, CAmount &mintAmount) {
	CBlock block; 
	if(!getBlockFromHeader(blockHeader, block))
		throw std::runtime_error("Cannot access blockchain database!");
	
    BOOST_FOREACH(const CTransaction& tx, block.vtx) {
		BOOST_FOREACH(const CTxOut& txout, tx.vout) {
			if (txout.scriptPubKey.IsProtocolInstruction(MINT_TX)) {
				std::string message;
				if (!CheckIfQuorumExists(ScriptToAsmStr(txout.scriptPubKey), message))
					LogPrintf("Fluid::GetMintingInstructions: FAILED instruction verification!\n");
				else {
					if (!ParseMintKey(GetTime(), toMintAddress, mintAmount, ScriptToAsmStr(txout.scriptPubKey))) {
						LogPrintf("Fluid::GetMintingInstructions: Failed in parsing key as, Address: %s, Amount: %s, Script: %s\n", toMintAddress.ToString(), mintAmount, ScriptToAsmStr(txout.scriptPubKey));
					} else return true;
				} 
			} else { LogPrintf("Fluid::GetMintingInstructions: No minting instruction, Script: %s\n", ScriptToAsmStr(txout.scriptPubKey)); }
		}
	}
	return false;
}

bool Fluid::ParseDestructionAmount(std::string scriptString, CAmount coinsSpent, CAmount &coinsDestroyed) {
	// Step 1: Make sense out of ASM ScriptKey, split OP_DESTROY from Hex
	std::string r = getRidOfScriptStatement(scriptString); scriptString = r;
	
	// Step 1.2: Convert new Hex Data to dehexed amount
	std::string dehexString = HexToString(scriptString);
	scriptString = dehexString;
	
	// Step 2: Take string and apply lexical cast to convert it to CAmount (int64_t)
	std::string lr = scriptString; ScrubString(lr, true); 
	
	coinsDestroyed			= stringToInteger(lr);

	if (coinsDestroyed != coinsSpent) {
		LogPrintf("Fluid::ParseDestructionAmount: Coins claimed to be destroyed do not match coins spent to destroy! Amount is %s claimed destroyed vs %s actually spent\n", std::to_string(coinsDestroyed), std::to_string(coinsSpent));
		return false;
	}
	
	return true;
}

void Fluid::GetDestructionTxes(const CBlockHeader& blockHeader, CValidationState& state, CAmount &amountDestroyed) {
	CBlock block; 
	CAmount parseToDestroy = 0; amountDestroyed = 0;
	if(!getBlockFromHeader(blockHeader, block))
		throw std::runtime_error("Cannot access blockchain database!");
	
    BOOST_FOREACH(const CTransaction& tx, block.vtx) {
		BOOST_FOREACH(const CTxOut& txout, tx.vout) {
			if (txout.scriptPubKey.IsProtocolInstruction(DESTROY_TX)) {
				if (ParseDestructionAmount(ScriptToAsmStr(txout.scriptPubKey), txout.nValue, parseToDestroy)) {
					amountDestroyed += txout.nValue; // This is what metric we need to get
				}
			} else { LogPrintf("Fluid::GetDestructionTxes: No destruction scripts, script: %s\n", ScriptToAsmStr(txout.scriptPubKey)); }
		}
	}
}

UniValue burndynamic(const UniValue& params, bool fHelp)
{
 	CWalletTx wtx;

    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;
    
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "burndynamic \"amount\"\n"
            "\nSend coins to be burnt (destroyed) onto the Dynamic Network\n"
            "\nArguments:\n"
            "1. \"account\"         (numeric or string, required) The amount of coins to be minted.\n"
            "\nExamples:\n"
            + HelpExampleCli("burndynamic", "123.456")
            + HelpExampleRpc("burndynamic", "123.456")
        );

    EnsureWalletIsUnlocked();   
	
	CAmount nAmount = AmountFromValue(params[0]);
	
	if (nAmount <= 0)
		throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for destruction");
	
	std::string result = std::to_string(nAmount);
    fluid.ConvertToHex(result);
    
    CScript destroyScript = CScript() << OP_DESTROY << ParseHex(result);
    
    SendCustomTransaction(destroyScript, wtx, nAmount);

    return wtx.GetHash().GetHex();
}

bool Fluid::GetProofOverrideRequest(const CBlockHeader& blockHeader, CValidationState& state, CAmount &howMuch) {
	CBlock block; 
	if(!getBlockFromHeader(blockHeader, block))
		throw std::runtime_error("Cannot access blockchain database!");
	
    BOOST_FOREACH(const CTransaction& tx, block.vtx) {
		BOOST_FOREACH(const CTxOut& txout, tx.vout) {
			if (txout.scriptPubKey.IsProtocolInstruction(MINING_MODIFY_TX)) {
				std::string message;
				if (CheckIfQuorumExists(ScriptToAsmStr(txout.scriptPubKey), message))
					return GenericParseNumber(ScriptToAsmStr(txout.scriptPubKey), howMuch);
			}
		}
	}
	return false;
}

bool Fluid::GetDynodeOverrideRequest(const CBlockHeader& blockHeader, CValidationState& state, CAmount &howMuch) {
	CBlock block; 
	if(!getBlockFromHeader(blockHeader, block))
		throw std::runtime_error("Cannot access blockchain database!");
	
    BOOST_FOREACH(const CTransaction& tx, block.vtx) {
		BOOST_FOREACH(const CTxOut& txout, tx.vout) {
			if (txout.scriptPubKey.IsProtocolInstruction(MINING_MODIFY_TX)) {
				std::string message;
				if (CheckIfQuorumExists(ScriptToAsmStr(txout.scriptPubKey), message))
					return GenericParseNumber(ScriptToAsmStr(txout.scriptPubKey), howMuch);
			}
		}
	}
	return false;
}

UniValue getrawpubkey(const UniValue& params, bool fHelp)
{
    UniValue ret(UniValue::VOBJ);

    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "getrawpubkey \"address\"\n"
            "\nGet (un)compressed raw public key of an address of the wallet\n"
            "\nArguments:\n"
            "1. \"address\"         (string, required) The Dynamic Address from which the pubkey is to recovered.\n"
            "\nExamples:\n"
            + HelpExampleCli("burndynamic", "123.456")
            + HelpExampleRpc("burndynamic", "123.456")
        );

    CDynamicAddress address(params[0].get_str()); bool isValid = address.IsValid();

    if (isValid)
    {
        CTxDestination dest = address.Get();
        CScript scriptPubKey = GetScriptForDestination(dest);
        ret.push_back(Pair("pubkey", HexStr(scriptPubKey.begin(), scriptPubKey.end())));
	} else {
		ret.push_back(Pair("errors", "Dynamic address is not valid!"));
	}
	
    return ret;
}

CAmount GetPoWBlockPayment(const int& nHeight, CAmount nFees)
{
	CAmount nSubsidy = BLOCKCHAIN_INIT_REWARD;
	
	if (chainActive.Height() >= 1 && chainActive.Height() <= Params().GetConsensus().nRewardsStart) {
        nSubsidy = BLOCKCHAIN_INIT_REWARD;
    }
    else if (chainActive.Height() > Params().GetConsensus().nRewardsStart) {
        nSubsidy = PHASE_1_POW_REWARD;
    }
	
	LogPrint("creation", "GetPoWBlockPayment() : create=%s PoW Reward=%d\n", FormatMoney(nSubsidy+nFees), nSubsidy+nFees);

	return nSubsidy  + nFees;
}

CAmount GetDynodePayment(bool fDynode)
{
	CAmount dynodePayment = BLOCKCHAIN_INIT_REWARD;
	
    if (fDynode && 
		chainActive.Height() > Params().GetConsensus().nDynodePaymentsStartBlock && 
		chainActive.Height() < Params().GetConsensus().nUpdateDiffAlgoHeight) {
        dynodePayment = PHASE_1_DYNODE_PAYMENT;
    }
    else if (fDynode && 
			chainActive.Height() > Params().GetConsensus().nDynodePaymentsStartBlock && 
			chainActive.Height() >= Params().GetConsensus().nUpdateDiffAlgoHeight) {
        dynodePayment = PHASE_2_DYNODE_PAYMENT;
    }
    else if ((fDynode && !fDynode) &&
			chainActive.Height() <= Params().GetConsensus().nDynodePaymentsStartBlock) {
        dynodePayment = BLOCKCHAIN_INIT_REWARD;
    }
	
	LogPrint("creation", "GetDynodePayment() : create=%s DN Payment=%d\n", FormatMoney(dynodePayment), dynodePayment);

    return dynodePayment;
}

/** Passover code that will act as a switch to check if override did occur for Proof of Work Rewards **/ 
CAmount getBlockSubsidyWithOverride(const int& nHeight, CAmount nFees, CAmount lastOverrideCommand) {
	if (lastOverrideCommand != 0) {
		return lastOverrideCommand;
	} else {
		return GetPoWBlockPayment(nHeight, nFees);
	}
}

/** Passover code that will act as a switch to check if override did occur for Dynode Rewards **/ 
CAmount getDynodeSubsidyWithOverride(CAmount lastOverrideCommand, bool fDynode) {
	if (lastOverrideCommand != 0) {
		return lastOverrideCommand;
	} else {
		return GetDynodePayment(fDynode);
	}
}

UniValue sendfluidtransaction(const UniValue& params, bool fHelp)
{
	CScript finalScript;

    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;
    
    if (fHelp || params.size() != 2)
        throw std::runtime_error(
            "sendfluidtransaction \"opcode\" \"hexstring\"\n"
            "\Send Fluid transactions to the network\n"
            "\nArguments:\n"
            "1. \"opcode\"  (string, required) The Fluid operation to be executed.\n"
            "2. \"hexstring\" (string, required) The token for that opearation.\n"
            "\nExamples:\n"
            + HelpExampleCli("sendfluidtransaction", "\"D5nRy9Tf7Zsef8gMGL2fhWA9ZslrP4K5tf\" \"3130303030303030303030303a3a313439393336353333363a3a445148697036443655376d46335761795a32747337794478737a71687779367a5a6a20494f42447a557167773\"")
            + HelpExampleRpc("sendfluidtransaction", "\"D5nRy9Tf7Zsef8gMGL2fhWA9ZslrP4K5tf\", \"3130303030303030303030303a3a313439393336353333363a3a445148697036443655376d46335761795a32747337794478737a71687779367a5a6a20494f42447a557167773\"")
        );

    EnsureWalletIsUnlocked();
      
    opcodetype opcode = getOpcodeFromString(params[0].get_str());
    opcodetype negatif = OP_RETURN;
    
	if (negatif == opcode)
		throw std::runtime_error("OP_CODE is either not a Fluid OP_CODE or is invalid");

    if(!IsHex(params[1].get_str()))
		throw std::runtime_error("Hex isn't even valid!");    
	else
		finalScript = CScript() << opcode << ParseHex(params[1].get_str());

	std::string message;

    if(!fluid.CheckIfQuorumExists(ScriptToAsmStr(finalScript), message))
		throw std::runtime_error("Instruction does not meet required quorum for validity");
	
	CWalletTx wtx;
    SendCustomTransaction(finalScript, wtx);

    return wtx.GetHash().GetHex();
}

UniValue signtoken(const UniValue& params, bool fHelp)
{
	std::string result;
	
    if (fHelp || params.size() != 2)
        throw std::runtime_error(
            "signtoken \"address\" \"tokenkey\"\n"
            "\nSign a Fluid Protocol Token\n"
            "\nArguments:\n"
            "1. \"address\"         (string, required) The Dynamic Address which will be used to sign.\n"
            "2. \"tokenkey\"         (string, required) The token which has to be initially signed\n"
            "\nExamples:\n"
            + HelpExampleCli("signtoken", "\"D5nRy9Tf7Zsef8gMGL2fhWA9ZslrP4K5tf\" \"3130303030303030303030303a3a313439393336353333363a3a445148697036443655376d46335761795a32747337794478737a71687779367a5a6a20494f42447a557167773\"")
            + HelpExampleRpc("signtoken", "\"D5nRy9Tf7Zsef8gMGL2fhWA9ZslrP4K5tf\" \"3130303030303030303030303a3a313439393336353333363a3a445148697036443655376d46335761795a32747337794478737a71687779367a5a6a20494f42447a557167773\"")
        );
     
    CDynamicAddress address(params[0].get_str());
    if (!address.IsValid())
		throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Dynamic address");
	
	int x;
	if (!fluid.IsGivenKeyMaster(address, x))
		throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Address is not Fluid Protocol Sovreign address");
	
    if (!fluid.InitiateFluidVerify(address))
		throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Address is not possessed by wallet!");

	std::string r = params[1].get_str();

    if(!IsHex(r))
		throw std::runtime_error("Hex isn't even valid! Cannot process ahead...");

	fluid.ConvertToString(r);
	
	if (!fluid.GenericSignMessage(r, result, address))
		throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Message signing failed");
    
    return result;
}

UniValue verifyquorum(const UniValue& params, bool fHelp)
{
	std::string message;
	
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "verifyquorum \"tokenkey\"\n"
            "\nVerify if the token provided has required quorum\n"
            "\nArguments:\n"
            "1. \"tokenkey\"         (string, required) The token which has to be initially signed\n"
            "\nExamples:\n"
            + HelpExampleCli("consenttoken", "\"3130303030303030303030303a3a313439393336353333363a3a445148697036443655376d46335761795a32747337794478737a71687779367a5a6a20494f42447a557167773\"")
            + HelpExampleRpc("consenttoken", "\"3130303030303030303030303a3a313439393336353333363a3a445148697036443655376d46335761795a32747337794478737a71687779367a5a6a20494f42447a557167773\"")
        );
	
    if (!fluid.CheckNonScriptQuorum(params[0].get_str(), message, false))
		throw std::runtime_error("Instruction does not meet minimum quorum for validity");

    return "Quorum is present!";
}

UniValue consenttoken(const UniValue& params, bool fHelp)
{
	std::string result;

    if (fHelp || params.size() != 2)
        throw std::runtime_error(
            "consenttoken \"address\" \"tokenkey\"\n"
            "\nGive consent to a Fluid Protocol Token as a second party\n"
            "\nArguments:\n"
            "1. \"address\"         (string, required) The Dynamic Address which will be used to give consent.\n"
            "2. \"tokenkey\"         (string, required) The token which has to be been signed by one party\n"
            "\nExamples:\n"
            + HelpExampleCli("consenttoken", "\"D5nRy9Tf7Zsef8gMGL2fhWA9ZslrP4K5tf\" \"3130303030303030303030303a3a313439393336353333363a3a445148697036443655376d46335761795a32747337794478737a71687779367a5a6a20494f42447a557167773\"")
            + HelpExampleRpc("consenttoken", "\"D5nRy9Tf7Zsef8gMGL2fhWA9ZslrP4K5tf\" \"3130303030303030303030303a3a313439393336353333363a3a445148697036443655376d46335761795a32747337794478737a71687779367a5a6a20494f42447a557167773\"")
        );
	
    CDynamicAddress address(params[0].get_str());
    if (!address.IsValid())
		throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Dynamic address");
	
	int x;
	
	if (!IsHex(params[1].get_str()))
		throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Hex string is invalid! Token incorrect");
	
	if (!fluid.IsGivenKeyMaster(address, x))
		throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Address is not Fluid Protocol Sovreign address");
	
    if (!fluid.InitiateFluidVerify(address))
		throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Address is not possessed by wallet!");

	std::string message;

    if (!fluid.CheckNonScriptQuorum(params[1].get_str(), message, true))
		throw std::runtime_error("Instruction does not meet minimum quorum for validity");

	if (!fluid.GenericConsentMessage(params[1].get_str(), result, address))
		throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Message signing failed");
    
    if (!fluid.CheckNonScriptQuorum(result, message, false))
		throw std::runtime_error("Quorum Signature cannot be from the same address twice");

	return result;
}

/* Pretty pointless function, but - meh */
UniValue stringtohex(const UniValue& params, bool fHelp)
{
	std::string result;

    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "stringtohex \"string\"\n"
            "\nConvert String to Hexadecimal Format\n"
            "\nArguments:\n"
            "1. \"string\"         (string, required) String that has to be converted to hex.\n"
            "\nExamples:\n"
            + HelpExampleCli("stringtohex", "\"Hello World!\"")
            + HelpExampleRpc("stringtohex", "\"Hello World!\"")
        );
	
	result = params[0].get_str();
	
	fluid.ConvertToHex(result);
	return result;
}

bool CheckIfAddressIsBlacklisted(CScript scriptPubKey) {
	/* Step 1: Copy vector */
	std::vector<uint256> bannedDatabase;
	if (chainActive.Height() <= 10)
		return false;
	else bannedDatabase = chainActive.Tip()->bannedAddresses;
	
	CTxDestination source;
	/* Step 2: Get destination */
	if (ExtractDestination(scriptPubKey, source)){
			/* Step 3: Hash it */
			CDynamicAddress addressSource(source);
			std::string address = addressSource.ToString();
			uint256 identiferHash = Hash(address.begin(), address.end());
			
			/* Step 4: Check for each offending entry */
			BOOST_FOREACH(const uint256& offendingHash, bannedDatabase)
			{
				/* Step 5: Do the hashes match? If so, return true */
				if (offendingHash == identiferHash) {
					return true;
				}
			}
	}
	/* Step 6: Address is not banned */
	return false;
}

bool ProcessBanEntry(std::string getBanInstruction, std::vector<uint256>& bannedList) {
	uint256 entry;
	std::string one = fluid.fluidImportantAddress(KEY_UNE), two = fluid.fluidImportantAddress(KEY_DEUX), three = fluid.fluidImportantAddress(KEY_TROIS);
	/* Can we get hash to insert? */
	if (!fluid.GenericParseHash(getBanInstruction, entry))
		return false;
	
	/* Is it already there? */
	BOOST_FOREACH(const uint256& offendingHash, bannedList)
	{
		if (offendingHash == entry) {
			return false;
			/* You can't jsut ban the hodl addresses */
		} else if ( entry == Hash(one.begin(), one.end()) ||
					entry == Hash(two.begin(), two.end()) ||
					entry == Hash(three.begin(), three.end()) ) {
			return false;
		}
	}
	
	/* Okay, it's not there, so it's fine */
	bannedList.push_back(entry);
	
	/* It's true */
	return true;
}

bool RemoveEntry(std::string getBanInstruction, std::vector<uint256>& bannedList) {
	uint256 entry;
	
	/* Can we get hash to insert? */
	if (!fluid.GenericParseHash(getBanInstruction, entry))
		return false;
	
	/* Is it already there? */
	BOOST_FOREACH(const uint256& offendingHash, bannedList)
	{
		/* Check if there */
		if (offendingHash == entry) {
			/* Wipe entry reference off the map */
			bannedList.erase(std::remove(bannedList.begin(), bannedList.end(), entry), bannedList.end());
			return true;
		}
	}
	
	return false;
}
