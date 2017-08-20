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

/** Checks whether as to parties have actually signed it - please use this with ones **without** the OP_CODE */
bool Fluid::CheckNonScriptQuorum(std::string token, std::string &message, bool individual) {
	std::string result = "12345 " + token;
	return CheckIfQuorumExists(result, message, individual);
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
bool Fluid::GenericParseNumber(std::string scriptString, int64_t timeStamp, CAmount &howMuch, bool txCheckPurpose) {
	// Step 1: Make sense out of ASM ScriptKey, split OP_MINT from Hex
	std::string r = getRidOfScriptStatement(scriptString); scriptString = r;
	
	// Step 1.1: Check if our key matches the required quorum
	std::string message;
	if (!CheckNonScriptQuorum(scriptString, message)) {
		LogPrintf("GenericParseNumber: CheckNonScriptQuorum FAILED! Cannot continue!, identifier: %s\n", scriptString);
		return false;
	}
	
	// Step 1.2: Convert new Hex Data to dehexed amount
	std::string dehexString = HexToString(scriptString);
	scriptString = dehexString;

	// Step 2: Convert the Dehexed Token to sense
	std::vector<std::string> strs, ptrs; SeperateString(dehexString, strs, false); SeperateString(strs.at(0), ptrs, true);
	
	if(1 >= (int)strs.size())
		return false;
	
	// Step 3: Convert the token to our variables
	std::string lr = ptrs.at(0); ScrubString(lr, true); 
	std::string ls = ptrs.at(1); ScrubString(ls, true);
	
	// Step 4: Final steps of parsing, is the timestamp exceeding five minutes?
	if (timeStamp > stringToInteger(ls) + maximumFluidDistortionTime && !txCheckPurpose)
		return false;
	
	howMuch			 	= stringToInteger(lr);

	return true;
}

bool Fluid::GenericParseHash(std::string scriptString, int64_t timeStamp, uint256 &hash, bool txCheckPurpose) {
	// Step 1: Make sense out of ASM ScriptKey, split OPCODE from Hex
	std::string r = getRidOfScriptStatement(scriptString); scriptString = r;
	
	// Step 1.1.1: Check if our key matches the required quorum
	std::string message;
	if (!CheckNonScriptQuorum(scriptString, message)) {
		LogPrintf("GenericParseHash: GenericVerifyInstruction FAILED! Cannot continue!, identifier: %s\n", scriptString);
		return false;
	}
	
	// Step 1.2: Convert new Hex Data to dehexed token
	std::string dehexString = HexToString(scriptString);
	scriptString = dehexString;
	
	// Step 2: Convert the Dehexed Token to sense
	std::vector<std::string> strs, ptrs; SeperateString(dehexString, strs, false); SeperateString(strs.at(0), ptrs, true);
	
	if(1 >= (int)strs.size())
		return false;
	
	// Step 3: Convert the token to our variables
	std::string lr = ptrs.at(0);
	std::string ls = ptrs.at(1); ScrubString(ls, true);
	
	// Step 4: Final steps of parsing, is the timestamp exceeding five minutes?
	if (timeStamp > stringToInteger(ls) + maximumFluidDistortionTime && !txCheckPurpose)
		return false;
	
	// Step 3: Get hash
	hash = uint256S(lr);
	
	return true;
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
		LogPrintf("GenericVerifyInstruction: Digest Signature Found Invalid, Signature: %s \n", digestSignature);
		return false;
	}
	
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << messageTokenKey;

    CPubKey pubkey;
    
    if (!pubkey.RecoverCompact(ss.GetHash(), vchSig)) {
		LogPrintf("GenericVerifyInstruction: Public Key Recovery Failed! Hash: %s\n", ss.GetHash().ToString());
		return false;
	}
    
    if (!(CDynamicAddress(pubkey.GetID()) == addr))
		return false;
	
	return true;
}

bool Fluid::ParseMintKey(int64_t nTime, CDynamicAddress &destination, CAmount &coinAmount, std::string uniqueIdentifier, bool txCheckPurpose) {
	// Step 1: Make sense out of ASM ScriptKey, split OP_MINT from Hex
	std::string r = getRidOfScriptStatement(uniqueIdentifier); uniqueIdentifier = r;
	
	// Step 1.1.1: Check if our key matches the required quorum
	std::string message;
	if (!CheckNonScriptQuorum(uniqueIdentifier, message)) {
		LogPrintf("ParseMintKey: GenericVerifyInstruction FAILED! Cannot continue!, identifier: %s\n", uniqueIdentifier);
		return false;
	}
		
	// Step 1.2: Convert new Hex Data to dehexed token
	std::string dehexString = HexToString(uniqueIdentifier);
	uniqueIdentifier = dehexString;
	
	// Step 2: Convert the Dehexed Token to sense
	std::vector<std::string> strs, ptrs; SeperateString(dehexString, strs, false); SeperateString(strs.at(0), ptrs, true);
	
	if(1 >= (int)strs.size() || 2 >= (int)ptrs.size())
		return false;
	
	// Step 3: Convert the token to our variables
	std::string lr = ptrs.at(0); ScrubString(lr, true); 
	std::string ls = ptrs.at(1); ScrubString(ls, true);
	
	// Step 4: Final steps of parsing, is the timestamp exceeding five minutes?
	if (nTime > stringToInteger(ls) + maximumFluidDistortionTime && !txCheckPurpose)
		return false;
	
	coinAmount			 	= stringToInteger(lr);

	std::string recipientAddress = ptrs.at(2);
	destination.SetString(recipientAddress);
		
	if(!destination.IsValid())
		return false;
	
	return true;
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
		LogPrintf("ParseDestructionAmount: Coins claimed to be destroyed do not match coins spent to destroy! Amount is %s claimed destroyed vs %s actually spent\n", std::to_string(coinsDestroyed), std::to_string(coinsSpent));
		return false;
	}
	
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
					LogPrintf("GetMintingInstructions: FAILED instruction verification!\n");
				else {
					if (!ParseMintKey(block.nTime, toMintAddress, mintAmount, ScriptToAsmStr(txout.scriptPubKey))) {
						LogPrintf("GetMintingInstructions: Failed in parsing key as, Address: %s, Amount: %s, Script: %s\n", toMintAddress.ToString(), mintAmount, ScriptToAsmStr(txout.scriptPubKey));
					} else return true;
				} 
			} else { LogPrintf("GetMintingInstructions: No minting instruction, Script: %s\n", ScriptToAsmStr(txout.scriptPubKey)); }
		}
	}
	return false;
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
			} else { LogPrintf("GetDestructionTxes: No destruction scripts, script: %s\n", ScriptToAsmStr(txout.scriptPubKey)); }
		}
	}
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
					return GenericParseNumber(ScriptToAsmStr(txout.scriptPubKey), block.nTime, howMuch);
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
					return GenericParseNumber(ScriptToAsmStr(txout.scriptPubKey), block.nTime, howMuch);
			}
		}
	}
	return false;
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

bool Fluid::CheckIfAddressIsBlacklisted(CScript scriptPubKey) {
	/* Step 1: Copy vector */
	std::vector<uint256> bannedDatabase;
	if (chainActive.Height() <= minimumThresholdForBanning)
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

bool Fluid::ProcessBanEntry(std::string getBanInstruction, int64_t timestamp, std::vector<uint256> &bannedList) {
	uint256 entry;
	std::string one = fluidImportantAddress(KEY_UNE), two = fluidImportantAddress(KEY_DEUX), three = fluidImportantAddress(KEY_TROIS);
	/* Can we get hash to insert? */
	if (!GenericParseHash(getBanInstruction, timestamp, entry))
		return false;
		
	BOOST_FOREACH(const uint256& offendingHash, bannedList)
	{
		/* Is it already there? */
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

bool Fluid::RemoveEntry(std::string getBanInstruction, int64_t timestamp, std::vector<uint256> &bannedList) {
	uint256 entry;
	
	/* Can we get hash to insert? */
	if (!GenericParseHash(getBanInstruction, timestamp, entry))
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

void Fluid::AddRemoveBanAddresses(const CBlockHeader& blockHeader, std::vector<uint256> &bannedList) {
	/* Step One: Get the bloukz! */
	CBlock block; 
	std::string message;
	if(!getBlockFromHeader(blockHeader, block))
		throw std::runtime_error("Cannot access blockchain database!");
	
	/* Step Two: Process transactions */
    BOOST_FOREACH(const CTransaction& tx, block.vtx) {
		BOOST_FOREACH(const CTxOut& txout, tx.vout) {
			/* First those who add addresses */
			if (txout.scriptPubKey.IsProtocolInstruction(STERILIZE_TX)) {
				if (CheckIfQuorumExists(ScriptToAsmStr(txout.scriptPubKey), message)) {
					if (!ProcessBanEntry(ScriptToAsmStr(txout.scriptPubKey), block.nTime, bannedList)) {
						LogPrintf("Script Public Key for Ban: %s , FAILED!\n", ScriptToAsmStr(txout.scriptPubKey));
					}
				}
			}
			/* Second those who remove addresses */
			if (txout.scriptPubKey.IsProtocolInstruction(REALLOW_TX)) {
				if (CheckIfQuorumExists(ScriptToAsmStr(txout.scriptPubKey), message)) {
					if (!RemoveEntry(ScriptToAsmStr(txout.scriptPubKey), block.nTime, bannedList)) {
						LogPrintf("Script Public Key for Unban: %s , FAILED!\n", ScriptToAsmStr(txout.scriptPubKey));
					}
				}
			}
		}
	}
}

bool Fluid::ValidationProcesses(CValidationState &state, CScript txOut, CAmount txValue) {
	CDynamicAddress toMintAddress;
    std::string message; uint256 entry;
    CAmount nCoinsBurn = 0, mintAmount;
    
	if (txOut.IsProtocolInstruction(DESTROY_TX) && 
		!fluid.ParseDestructionAmount(ScriptToAsmStr(txOut), txValue, nCoinsBurn))
			return state.DoS(100, false, REJECT_INVALID, "bad-txns-fluid-burn-parse-failure");

	/* Block of Fluid Verification */
	if (txOut.IsProtocolInstruction(MINT_TX) 
		|| txOut.IsProtocolInstruction(DYNODE_MODFIY_TX)
		|| txOut.IsProtocolInstruction(MINING_MODIFY_TX)
		// || txOut.IsProtocolInstruction(ACTIVATE_TX)
		// || txOut.IsProtocolInstruction(DEACTIVATE_TX)
		|| txOut.IsProtocolInstruction(REALLOW_TX)
		|| txOut.IsProtocolInstruction(STERILIZE_TX)
		) {
			if (!CheckIfQuorumExists(ScriptToAsmStr(txOut), message)) {
				return state.DoS(100, false, REJECT_INVALID, "bad-txns-fluid-auth-failure");
			}
					
			if (txOut.IsProtocolInstruction(MINT_TX) &&
				!ParseMintKey(0, toMintAddress, mintAmount, ScriptToAsmStr(txOut), true)) {
				return state.DoS(100, false, REJECT_INVALID, "bad-txns-fluid-mint-auth-failure");
			} 
			
			if ((txOut.IsProtocolInstruction(STERILIZE_TX) ||
			     txOut.IsProtocolInstruction(REALLOW_TX)) &&
				 !GenericParseHash(ScriptToAsmStr(txOut), 0, entry, true)) {
					return state.DoS(100, false, REJECT_INVALID, "bad-txns-fluid-hash-auth-failure");
			}
			
			if ((txOut.IsProtocolInstruction(DYNODE_MODFIY_TX) ||
				 txOut.IsProtocolInstruction(MINING_MODIFY_TX)) &&
				 !GenericParseNumber(ScriptToAsmStr(txOut), 0, mintAmount, true)) {
					return state.DoS(100, false, REJECT_INVALID, "bad-txns-fluid-modify-parse-failure");
			}
			
			if (CheckTransactionInRecord(txOut)) {
					return state.DoS(500, false, REJECT_INVALID, "bad-txns-fluid-exists-already");
			}
	}
	
	/* Check if address is part of ban list */
	if (CheckIfAddressIsBlacklisted(txOut))
		return state.DoS(100, false, REJECT_INVALID, "bad-txns-output-banned-address");
	
	return true;
}

void BuildFluidInformationIndex(CBlockIndex* pindex, CAmount &nExpectedBlockValue, CAmount nFees, CAmount nValueIn, 
								CAmount nValueOut, bool fDynodePaid) {
	CAmount fluidIssuance, dynamicBurnt, newReward = 0, newDynodeReward = 0;
	CValidationState validationState;
	CDynamicAddress addressX;

	if (fluid.GetMintingInstructions(pindex->pprev->GetBlockHeader(), validationState, addressX, fluidIssuance)) {
	    nExpectedBlockValue = 	getDynodeSubsidyWithOverride(pindex->pprev->overridenDynodeReward, fDynodePaid) + 
								getBlockSubsidyWithOverride(pindex->pprev->nHeight, nFees, pindex->pprev->overridenBlockReward) + 
								fluidIssuance;
	} else {
		nExpectedBlockValue = 	getDynodeSubsidyWithOverride(pindex->pprev->overridenDynodeReward, fDynodePaid) + 
								getBlockSubsidyWithOverride(pindex->pprev->nHeight, nFees, pindex->pprev->overridenBlockReward);
	}

    // Get Destruction Transactions on the Network
    fluid.GetDestructionTxes(pindex->pprev->GetBlockHeader(), validationState, dynamicBurnt);

   	pindex->nMoneySupply = (pindex->pprev? pindex->pprev->nMoneySupply : 0) + (nValueOut - nValueIn) - dynamicBurnt;
   	pindex->nDynamicBurnt = (pindex->pprev? pindex->pprev->nDynamicBurnt : 0) + dynamicBurnt;

	// Get override reward transactions from the network
	if (!fluid.GetProofOverrideRequest(pindex->pprev->GetBlockHeader(), validationState, newReward)) {
			pindex->overridenBlockReward = (pindex->pprev? pindex->pprev->overridenBlockReward : 0);
	} else {
			pindex->overridenBlockReward = newReward;
	}
	 
	if (!fluid.GetDynodeOverrideRequest(pindex->pprev->GetBlockHeader(), validationState, newDynodeReward)) {
	 		pindex->overridenDynodeReward = (pindex->pprev? pindex->pprev->overridenDynodeReward : 0);
	} else {
	 		pindex->overridenDynodeReward = newDynodeReward;
	}
	
	// Handle the ban address system and update the vector
	fluid.AddRemoveBanAddresses(pindex->pprev->GetBlockHeader(), pindex->bannedAddresses);
	
	// Scan and add Fluid Transactions to the Database
	fluid.AddFluidTransactionsToRecord(pindex->pprev->GetBlockHeader(), pindex->existingFluidTransactions);
}

void Fluid::AddFluidTransactionsToRecord(const CBlockHeader& blockHeader, std::vector<std::string> &transactionRecord) {
	/* Step One: Get the bloukz! */
	CBlock block; 
	std::string message;
	if(!getBlockFromHeader(blockHeader, block))
		throw std::runtime_error("Cannot access blockchain database!");
	
	/* Step Two: Process transactions */
    BOOST_FOREACH(const CTransaction& tx, block.vtx) {
		BOOST_FOREACH(const CTxOut& txout, tx.vout) {
			if (txout.scriptPubKey.IsProtocolInstruction(MINT_TX) 
				|| txout.scriptPubKey.IsProtocolInstruction(DYNODE_MODFIY_TX)
				|| txout.scriptPubKey.IsProtocolInstruction(MINING_MODIFY_TX)
				|| txout.scriptPubKey.IsProtocolInstruction(REALLOW_TX)
				|| txout.scriptPubKey.IsProtocolInstruction(STERILIZE_TX)
				) {
				if (!InsertTransactionToRecord(txout.scriptPubKey, transactionRecord)) {
					LogPrintf("Script Public Key Database Entry: %s , FAILED!\n", ScriptToAsmStr(txout.scriptPubKey));
				}
			}
		}
	}
}

/* Insertion of transaction script to record */
bool Fluid::InsertTransactionToRecord(CScript fluidInstruction, std::vector<std::string> &transactionRecord) {
	std::string verificationString;

	if (fluidInstruction.IsProtocolInstruction(MINT_TX) 
		|| fluidInstruction.IsProtocolInstruction(DYNODE_MODFIY_TX)
		|| fluidInstruction.IsProtocolInstruction(MINING_MODIFY_TX)
		|| fluidInstruction.IsProtocolInstruction(REALLOW_TX)
		|| fluidInstruction.IsProtocolInstruction(STERILIZE_TX)
		) {
			verificationString = ScriptToAsmStr(fluidInstruction);
			
			std::string message;
			if (CheckIfQuorumExists(verificationString, message)) {
				BOOST_FOREACH(const std::string& existingRecord, transactionRecord)
				{
					if (existingRecord == verificationString) {
						return false;
					}
				}
				
				transactionRecord.push_back(verificationString);
				return true;
			}
	}
	
	return false;
}

/* Check if transaction exists in record */
bool Fluid::CheckTransactionInRecord(CScript fluidInstruction) {
	std::string verificationString;
	std::vector<std::string> transactionRecord;
	if (chainActive.Height() <= minimumThresholdForBanning)
		return false;
	else transactionRecord = chainActive.Tip()->existingFluidTransactions;
	
	if (fluidInstruction.IsProtocolInstruction(MINT_TX) 
		|| fluidInstruction.IsProtocolInstruction(DYNODE_MODFIY_TX)
		|| fluidInstruction.IsProtocolInstruction(MINING_MODIFY_TX)
		|| fluidInstruction.IsProtocolInstruction(REALLOW_TX)
		|| fluidInstruction.IsProtocolInstruction(STERILIZE_TX)
		) {
			verificationString = ScriptToAsmStr(fluidInstruction);
			
			std::string message;
			if (CheckIfQuorumExists(verificationString, message)) {
				BOOST_FOREACH(const std::string& existingRecord, transactionRecord)
				{
					if (existingRecord == verificationString) {
						return true;
					}
				}
			}
	}
	
	return false;
}
