/**
 * Copyright (c) 2017 Everybody and Nobody (Empinel/Plaxton)
 * Copyright (c) 2017 The Dynamic Developers
 * Copyright (c) 2014-2017 The Syscoin Developers
 * Copyright (c) 2016-2017 Duality Blockchain Solutions Ltd.
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

#include "message.h"
#include "identity.h"
#include "cert.h"
#include "init.h"
#include "main.h"
#include "util.h"
#include "random.h"
#include "base58.h"
#include "core_io.h"
#include "rpcserver.h"
#include "wallet/wallet.h"
#include "chainparams.h"
#include <boost/algorithm/hex.hpp>
#include <boost/xpressive/xpressive_dynamic.hpp>
#include <boost/foreach.hpp>
#include <boost/thread.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <functional> 

using namespace std;

extern void SendMoneyDynamic(const vector<CRecipient> &vecSend, CAmount nValue, bool fSubtractFeeFromAmount, CWalletTx& wtxNew, const CWalletTx* wtxInIdentity=NULL, int nTxOutIdentity = 0, bool dynamicMultiSigTx=false, const CCoinControl* coinControl=NULL, const CWalletTx* wtxInLinkIdentity=NULL,  int nTxOutLinkIdentity = 0);

void PutToMessageList(std::vector<CMessage> &messageList, CMessage& index) {
	int i = messageList.size() - 1;
	BOOST_REVERSE_FOREACH(CMessage &o, messageList) {
        if(index.nHeight != 0 && o.nHeight == index.nHeight) {
        	messageList[i] = index;
            return;
        }
        else if(!o.txHash.IsNull() && o.txHash == index.txHash) {
        	messageList[i] = index;
            return;
        }
        i--;
	}
    messageList.push_back(index);
}
bool IsMessageOp(int op) {
    return op == OP_MESSAGE_ACTIVATE;
}

uint64_t GetMessageExpiration(const CMessage& message) {
	uint64_t nTime = chainActive.Tip()->nTime + 1;
	CIdentityUnprunable identityUnprunable;
	if (pidentitydb && pidentitydb->ReadIdentityUnprunable(message.vchIdentityTo, identityUnprunable) && !identityUnprunable.IsNull())
		nTime = identityUnprunable.nExpireTime;
	
	return nTime;
}


string messageFromOp(int op) {
    switch (op) {
    case OP_MESSAGE_ACTIVATE:
        return "messageactivate";
    default:
        return "<unknown message op>";
    }
}
bool CMessage::UnserializeFromData(const vector<unsigned char> &vchData, const vector<unsigned char> &vchHash) {
    try {
        CDataStream dsMessage(vchData, SER_NETWORK, PROTOCOL_VERSION);
        dsMessage >> *this;
    } catch (std::exception &e) {
		SetNull();
        return false;
    }
	vector<unsigned char> vchMsgData ;
	Serialize(vchMsgData);
	const uint256 &calculatedHash = Hash(vchMsgData.begin(), vchMsgData.end());
	const vector<unsigned char> &vchRandMsg = vchFromValue(calculatedHash.GetHex());
	if(vchRandMsg != vchHash)
	{
		SetNull();
        return false;
	}
	return true;
}
bool CMessage::UnserializeFromTx(const CTransaction &tx) {
	vector<unsigned char> vchData;
	vector<unsigned char> vchHash;
	int nOut;
	if(!GetDynamicData(tx, vchData, vchHash, nOut))
	{
		SetNull();
		return false;
	}
	if(!UnserializeFromData(vchData, vchHash))
	{
		return false;
	}
    return true;
}
void CMessage::Serialize(vector<unsigned char>& vchData) {
    CDataStream dsMessage(SER_NETWORK, PROTOCOL_VERSION);
    dsMessage << *this;
	vchData = vector<unsigned char>(dsMessage.begin(), dsMessage.end());

}
bool CMessageDB::CleanupDatabase(int &servicesCleaned)
{
	boost::scoped_ptr<CDBIterator> pcursor(NewIterator());
	pcursor->SeekToFirst();
	vector<CMessage> vtxPos;
	pair<string, vector<unsigned char> > key;
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        try {
			if (pcursor->GetKey(key) && key.first == "messagei") {
            	const vector<unsigned char> &vchMyMessage= key.second;         
				pcursor->GetValue(vtxPos);	
				if (vtxPos.empty()){
					servicesCleaned++;
					EraseMessage(vchMyMessage);
					pcursor->Next();
					continue;
				}
				const CMessage &txPos = vtxPos.back();
  				if (chainActive.Tip()->nTime >= GetMessageExpiration(txPos))
				{
					servicesCleaned++;
					EraseMessage(vchMyMessage);
				} 
				
            }
            pcursor->Next();
        } catch (std::exception &e) {
            return error("%s() : deserialize error", __PRETTY_FUNCTION__);
        }
    }
	return true;
}

bool CMessageDB::ScanRecvMessages(const std::vector<unsigned char>& vchMessage, const vector<string>& keyWordArray,unsigned int nMax,
        std::vector<CMessage> & messageScan) {
	boost::scoped_ptr<CDBIterator> pcursor(NewIterator());
	if(!vchMessage.empty())
		pcursor->Seek(make_pair(string("messagei"), vchMessage));
	else
		pcursor->SeekToFirst();
	pair<string, vector<unsigned char> > key;
	 vector<CMessage> vtxPos;
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        try {
            if (pcursor->GetKey(key) && key.first == "messagei") {
                const vector<unsigned char> &vchMyMessage = key.second;     
                pcursor->GetValue(vtxPos);
				if (vtxPos.empty()){
					pcursor->Next();
					continue;
				}
				const CMessage &txPos = vtxPos.back();
  				if (chainActive.Tip()->nTime >= GetMessageExpiration(txPos))
				{
					pcursor->Next();
					continue;
				}

				if(keyWordArray.size() > 0)
				{
					string toIdentityLower = stringFromVch(txPos.vchIdentityTo);
					if (std::find(keyWordArray.begin(), keyWordArray.end(), toIdentityLower) == keyWordArray.end())
					{
						pcursor->Next();
						continue;
					}
				}
				if(vchMessage.size() > 0)
				{
					if(vchMyMessage != vchMessage)
					{
						pcursor->Next();
						continue;
					}
				}
                messageScan.push_back(txPos);
            }
            if (messageScan.size() >= nMax)
                break;

            pcursor->Next();
        } catch (std::exception &e) {
            return error("%s() : deserialize error", __PRETTY_FUNCTION__);
        }
    }
    return true;
}

int IndexOfMessageOutput(const CTransaction& tx) {
	if (tx.nVersion != DYNAMIC_TX_VERSION)
		return -1;
    vector<vector<unsigned char> > vvch;
	int op;
	for (unsigned int i = 0; i < tx.vout.size(); i++) {
		const CTxOut& out = tx.vout[i];
		// find an output you own
		if (pwalletMain->IsMine(out) && DecodeMessageScript(out.scriptPubKey, op, vvch)) {
			return i;
		}
	}
	return -1;
}


bool GetTxOfMessage(const vector<unsigned char> &vchMessage,
        CMessage& txPos, CTransaction& tx) {
    vector<CMessage> vtxPos;
    if (!pmessagedb->ReadMessage(vchMessage, vtxPos) || vtxPos.empty())
        return false;
    txPos = vtxPos.back();
    int nHeight = txPos.nHeight;
    if (chainActive.Tip()->nTime >= GetMessageExpiration(txPos)) {
        string message = stringFromVch(vchMessage);
        LogPrintf("GetTxOfMessage(%s) : expired", message.c_str());
        return false;
    }

    if (!GetDynamicTransaction(nHeight, txPos.txHash, tx, Params().GetConsensus()))
        return error("GetTxOfMessage() : could not read tx from disk");

    return true;
}
bool DecodeAndParseMessageTx(const CTransaction& tx, int& op, int& nOut,
		vector<vector<unsigned char> >& vvch)
{
	CMessage message;
	bool decode = DecodeMessageTx(tx, op, nOut, vvch);
	bool parse = message.UnserializeFromTx(tx);
	return decode && parse;
}
bool DecodeMessageTx(const CTransaction& tx, int& op, int& nOut,
        vector<vector<unsigned char> >& vvch) {
    bool found = false;


    // Strict check - bug disallowed
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& out = tx.vout[i];
        vector<vector<unsigned char> > vvchRead;
        if (DecodeMessageScript(out.scriptPubKey, op, vvchRead)) {
            nOut = i; found = true; vvch = vvchRead;
            break;
        }
    }
	if (!found) vvch.clear();
    return found;
}

bool DecodeMessageScript(const CScript& script, int& op,
        vector<vector<unsigned char> > &vvch, CScript::const_iterator& pc) {
    opcodetype opcode;
	vvch.clear();
	if (!script.GetOp(pc, opcode)) return false;
	if (opcode < OP_1 || opcode > OP_16) return false;
    op = CScript::DecodeOP_N(opcode);
	bool found = false;
	for (;;) {
		vector<unsigned char> vch;
		if (!script.GetOp(pc, opcode, vch))
			return false;
		if (opcode == OP_DROP || opcode == OP_2DROP)
		{
			found = true;
			break;
		}
		if (!(opcode >= 0 && opcode <= OP_PUSHDATA4))
			return false;
		vvch.push_back(vch);
	}

	// move the pc to after any DROP or NOP
	while (opcode == OP_DROP || opcode == OP_2DROP) {
		if (!script.GetOp(pc, opcode))
			break;
	}

	pc--;
	return found && IsMessageOp(op);
}

bool DecodeMessageScript(const CScript& script, int& op,
        vector<vector<unsigned char> > &vvch) {
    CScript::const_iterator pc = script.begin();
    return DecodeMessageScript(script, op, vvch, pc);
}

bool RemoveMessageScriptPrefix(const CScript& scriptIn, CScript& scriptOut) {
    int op;
    vector<vector<unsigned char> > vvch;
    CScript::const_iterator pc = scriptIn.begin();

    if (!DecodeMessageScript(scriptIn, op, vvch, pc))
		return false;
	scriptOut = CScript(pc, scriptIn.end());
	return true;
}

bool CheckMessageInputs(const CTransaction &tx, int op, int nOut, const vector<vector<unsigned char> > &vvchArgs, const CCoinsViewCache &inputs, bool fJustCheck, int nHeight, string &errorMessage, bool dontaddtodb) {
	if (tx.IsCoinBase() && !fJustCheck && !dontaddtodb)
	{
		LogPrintf("*Trying to add message in coinbase transaction, skipping...");
		return true;
	}
	if (fDebug)
		LogPrintf("*** MESSAGE %d %d %s %s\n", nHeight,
			chainActive.Tip()->nHeight, tx.GetHash().ToString().c_str(),
			fJustCheck ? "JUSTCHECK" : "BLOCK");
    const COutPoint *prevOutput = NULL;
    const CCoins *prevCoins;

	int prevIdentityOp = 0;
	if (tx.nVersion != DYNAMIC_TX_VERSION)
	{
		errorMessage = "DYNAMIC_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3000 - " + _("Non-Dynamic transaction found");
		return true;
	}
	// unserialize msg from txn, check for valid
	CMessage theMessage;
	CIdentityIndex identity;
	CTransaction identityTx;
	vector<unsigned char> vchData;
	vector<unsigned char> vchHash;
	int nDataOut;
	if(!GetDynamicData(tx, vchData, vchHash, nDataOut) || !theMessage.UnserializeFromData(vchData, vchHash))
	{
		errorMessage = "DYNAMIC_MESSAGE_CONSENSUS_ERROR ERRCODE: 3001 - " + _("Cannot unserialize data inside of this transaction relating to a message");
		return true;
	}

    vector<vector<unsigned char> > vvchPrevIdentityArgs;
	if(fJustCheck)
	{	
		if(vvchArgs.size() != 2)
		{
			errorMessage = "DYNAMIC_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3002 - " + _("Message arguments incorrect size");
			return error(errorMessage.c_str());
		}
		if(!theMessage.IsNull())
		{
			if(vvchArgs.size() <= 1 || vchHash != vvchArgs[1])
			{
				errorMessage = "DYNAMIC_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3003 - " + _("Hash provided doesn't match the calculated hash of the data");
				return true;
			}
		}
		

		// Strict check - bug disallowed
		for (unsigned int i = 0; i < tx.vin.size(); i++) {
			vector<vector<unsigned char> > vvch;
			int pop;
			prevOutput = &tx.vin[i].prevout;
			if(!prevOutput)
				continue;
			// ensure inputs are unspent when doing consensus check to add to block
			prevCoins = inputs.AccessCoins(prevOutput->hash);
			if(prevCoins == NULL)
				continue;
			if(prevCoins->vout.size() <= prevOutput->n || !IsDynamicScript(prevCoins->vout[prevOutput->n].scriptPubKey, pop, vvch) || pop == OP_IDENTITY_PAYMENT)
				continue;
			if (IsIdentityOp(pop))
			{
				prevIdentityOp = pop;
				vvchPrevIdentityArgs = vvch;
				break;
			}
		}	
	}

    // unserialize message UniValue from txn, check for valid
   
	string retError = "";
	if(fJustCheck)
	{
		if (vvchArgs.empty() || vvchArgs[0].size() > MAX_GUID_LENGTH)
		{
			errorMessage = "DYNAMIC_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3004 - " + _("Message transaction guid too big");
			return error(errorMessage.c_str());
		}
		if(theMessage.vchSubject.size() > MAX_NAME_LENGTH)
		{
			errorMessage = "DYNAMIC_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3005 - " + _("Message subject too long");
			return error(errorMessage.c_str());
		}
		if(theMessage.vchMessageTo.size() > MAX_ENCRYPTED_MESSAGE_LENGTH)
		{
			errorMessage = "DYNAMIC_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3006 - " + _("Message too long");
			return error(errorMessage.c_str());
		}
		if(theMessage.vchMessageFrom.size() > MAX_ENCRYPTED_VALUE_LENGTH)
		{
			errorMessage = "DYNAMIC_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3007 - " + _("Message too long");
			return error(errorMessage.c_str());
		}
		if(!theMessage.vchMessage.empty() && theMessage.vchMessage != vvchArgs[0])
		{
			errorMessage = "DYNAMIC_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3008 - " + _("Message guid in data output does not match guid in transaction");
			return error(errorMessage.c_str());
		}
		if(!IsValidIdentityName(theMessage.vchIdentityFrom))
		{
			errorMessage = "DYNAMIC_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3009 - " + _("Identity name does not follow the domain name specification");
			return error(errorMessage.c_str());
		}
		if(!IsValidIdentityName(theMessage.vchIdentityTo))
		{
			errorMessage = "DYNAMIC_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3010 - " + _("Identity name does not follow the domain name specification");
			return error(errorMessage.c_str());
		}
		if(op == OP_MESSAGE_ACTIVATE)
		{
			if(!IsIdentityOp(prevIdentityOp) || vvchPrevIdentityArgs.empty() || theMessage.vchIdentityFrom != vvchPrevIdentityArgs[0])
			{
				errorMessage = "DYNAMIC_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3011 - " + _("Identity not provided as input");
				return error(errorMessage.c_str());
			}
			if (theMessage.vchMessage != vvchArgs[0])
			{
				errorMessage = "DYNAMIC_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3012 - " + _("Message guid mismatch");
				return error(errorMessage.c_str());
			}

		}
		else{
			errorMessage = "DYNAMIC_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3013 - " + _("Message transaction has unknown op");
			return error(errorMessage.c_str());
		}
	}
	// save serialized message for later use
	CMessage serializedMessage = theMessage;


    if (!fJustCheck ) {
		vector<CIdentityIndex> vtxIdentity;
		bool isExpired = false;
		if(!GetVtxOfIdentity(theMessage.vchIdentityTo, identity, vtxIdentity, isExpired))
		{
			errorMessage = "DYNAMIC_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3014 - " + _("Cannot find identity for the recipient of this message. It may be expired");
			return true;
		}

		vector<CMessage> vtxPos;
		if (pmessagedb->ExistsMessage(vvchArgs[0])) {
			errorMessage = "DYNAMIC_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3016 - " + _("This message already exists");
			return true;
		}      
        // set the message's txn-dependent values
		theMessage.txHash = tx.GetHash();
		theMessage.nHeight = nHeight;
		if(theMessage.bHex)
			theMessage.vchMessageFrom.clear();
		PutToMessageList(vtxPos, theMessage);
        // write message  

		if(!dontaddtodb && !pmessagedb->WriteMessage(vvchArgs[0], vtxPos))
		{
			errorMessage = "DYNAMIC_MESSAGE_CONSENSUS_ERROR: ERRCODE: 3016 - " + _("Failed to write to message DB");
            return error(errorMessage.c_str());
		}
	
		
      			
        // debug
		if(fDebug)
			LogPrintf( "CONNECTED MESSAGE: op=%s message=%s hash=%s height=%d\n",
                messageFromOp(op).c_str(),
                stringFromVch(vvchArgs[0]).c_str(),
                tx.GetHash().ToString().c_str(),
                nHeight);
	}
    return true;
}

UniValue messagenew(const UniValue& params, bool fHelp) {
    if (fHelp || 4 > params.size() || 5 < params.size() )
        throw runtime_error(
		"messagenew <subject> <message> <fromidentity> <toidentity> [hex='No']\n"
						"<subject> Subject of message.\n"
						"<message> Message to send to identity.\n"
						"<fromidentity> Identity to send message from.\n"
						"<toidentity> Identity to send message to.\n"	
						"<hex> Is data an hex based message(only To-Message will be displayed). No by default.\n"	
                        + HelpRequiringPassphrase());
	vector<unsigned char> vchMySubject = vchFromValue(params[0]);
	vector<unsigned char> vchMyMessage = vchFromString(params[1].get_str());
	string strFromAddress = params[2].get_str();
	boost::algorithm::to_lower(strFromAddress);
	string strToAddress = params[3].get_str();
	boost::algorithm::to_lower(strToAddress);
	bool bHex = false;
	if(params.size() >= 5)
		bHex = params[4].get_str() == "Yes"? true: false;

	EnsureWalletIsUnlocked();

	CIdentityIndex identityFrom, identityTo;
	CTransaction identitytx;
	if (!GetTxOfIdentity(vchFromString(strFromAddress), identityFrom, identitytx))
		throw runtime_error("DYNAMIC_MESSAGE_RPC_ERROR: ERRCODE: 3500 - " + _("Could not find an identity with this name"));
    if(!IsMyIdentity(identityFrom)) {
		throw runtime_error("DYNAMIC_MESSAGE_RPC_ERROR: ERRCODE: 3501 - " + _("This identity is not yours"));
    }
	CScript scriptPubKeyIdentityOrig, scriptPubKeyIdentity, scriptPubKeyOrig, scriptPubKey;
	CDynamicAddress fromAddr;
	GetAddress(identityFrom, &fromAddr, scriptPubKeyIdentityOrig);

	// lock coins before going into identityunspent if we are sending raw tx that uses inputs in our wallet
	vector<COutPoint> lockedOutputs;
	if(bHex)
	{
		CTransaction rawTx;
		DecodeHexTx(rawTx,stringFromVch(vchMyMessage));
		BOOST_FOREACH(const CTxIn& txin, rawTx.vin)
		{
			if(!pwalletMain->IsLockedCoin(txin.prevout.hash, txin.prevout.n))
			{
              LOCK2(cs_main, pwalletMain->cs_wallet);
              pwalletMain->LockCoin(txin.prevout);
			  lockedOutputs.push_back(txin.prevout);
			}
		}
	}
	
	COutPoint outPoint;
	int numResults  = identityunspent(identityFrom.vchIdentity, outPoint);	
	const CWalletTx *wtxIdentityIn = pwalletMain->GetWalletTx(outPoint.hash);
	if (wtxIdentityIn == NULL)
	{
		BOOST_FOREACH(const COutPoint& outpoint, lockedOutputs)
		{
			 LOCK2(cs_main, pwalletMain->cs_wallet);
			 pwalletMain->UnlockCoin(outpoint);
		}
		throw runtime_error("DYNAMIC_MESSAGE_RPC_ERROR: ERRCODE: 3502 - " + _("This identity is not in your wallet"));
	}


	scriptPubKeyIdentity << CScript::EncodeOP_N(OP_IDENTITY_UPDATE) << identityFrom.vchIdentity <<  identityFrom.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
	scriptPubKeyIdentity += scriptPubKeyIdentityOrig;		


	if(!GetTxOfIdentity(vchFromString(strToAddress), identityTo, identitytx))
	{
		BOOST_FOREACH(const COutPoint& outpoint, lockedOutputs)
		{
			 LOCK2(cs_main, pwalletMain->cs_wallet);
			 pwalletMain->UnlockCoin(outpoint);
		}
		throw runtime_error("DYNAMIC_MESSAGE_RPC_ERROR: ERRCODE: 3503 - " + _("Failed to read to identity from identity DB"));
	}
	CDynamicAddress toAddr;
	GetAddress(identityTo, &toAddr, scriptPubKeyOrig);


    // gather inputs
	vector<unsigned char> vchMessage = vchFromString(GenerateDynamicGuid());
    // this is a dynamic transaction
    CWalletTx wtx;

	vector<unsigned char> vchMessageByte;
	if(bHex)
		boost::algorithm::unhex(vchMyMessage.begin(), vchMyMessage.end(), std::back_inserter(vchMessageByte ));
	else
		vchMessageByte = vchMyMessage;
	
	

	string strCipherTextTo;
	if(!EncryptMessage(identityTo, vchMessageByte, strCipherTextTo))
	{
		BOOST_FOREACH(const COutPoint& outpoint, lockedOutputs)
		{
			 LOCK2(cs_main, pwalletMain->cs_wallet);
			 pwalletMain->UnlockCoin(outpoint);
		}
		throw runtime_error("DYNAMIC_MESSAGE_RPC_ERROR: ERRCODE: 3504 - " + _("Could not encrypt message data for receiver"));
	}
	string strCipherTextFrom;
	if(!EncryptMessage(identityFrom, vchMessageByte, strCipherTextFrom))
	{
		BOOST_FOREACH(const COutPoint& outpoint, lockedOutputs)
		{
			 LOCK2(cs_main, pwalletMain->cs_wallet);
			 pwalletMain->UnlockCoin(outpoint);
		}
		throw runtime_error("DYNAMIC_MESSAGE_RPC_ERROR: ERRCODE: 3505 - " + _("Could not encrypt message data for sender"));
	}

    // build message
    CMessage newMessage;
	newMessage.vchMessage = vchMessage;
	if(!bHex)
		newMessage.vchMessageFrom = vchFromString(strCipherTextFrom);
	newMessage.vchMessageTo = vchFromString(strCipherTextTo);
	newMessage.vchSubject = vchMySubject;
	newMessage.vchIdentityFrom = identityFrom.vchIdentity;
	newMessage.bHex = bHex;
	newMessage.vchIdentityTo = identityTo.vchIdentity;
	newMessage.nHeight = chainActive.Tip()->nHeight;

	vector<unsigned char> data;
	newMessage.Serialize(data);
    uint256 hash = Hash(data.begin(), data.end());
 	
    vector<unsigned char> vchHashMessage = vchFromValue(hash.GetHex());
	scriptPubKey << CScript::EncodeOP_N(OP_MESSAGE_ACTIVATE) << vchMessage << vchHashMessage << OP_2DROP << OP_DROP;
	scriptPubKey += scriptPubKeyOrig;

	// send the tranasction
	vector<CRecipient> vecSend;
	CRecipient recipient;
	CreateRecipient(scriptPubKey, recipient);
	vecSend.push_back(recipient);
	CRecipient identityRecipient;
	CreateRecipient(scriptPubKeyIdentity, identityRecipient);
	for(unsigned int i =numResults;i<=MAX_IDENTITY_UPDATES_PER_BLOCK;i++)
		vecSend.push_back(identityRecipient);

	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, identityFrom.vchIdentityPeg, chainActive.Tip()->nHeight, data, fee);
	vecSend.push_back(fee);
	
	
	
	SendMoneyDynamic(vecSend, recipient.nAmount+fee.nAmount, false, wtx, wtxIdentityIn, outPoint.n, identityFrom.multiSigInfo.vchIdentityes.size() > 0);
	UniValue res(UniValue::VARR);
	if(identityFrom.multiSigInfo.vchIdentityes.size() > 0)
	{
		UniValue signParams(UniValue::VARR);
		signParams.push_back(EncodeHexTx(wtx));
		const UniValue &resSign = tableRPC.execute("dynamicsignrawtransaction", signParams);
		const UniValue& so = resSign.get_obj();
		string hex_str = "";

		const UniValue& hex_value = find_value(so, "hex");
		if (hex_value.isStr())
			hex_str = hex_value.get_str();
		const UniValue& complete_value = find_value(so, "complete");
		bool bComplete = false;
		if (complete_value.isBool())
			bComplete = complete_value.get_bool();
		if(bComplete)
		{
			res.push_back(wtx.GetHash().GetHex());
			res.push_back(stringFromVch(vchMessage));
		}
		else
		{
			res.push_back(hex_str);
			res.push_back(stringFromVch(vchMessage));
			res.push_back("false");
		}
	}
	else
	{
		res.push_back(wtx.GetHash().GetHex());
		res.push_back(stringFromVch(vchMessage));
	}
	// once we have used correct inputs for this message unlock coins that were locked in the wallet
	BOOST_FOREACH(const COutPoint& outpoint, lockedOutputs)
	{
		 LOCK2(cs_main, pwalletMain->cs_wallet);
		 pwalletMain->UnlockCoin(outpoint);
	}
	return res;
}

UniValue messageinfo(const UniValue& params, bool fHelp) {
    if (fHelp || 1 != params.size())
        throw runtime_error("messageinfo <guid>\n"
                "Show stored values of a single message.\n");

    vector<unsigned char> vchMessage = vchFromValue(params[0]);

    // look for a transaction with this key, also returns
    // an message UniValue if it is found
    CTransaction tx;

	vector<CMessage> vtxPos;

    UniValue oMessage(UniValue::VOBJ);
    vector<unsigned char> vchValue;

	if (!pmessagedb->ReadMessage(vchMessage, vtxPos) || vtxPos.empty())
		throw runtime_error("DYNAMIC_MESSAGE_RPC_ERROR: ERRCODE: 3506 - " + _("Failed to read from message DB"));

	if(!BuildMessageJson(vtxPos.back(), oMessage))
		throw runtime_error("DYNAMIC_MESSAGE_RPC_ERROR: ERRCODE: 3507 - " + _("Could not find this message"));

    return oMessage;
}

UniValue messagereceivelist(const UniValue& params, bool fHelp) {
    if (fHelp || 3 < params.size())
        throw runtime_error("messagereceivelist [\"identity\",...] [<message>] [<privatekey>]\n"
                "list received messages that an array of identities own. Set of identities to look up based on identity, and private key to decrypt any data found in message.");
	UniValue identitiesValue(UniValue::VARR);
	vector<string> identities;
	if(params.size() >= 1)
	{
		if(params[0].isArray())
		{
			identitiesValue = params[0].get_array();
			for(unsigned int identityIndex =0;identityIndex<identitiesValue.size();identityIndex++)
			{
				string lowerStr = identitiesValue[identityIndex].get_str();
				boost::algorithm::to_lower(lowerStr);
				if(!lowerStr.empty())
					identities.push_back(lowerStr);
			}
		}
		else
		{
			string identityName =  params[0].get_str();
			boost::algorithm::to_lower(identityName);
			if(!identityName.empty())
				identities.push_back(identityName);
		}
	}
	vector<unsigned char> vchNameUniq;
    if (params.size() >= 2 && !params[1].get_str().empty())
        vchNameUniq = vchFromValue(params[1]);

	string strPrivateKey;
	if(params.size() >= 3)
		strPrivateKey = params[2].get_str();

	UniValue oRes(UniValue::VARR);
	map< vector<unsigned char>, int > vNamesI;
	vector<CMessage > messageScan;
	if(identities.size() > 0)
	{
		if (!pmessagedb->ScanRecvMessages(vchNameUniq, identities, 1000, messageScan))
			throw runtime_error("DYNAMIC_MESSAGE_RPC_ERROR: ERRCODE: 3508 - " + _("Scan failed"));
	}
	else
	{
		BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, pwalletMain->mapWallet)
		{
			const CWalletTx &wtx = item.second; 
			if (wtx.nVersion != DYNAMIC_TX_VERSION)
				continue;
			if(!IsDynamicTxMine(wtx, "message"))
				continue;
			CMessage message(wtx);
			if(!message.IsNull())
			{
				if (vNamesI.find(message.vchMessage) != vNamesI.end())
					continue;
				if (vchNameUniq.size() > 0 && vchNameUniq != message.vchMessage)
					continue;
				messageScan.push_back(message);
				vNamesI[message.vchMessage] = message.nHeight;
				UniValue oName(UniValue::VOBJ);
				if(BuildMessageJson(message, oName, strPrivateKey))
					oRes.push_back(oName);
			}
		}
	}
	BOOST_FOREACH(const CMessage &message, messageScan) {
		// build the output
		UniValue oName(UniValue::VOBJ);
		if(BuildMessageJson(message, oName, strPrivateKey))
			oRes.push_back(oName);
	}
	

    return oRes;
}
bool BuildMessageJson(const CMessage& message, UniValue& oName, const string &strPrivKey)
{
	CIdentityIndex identityFrom, identityTo;
	CTransaction identitytxtmp;
	bool isExpired = false;
	vector<CIdentityIndex> identityVtxPos;
	if(GetTxAndVtxOfIdentity(message.vchIdentityFrom, identityFrom, identitytxtmp, identityVtxPos, isExpired, true))
	{
		identityFrom.nHeight = message.nHeight;
		identityFrom.GetIdentityFromList(identityVtxPos);
	}
	else
		return false;
	identityVtxPos.clear();
	if(GetTxAndVtxOfIdentity(message.vchIdentityTo, identityTo, identitytxtmp, identityVtxPos, isExpired, true))
	{
		identityTo.nHeight = message.nHeight;
		identityTo.GetIdentityFromList(identityVtxPos);
	}
	else
		return false;
	oName.push_back(Pair("GUID", stringFromVch(message.vchMessage)));
	string sTime;
	CBlockIndex *pindex = chainActive[message.nHeight];
	if (pindex) {
		sTime = strprintf("%llu", pindex->nTime);
	}
	string strAddress = "";
	oName.push_back(Pair("txid", message.txHash.GetHex()));
	oName.push_back(Pair("time", sTime));
	oName.push_back(Pair("from", stringFromVch(message.vchIdentityFrom)));
	oName.push_back(Pair("to", stringFromVch(message.vchIdentityTo)));

	oName.push_back(Pair("subject", stringFromVch(message.vchSubject)));
	string strDecrypted = "";
	string strData = _("Encrypted for recipient of message");
	if(DecryptMessage(identityTo, message.vchMessageTo, strDecrypted, strPrivKey))
	{
		if(message.bHex)
			strData = HexStr(strDecrypted);
		else
			strData = strDecrypted;
	}
	else if(!message.bHex && DecryptMessage(identityFrom, message.vchMessageFrom, strDecrypted, strPrivKey))
		strData = strDecrypted;

	oName.push_back(Pair("message", strData));
	return true;
}

UniValue messagesentlist(const UniValue& params, bool fHelp) {
    if (fHelp || 3 < params.size())
        throw runtime_error("messagesentlist [\"identity\",...] [<message>] [<privatekey>]\n"
                "list sent messages that an array of identities own. Set of identities to look up based on identity, and private key to decrypt any data found in message.");
	UniValue identitiesValue(UniValue::VARR);
	vector<string> identities;
	if(params.size() >= 1)
	{
		if(params[0].isArray())
		{
			identitiesValue = params[0].get_array();
			for(unsigned int identityIndex =0;identityIndex<identitiesValue.size();identityIndex++)
			{
				string lowerStr = identitiesValue[identityIndex].get_str();
				boost::algorithm::to_lower(lowerStr);
				if(!lowerStr.empty())
					identities.push_back(lowerStr);
			}
		}
		else
		{
			string identityName =  params[0].get_str();
			boost::algorithm::to_lower(identityName);
			if(!identityName.empty())
				identities.push_back(identityName);
		}
	}
	vector<unsigned char> vchNameUniq;
    if (params.size() >= 2 && !params[1].get_str().empty())
        vchNameUniq = vchFromValue(params[1]);

	string strPrivateKey;
	if(params.size() >= 3)
		strPrivateKey = params[2].get_str();

	UniValue oRes(UniValue::VARR);
	map< vector<unsigned char>, int > vNamesI;
	vector<CMessage> messageScan;
	if(identities.size() > 0)
	{
		for(unsigned int identityIndex =0;identityIndex<identities.size();identityIndex++)
		{
			string name = identities[identityIndex];
			vector<unsigned char> vchIdentity = vchFromString(name);
			vector<CIdentityIndex> vtxPos;
			if (!pidentitydb->ReadIdentity(vchIdentity, vtxPos) || vtxPos.empty())
				continue;
		
			const CIdentityIndex &identity = vtxPos.back();
			CTransaction identitytx;
			uint256 txHash;
			if (!GetDynamicTransaction(identity.nHeight, identity.txHash, identitytx, Params().GetConsensus()))
				continue;

			CTransaction tx;

			vector<unsigned char> vchValue;
			BOOST_FOREACH(const CIdentityIndex &theIdentity, vtxPos)
			{
				if(!GetDynamicTransaction(theIdentity.nHeight, theIdentity.txHash, tx, Params().GetConsensus()))
					continue;

				CMessage message(tx);
				if(!message.IsNull() && message.vchIdentityFrom == vchIdentity)
				{
					if (vNamesI.find(message.vchMessage) != vNamesI.end())
						continue;
					if (vchNameUniq.size() > 0 && vchNameUniq != message.vchMessage)
						continue;
					messageScan.push_back(message);
					vNamesI[message.vchMessage] = message.nHeight;
				}
			}
		}
	}
	else
	{
		BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, pwalletMain->mapWallet)
		{
			const CWalletTx &wtx = item.second; 
			if (wtx.nVersion != DYNAMIC_TX_VERSION)
				continue;
			if(IsDynamicTxMine(wtx, "message"))
				continue;
			CMessage message(wtx);
			if(!message.IsNull())
			{
				if (vNamesI.find(message.vchMessage) != vNamesI.end())
					continue;
				if (vchNameUniq.size() > 0 && vchNameUniq != message.vchMessage)
					continue;
				messageScan.push_back(message);
				vNamesI[message.vchMessage] = message.nHeight;
			}
		}
	}
	BOOST_FOREACH(const CMessage &message, messageScan) {
		// build the output
		UniValue oName(UniValue::VOBJ);
		if(BuildMessageJson(message, oName, strPrivateKey))
			oRes.push_back(oName);
	}
    return oRes;
}

void MessageTxToJSON(const int op, const std::vector<unsigned char> &vchData, const std::vector<unsigned char> &vchHash, UniValue &entry)
{
	string opName = messageFromOp(op);
	CMessage message;
	if(!message.UnserializeFromData(vchData, vchHash))
		return;

	bool isExpired = false;
	vector<CIdentityIndex> identityVtxPosFrom;
	vector<CIdentityIndex> identityVtxPosTo;
	CTransaction identitytx;
	CIdentityIndex dbIdentityFrom, dbIdentityTo;
	if(GetTxAndVtxOfIdentity(message.vchIdentityFrom, dbIdentityFrom, identitytx, identityVtxPosFrom, isExpired, true))
	{
		dbIdentityFrom.nHeight = message.nHeight;
		dbIdentityFrom.GetIdentityFromList(identityVtxPosFrom);
	}
	if(GetTxAndVtxOfIdentity(message.vchIdentityTo, dbIdentityTo, identitytx, identityVtxPosTo, isExpired, true))
	{
		dbIdentityTo.nHeight = message.nHeight;
		dbIdentityTo.GetIdentityFromList(identityVtxPosTo);
	}
	entry.push_back(Pair("txtype", opName));
	entry.push_back(Pair("GUID", stringFromVch(message.vchMessage)));

	string identityFromValue = stringFromVch(message.vchIdentityFrom);
	entry.push_back(Pair("from", identityFromValue));

	string identityToValue = stringFromVch(message.vchIdentityTo);
	entry.push_back(Pair("to", identityToValue));

	string subjectValue = stringFromVch(message.vchSubject);
	entry.push_back(Pair("subject", subjectValue));

	string strMessage =_("Encrypted for recipient of message");
	string strDecrypted = "";
	if(DecryptMessage(dbIdentityTo, message.vchMessageTo, strDecrypted))
		strMessage = strDecrypted;
	else if(DecryptMessage(dbIdentityFrom, message.vchMessageFrom, strDecrypted))
		strMessage = strDecrypted;	

	entry.push_back(Pair("message", strMessage));


}
