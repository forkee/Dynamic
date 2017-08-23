/**
 * Copyright (c) 2017 Everybody and Nobody (Empinel/Plaxton)
 * Copyright (c) 2017 The Dynamic Developers
 * Copyright (c) 2013-2017 Emercoin Developers
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

#include "identity.h"
#include "offer.h"
#include "escrow.h"
#include "message.h"
#include "cert.h"
#include "offer.h"
#include "init.h"
#include "main.h"
#include "util.h"
#include "random.h"
#include "wallet/wallet.h"
#include "rpcserver.h"
#include "base58.h"
#include "txmempool.h"
#include "txdb.h"
#include "chainparams.h"
#include "core_io.h"
#include "policy/policy.h"
#include "utiltime.h"
#include "coincontrol.h"

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <boost/xpressive/xpressive_dynamic.hpp>
#include <boost/foreach.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/thread.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string/find.hpp>

using namespace std;

CIdentityDB *pidentitydb = NULL;
COfferDB *pofferdb = NULL;
CCertDB *pcertdb = NULL;
CEscrowDB *pescrowdb = NULL;
CMessageDB *pmessagedb = NULL;

extern CScript GetScriptForMultisig(int nRequired, const std::vector<CPubKey>& keys);
extern void SendMoneyDynamic(const vector<CRecipient> &vecSend, CAmount nValue, bool fSubtractFeeFromAmount, CWalletTx& wtxNew, const CWalletTx* wtxInIdentity=NULL, int nTxOutIdentity = 0, bool dynamicMultiSigTx=false, const CCoinControl* coinControl=NULL, const CWalletTx* wtxInLinkIdentity=NULL,  int nTxOutLinkIdentity = 0);

bool GetDynamicTransaction(int nHeight, const uint256 &hash, CTransaction &txOut, const Consensus::Params& consensusParams)
{
	if(nHeight < 0 || nHeight > chainActive.Height())
		return false;
	CBlockIndex *pindexSlow = NULL; 
	LOCK(cs_main);
	pindexSlow = chainActive[nHeight];
    if (pindexSlow) {
        CBlock block;
        if (ReadBlockFromDisk(block, pindexSlow, consensusParams)) {
            BOOST_FOREACH(const CTransaction &tx, block.vtx) {
                if (tx.GetHash() == hash) {
                    txOut = tx;
                    return true;
                }
            }
        }
    }
	return false;
}

bool GetTimeToPrune(const CScript& scriptPubKey, uint64_t &nTime)
{
	vector<unsigned char> vchData;
	vector<unsigned char> vchHash;
	if(!GetDynamicData(scriptPubKey, vchData, vchHash))
		return false;
	if(!chainActive.Tip())
		return false;
	CIdentityIndex identity;
	COffer offer;
	CMessage message;
	CEscrow escrow;
	CCert cert;
	nTime = 0;
	if(identity.UnserializeFromData(vchData, vchHash))
	{
		if(identity.vchIdentity == vchFromString("dynrates.peg") || identity.vchIdentity == vchFromString("dynban") || identity.vchIdentity == vchFromString("dyncategory"))
		{
			// setting to the tip means we don't prune this data, we keep it
			nTime = chainActive.Tip()->nTime + 1;
			return true;
		}
		CIdentityUnprunable identityUnprunable;
		// we only prune things that we have in our db and that we can verify the last tx is expired
		// nHeight is set to the height at which data is pruned, if the tip is newer than nHeight it won't send data to other nodes
		if (pidentitydb->ReadIdentityUnprunable(identity.vchIdentity, identityUnprunable) && !identityUnprunable.IsNull())
		{	
			// if we are renewing identity then prune based on expiry of identity in tx
			if(!identity.vchGUID.empty() && identityUnprunable.vchGUID != identity.vchGUID)
				nTime = identity.nExpireTime;
			else
				nTime = identityUnprunable.nExpireTime;
			
			return true;				
		}
		// this is a new service, either sent to us because it's not supposed to be expired yet or sent to ourselves as a new service, either way we keep the data and validate it into the service db
		else
		{
			// setting to the tip means we don't prune this data, we keep it
			nTime = chainActive.Tip()->nTime + 1;
			return true;
		}
	}
	else if(offer.UnserializeFromData(vchData, vchHash))
	{
		nTime = GetOfferExpiration(offer);
		return true; 
	}
	else if(cert.UnserializeFromData(vchData, vchHash))
	{
		nTime = GetCertExpiration(cert);
		return true; 
	}
	else if(escrow.UnserializeFromData(vchData, vchHash))
	{
		nTime = GetEscrowExpiration(escrow);
		return true;
	}
	else if(message.UnserializeFromData(vchData, vchHash))
	{
		nTime = GetMessageExpiration(message);
		return true;
	}

	return false;
}
bool IsDynServiceExpired(const uint64_t &nTime)
{
	if(!chainActive.Tip() || fTxIndex)
		return false;
	return (chainActive.Tip()->nTime >= nTime);

}
bool IsDynamicScript(const CScript& scriptPubKey, int &op, vector<vector<unsigned char> > &vvchArgs)
{
	if (DecodeIdentityScript(scriptPubKey, op, vvchArgs))
		return true;
	else if(DecodeOfferScript(scriptPubKey, op, vvchArgs))
		return true;
	else if(DecodeCertScript(scriptPubKey, op, vvchArgs))
		return true;
	else if(DecodeMessageScript(scriptPubKey, op, vvchArgs))
		return true;
	else if(DecodeEscrowScript(scriptPubKey, op, vvchArgs))
		return true;
	return false;
}
void RemoveDynamicScript(const CScript& scriptPubKeyIn, CScript& scriptPubKeyOut)
{
	if (!RemoveIdentityScriptPrefix(scriptPubKeyIn, scriptPubKeyOut))
		if(!RemoveOfferScriptPrefix(scriptPubKeyIn, scriptPubKeyOut))
			if(!RemoveCertScriptPrefix(scriptPubKeyIn, scriptPubKeyOut))
				if(!RemoveEscrowScriptPrefix(scriptPubKeyIn, scriptPubKeyOut))
					RemoveMessageScriptPrefix(scriptPubKeyIn, scriptPubKeyOut);					
}

// how much is 1.1 BTC in dynamic? 1 BTC = 110000 DYN for example, nPrice would be 1.1, dynPrice would be 110000
CAmount convertCurrencyCodeToDynamic(const vector<unsigned char> &vchIdentityPeg, const vector<unsigned char> &vchCurrencyCode, const double &nPrice, const unsigned int &nHeight, int &precision)
{
	CAmount dynPrice = 0;
	double nRate = 1;
	float fEscrowFee = 0.005;
	int nFeePerByte;
	vector<string> rateList;
	try
	{
		if(getCurrencyToDYNFromIdentity(vchIdentityPeg, vchCurrencyCode, nRate, nHeight, rateList, precision, nFeePerByte, fEscrowFee) == "")
		{
			float fTotal = nPrice*nRate;
			CAmount nTotal = fTotal;
			int myprecision = precision;
			if(myprecision < 8)
				myprecision += 1;
			if(nTotal != fTotal)
				dynPrice = AmountFromValue(strprintf("%.*f", myprecision, fTotal)); 
			else
				dynPrice = nTotal*COIN;

		}
	}
	catch(...)
	{
		if(fDebug)
			LogPrintf("convertCurrencyCodeToDynamic() Exception caught getting rate identity information\n");
	}
	if(precision > 8)
		dynPrice = 0;
	return dynPrice;
}
float getEscrowFee(const std::vector<unsigned char> &vchIdentityPeg, const std::vector<unsigned char> &vchCurrencyCode, const unsigned int &nHeight, int &precision)
{
	double nRate;
	int nFeePerByte =0;
	// 0.05% escrow fee by default it not provided
	float fEscrowFee = 0.005;
	vector<string> rateList;
	try
	{
		if(getCurrencyToDYNFromIdentity(vchIdentityPeg, vchCurrencyCode, nRate, nHeight, rateList, precision, nFeePerByte, fEscrowFee) == "")
		{		
			return fEscrowFee;
		}
	}
	catch(...)
	{
		if(fDebug)
			LogPrintf("getEscrowFee() Exception caught getting rate identity information\n");
	}
	return fEscrowFee;
}
int getFeePerByte(const std::vector<unsigned char> &vchIdentityPeg, const std::vector<unsigned char> &vchCurrencyCode, const unsigned int &nHeight, int &precision)
{
	double nRate;
	int nFeePerByte = 25;
	float fEscrowFee = 0.005;
	vector<string> rateList;
	try
	{
		if(getCurrencyToDYNFromIdentity(vchIdentityPeg, vchCurrencyCode, nRate, nHeight, rateList, precision, nFeePerByte, fEscrowFee) == "")
		{
			return nFeePerByte;
		}
	}
	catch(...)
	{
		if(fDebug)
			LogPrintf("getBTCFeePerByte() Exception caught getting rate identity information\n");
	}
	return nFeePerByte;
}
// convert 110000*COIN DYN into 1.1*COIN BTC
CAmount convertDynamicToCurrencyCode(const vector<unsigned char> &vchIdentityPeg, const vector<unsigned char> &vchCurrencyCode, const CAmount &nPrice, const unsigned int &nHeight, int &precision)
{
	CAmount currencyPrice = 0;
	double nRate = 1;
	int nFeePerByte;
	float fEscrowFee = 0.005;
	vector<string> rateList;
	try
	{
		if(getCurrencyToDYNFromIdentity(vchIdentityPeg, vchCurrencyCode, nRate, nHeight, rateList, precision, nFeePerByte, fEscrowFee) == "")
		{
			currencyPrice = CAmount(nPrice/nRate);
		}
	}
	catch(...)
	{
		if(fDebug)
			LogPrintf("convertDynamicToCurrencyCode() Exception caught getting rate identity information\n");
	}
	if(precision > 8)
		currencyPrice = 0;
	return currencyPrice;
}
string getCurrencyToDYNFromIdentity(const vector<unsigned char> &vchIdentityPeg, const vector<unsigned char> &vchCurrency, double &nFee, const unsigned int &nHeightToFind, vector<string>& rateList, int &precision, int &nFeePerByte, float &fEscrowFee)
{
	string currencyCodeToFind = stringFromVch(vchCurrency);
	// check for identity existence in DB
	vector<CIdentityIndex> vtxPos;
	CIdentityIndex tmpIdentity;
	bool isExpired;
	if (!GetVtxOfIdentity(vchIdentityPeg, tmpIdentity, vtxPos, isExpired))
	{
		if(fDebug)
			LogPrintf("getCurrencyToDYNFromIdentity() Could not find %s identity\n", stringFromVch(vchIdentityPeg).c_str());
		return "1";
	}
	CIdentityIndex foundIdentity;
	for(unsigned int i=0;i<vtxPos.size();i++) {
        CIdentityIndex a = vtxPos[i];
        if(a.nHeight <= nHeightToFind) {
            foundIdentity = a;
        }
		else
			break;
    }
	if(foundIdentity.IsNull())
		foundIdentity = vtxPos.back();


	bool found = false;
	string value = stringFromVch(foundIdentity.vchPublicValue);
	
	UniValue outerValue(UniValue::VSTR);
	bool read = outerValue.read(value);
	if (read)
	{
		UniValue outerObj = outerValue.get_obj();
		UniValue ratesValue = find_value(outerObj, "rates");
		if (ratesValue.isArray())
		{
			UniValue codes = ratesValue.get_array();
			for (unsigned int idx = 0; idx < codes.size(); idx++) {
				const UniValue& code = codes[idx];					
				UniValue codeObj = code.get_obj();					
				UniValue currencyNameValue = find_value(codeObj, "currency");
				UniValue currencyAmountValue = find_value(codeObj, "rate");
				if (currencyNameValue.isStr())
				{		
					string currencyCode = currencyNameValue.get_str();
					rateList.push_back(currencyCode);
					if(currencyCodeToFind == currencyCode)
					{		
						UniValue feePerByteValue = find_value(codeObj, "fee");
						if(feePerByteValue.isNum())
						{
							nFeePerByte = feePerByteValue.get_int();
						}
						UniValue escrowFeeValue = find_value(codeObj, "escrowfee");
						if(escrowFeeValue.isNum())
						{
							fEscrowFee = escrowFeeValue.get_real();
						}
						UniValue precisionValue = find_value(codeObj, "precision");
						if(precisionValue.isNum())
						{
							precision = precisionValue.get_int();
						}
						if(currencyAmountValue.isNum())
						{
							found = true;
							try{
							
								nFee = currencyAmountValue.get_real();
							}
							catch(std::runtime_error& err)
							{
								try
								{
									nFee = currencyAmountValue.get_int();
								}
								catch(std::runtime_error& err)
								{
									if(fDebug)
										LogPrintf("getCurrencyToDYNFromIdentity() Failed to get currency amount from value\n");
									return "1";
								}
							}
							
						}
					}
				}
			}
		}
		
	}
	else
	{
		if(fDebug)
			LogPrintf("getCurrencyToDYNFromIdentity() Failed to get value from identity\n");
		return "1";
	}
	if(!found)
	{
		if(fDebug)
			LogPrintf("getCurrencyToDYNFromIdentity() currency %s not found in %s identity\n", stringFromVch(vchCurrency).c_str(), stringFromVch(vchIdentityPeg).c_str());
		return "0";
	}
	return "";

}
void getCategoryListFromValue(vector<string>& categoryList,const UniValue& outerValue)
{
	UniValue outerObj = outerValue.get_obj();
	UniValue objCategoriesValue = find_value(outerObj, "categories");
	UniValue categories = objCategoriesValue.get_array();
	for (unsigned int idx = 0; idx < categories.size(); idx++) {
		const UniValue& category = categories[idx];
		const UniValue& categoryObj = category.get_obj();	
		const UniValue categoryValue = find_value(categoryObj, "cat");
		categoryList.push_back(categoryValue.get_str());
	}
}
bool getBanListFromValue(map<string, unsigned char>& banIdentityList,  map<string, unsigned char>& banCertList,  map<string, unsigned char>& banOfferList,const UniValue& outerValue)
{
	try
		{
		UniValue outerObj = outerValue.get_obj();
		UniValue objOfferValue = find_value(outerObj, "offers");
		if (objOfferValue.isArray())
		{
			UniValue codes = objOfferValue.get_array();
			for (unsigned int idx = 0; idx < codes.size(); idx++) {
				const UniValue& code = codes[idx];					
				UniValue codeObj = code.get_obj();					
				UniValue idValue = find_value(codeObj, "id");
				UniValue severityValue = find_value(codeObj, "severity");
				if (idValue.isStr() && severityValue.isNum())
				{		
					string idStr = idValue.get_str();
					int severityNum = severityValue.get_int();
					banOfferList.insert(make_pair(idStr, severityNum));
				}
			}
		}

		UniValue objCertValue = find_value(outerObj, "certs");
		if (objCertValue.isArray())
		{
			UniValue codes = objCertValue.get_array();
			for (unsigned int idx = 0; idx < codes.size(); idx++) {
				const UniValue& code = codes[idx];					
				UniValue codeObj = code.get_obj();					
				UniValue idValue = find_value(codeObj, "id");
				UniValue severityValue = find_value(codeObj, "severity");
				if (idValue.isStr() && severityValue.isNum())
				{		
					string idStr = idValue.get_str();
					int severityNum = severityValue.get_int();
					banCertList.insert(make_pair(idStr, severityNum));
				}
			}
		}
			
		

		UniValue objIdentityValue = find_value(outerObj, "identities");
		if (objIdentityValue.isArray())
		{
			UniValue codes = objIdentityValue.get_array();
			for (unsigned int idx = 0; idx < codes.size(); idx++) {
				const UniValue& code = codes[idx];					
				UniValue codeObj = code.get_obj();					
				UniValue idValue = find_value(codeObj, "id");
				UniValue severityValue = find_value(codeObj, "severity");
				if (idValue.isStr() && severityValue.isNum())
				{		
					string idStr = idValue.get_str();
					int severityNum = severityValue.get_int();
					banIdentityList.insert(make_pair(idStr, severityNum));
				}
			}
		}
	}
	catch(std::runtime_error& err)
	{	
		if(fDebug)
			LogPrintf("getBanListFromValue(): Failed to get ban list from value\n");
		return false;
	}
	return true;
}
bool getBanList(const vector<unsigned char>& banData, map<string, unsigned char>& banIdentityList,  map<string, unsigned char>& banCertList,  map<string, unsigned char>& banOfferList)
{
	string value = stringFromVch(banData);
	
	UniValue outerValue(UniValue::VSTR);
	bool read = outerValue.read(value);
	if (read)
	{
		return getBanListFromValue(banIdentityList, banCertList, banOfferList, outerValue);
	}
	else
	{
		if(fDebug)
			LogPrintf("getBanList() Failed to get value from identity\n");
		return false;
	}
	return false;

}
bool getCategoryList(vector<string>& categoryList)
{
	// check for identity existence in DB
	vector<CIdentityIndex> vtxPos;
	if (!pidentitydb->ReadIdentity(vchFromString("dyncategory"), vtxPos) || vtxPos.empty())
	{
		if(fDebug)
			LogPrintf("getCategoryList() Could not find dyncategory identity\n");
		return false;
	}
	
	if (vtxPos.size() < 1)
	{
		if(fDebug)
			LogPrintf("getCategoryList() Could not find dyncategory identity (vtxPos.size() == 0)\n");
		return false;
	}

	CIdentityIndex categoryIdentity = vtxPos.back();

	UniValue outerValue(UniValue::VSTR);
	bool read = outerValue.read(stringFromVch(categoryIdentity.vchPublicValue));
	if (read)
	{
		try{
		
			getCategoryListFromValue(categoryList, outerValue);
			return true;
		}
		catch(std::runtime_error& err)
		{
			
			if(fDebug)
				LogPrintf("getCategoryListFromValue(): Failed to get category list from value\n");
			return false;
		}
	}
	else
	{
		if(fDebug)
			LogPrintf("getCategoryList() Failed to get value from identity\n");
		return false;
	}
	return false;

}
void PutToIdentityList(std::vector<CIdentityIndex> &identityList, CIdentityIndex& index) {
	int i = identityList.size() - 1;
	BOOST_REVERSE_FOREACH(CIdentityIndex &o, identityList) {
        if(!o.txHash.IsNull() && o.txHash == index.txHash) {
        	identityList[i] = index;
            return;
        }
        i--;
	}
    identityList.push_back(index);
}

bool IsIdentityOp(int op) {
	return op == OP_IDENTITY_ACTIVATE
			|| op == OP_IDENTITY_UPDATE
			|| op == OP_IDENTITY_PAYMENT;
}
string identityFromOp(int op) {
	switch (op) {
	case OP_IDENTITY_UPDATE:
		return "identityupdate";
	case OP_IDENTITY_ACTIVATE:
		return "identityactivate";
	case OP_IDENTITY_PAYMENT:
		return "identitypayment";
	default:
		return "<unknown identity op>";
	}
}
int GetDynamicDataOutput(const CTransaction& tx) {
   for(unsigned int i = 0; i<tx.vout.size();i++) {
	   if(IsDynamicDataOutput(tx.vout[i]))
		   return i;
	}
   return -1;
}
bool IsDynamicDataOutput(const CTxOut& out) {
   txnouttype whichType;
	if (!IsStandard(out.scriptPubKey, whichType))
		return false;
	if (whichType == TX_NULL_DATA)
		return true;
   return false;
}
int GetDynamicTxVersion()
{
	return DYNAMIC_TX_VERSION;
}

/**
 * [IsDynamicTxMine check if this transaction is mine or not, must contain a dynamic service vout]
 * @param  tx [dynamic based transaction]
 * @param  type [the type of dynamic service you expect in this transaction]
 * @return    [if dynamic transaction is yours based on type passed in]
 */
bool IsDynamicTxMine(const CTransaction& tx, const string &type) {
	if (tx.nVersion != DYNAMIC_TX_VERSION)
		return false;
	int myNout;
	vector<vector<unsigned char> > vvch;
	if ((type == "identity" || type == "any"))
		myNout = IndexOfIdentityOutput(tx);
	else if ((type == "offer" || type == "any"))
		myNout = IndexOfOfferOutput(tx);
	else if ((type == "cert" || type == "any"))
		myNout = IndexOfCertOutput(tx);
	else if ((type == "message" || type == "any"))
		myNout = IndexOfMessageOutput(tx);
	else if ((type == "escrow" || type == "any"))
		myNout = IndexOfEscrowOutput(tx);
	else
		return false;
	return myNout >= 0;
}
void updateBans(const vector<unsigned char> &banData)
{
	map<string, unsigned char> banIdentityList;
	map<string, unsigned char> banCertList;
	map<string, unsigned char> banOfferList;
	if(getBanList(banData, banIdentityList, banCertList, banOfferList))
	{
		// update identity bans
		for (map<string, unsigned char>::iterator it = banIdentityList.begin(); it != banIdentityList.end(); it++) {
			vector<unsigned char> vchGUID = vchFromString((*it).first);
			unsigned char severity = (*it).second;
			if(pidentitydb->ExistsIdentity(vchGUID))
			{
				vector<CIdentityIndex> vtxIdentityPos;
				if (pidentitydb->ReadIdentity(vchGUID, vtxIdentityPos) && !vtxIdentityPos.empty())
				{
					CIdentityIndex identityBan = vtxIdentityPos.back();
					identityBan.safetyLevel = severity;
					PutToIdentityList(vtxIdentityPos, identityBan);
					pidentitydb->WriteIdentity(identityBan.vchIdentity, vtxIdentityPos);
					
				}		
			}
		}
		// update cert bans
		for (map<string, unsigned char>::iterator it = banCertList.begin(); it != banCertList.end(); it++) {
			vector<unsigned char> vchGUID = vchFromString((*it).first);
			unsigned char severity = (*it).second;
			if(pcertdb->ExistsCert(vchGUID))
			{
				vector<CCert> vtxCertPos;
				if (pcertdb->ReadCert(vchGUID, vtxCertPos) && !vtxCertPos.empty())
				{
					CCert certBan = vtxCertPos.back();
					certBan.safetyLevel = severity;
					PutToCertList(vtxCertPos, certBan);
					pcertdb->WriteCert(vchGUID, vtxCertPos);
					
				}		
			}
		}
		// update offer bans
		for (map<string, unsigned char>::iterator it = banOfferList.begin(); it != banOfferList.end(); it++) {
			vector<unsigned char> vchGUID = vchFromString((*it).first);
			unsigned char severity = (*it).second;
			if(pofferdb->ExistsOffer(vchGUID))
			{
				vector<COffer> vtxOfferPos, myLinkVtxPos;
				if (pofferdb->ReadOffer(vchGUID, vtxOfferPos) && !vtxOfferPos.empty())
				{
					COffer offerBan = vtxOfferPos.back();
					offerBan.safetyLevel = severity;
					offerBan.PutToOfferList(vtxOfferPos);
					pofferdb->WriteOffer(vchGUID, vtxOfferPos);	
				}		
			}
		}
	}
}
bool CheckIdentityInputs(const CTransaction &tx, int op, int nOut, const vector<vector<unsigned char> > &vvchArgs, const CCoinsViewCache &inputs, bool fJustCheck, int nHeight, string &errorMessage, bool dontaddtodb) {
	if (tx.IsCoinBase() && !fJustCheck && !dontaddtodb)
	{
		LogPrintf("*Trying to add identity in coinbase transaction, skipping...");
		return true;
	}
	if (fDebug)
		LogPrintf("*** IDENTITY %d %d op=%s %s nOut=%d %s\n", nHeight, chainActive.Tip()->nHeight, identityFromOp(op).c_str(), tx.GetHash().ToString().c_str(), nOut, fJustCheck ? "JUSTCHECK" : "BLOCK");
	const COutPoint *prevOutput = NULL;
	const CCoins *prevCoins;
	int prevOp = 0;
	vector<vector<unsigned char> > vvchPrevArgs;
	// Make sure identity outputs are not spent by a regular transaction, or the identity would be lost
	if (tx.nVersion != DYNAMIC_TX_VERSION) 
	{
		errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5000 - " + _("Non-Dynamic transaction found");
		return true;
	}
	// unserialize identity from txn, check for valid
	CIdentityIndex theIdentity;
	vector<unsigned char> vchData;
	vector<unsigned char> vchIdentity;
	vector<unsigned char> vchHash;
	int nDataOut;
	if(op != OP_IDENTITY_PAYMENT)
	{
		bool bData = GetDynamicData(tx, vchData, vchHash, nDataOut);
		if(bData && !theIdentity.UnserializeFromData(vchData, vchHash))
		{
			theIdentity.SetNull();
		}
		// we need to check for cert update specially because an identity update without data is sent along with offers linked with the identity
		else if (!bData)
		{
			if(fDebug)
				LogPrintf("CheckIdentityInputs(): Null identity, skipping...\n");	
			return true;
		}
	}
	else
		theIdentity.SetNull();
	if(fJustCheck)
	{
		if(op != OP_IDENTITY_PAYMENT)
		{
			if(vvchArgs.size() != 3)
			{
				errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5001 - " + _("Identity arguments incorrect size");
				return error(errorMessage.c_str());
			}
		}
		else if(vvchArgs.size() != 1)
		{
			errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5002 - " + _("Identity arguments incorrect size");
			return error(errorMessage.c_str());
		}
		if(op != OP_IDENTITY_PAYMENT)
		{
			if(!theIdentity.IsNull())
			{
				if(vvchArgs.size() <= 2 || vchHash != vvchArgs[2])
				{
					errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5003 - " + _("Hash provided doesn't match the calculated hash of the data");
					return true;
				}
			}					
		}
	}
	if(fJustCheck || op == OP_IDENTITY_UPDATE)
	{
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

			if (IsIdentityOp(pop) && vvchArgs[0] == vvch[0]) {
				prevOp = pop;
				vvchPrevArgs = vvch;
				break;
			}
		}
	}
	vector<CIdentityIndex> vtxPos;
	CRecipient fee;
	string retError = "";
	if(fJustCheck)
	{
		if(vvchArgs.empty() || !IsValidIdentityName(vvchArgs[0]))
		{
			errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5004 - " + _("Identity name does not follow the domain name specification");
			return error(errorMessage.c_str());
		}
		if(theIdentity.vchPublicValue.size() > MAX_VALUE_LENGTH && vvchArgs[0] != vchFromString("dynrates.peg") && vvchArgs[0] != vchFromString("dyncategory"))
		{
			errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5005 - " + _("Identity public value too big");
			return error(errorMessage.c_str());
		}
		if(theIdentity.vchPrivateValue.size() > MAX_ENCRYPTED_VALUE_LENGTH)
		{
			errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5006 - " + _("Identity private value too big");
			return error(errorMessage.c_str());
		}
		if(theIdentity.vchIdentityPeg.size() > MAX_GUID_LENGTH)
		{
			errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5007 - " + _("Identity peg too long");
			return error(errorMessage.c_str());
		}
		if(theIdentity.vchPassword.size() > MAX_ENCRYPTED_NAME_LENGTH)
		{
			errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5008 - " + _("Identity password too long");
			return error(errorMessage.c_str());
		}
		if(theIdentity.nHeight > nHeight)
		{
			errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5009 - " + _("Bad identity height");
			return error(errorMessage.c_str());
		}

		switch (op) {
			case OP_IDENTITY_PAYMENT:
				break;
			case OP_IDENTITY_ACTIVATE:
				// Check GUID
				if (vvchArgs.size() <=  1 || theIdentity.vchGUID != vvchArgs[1])
				{
					errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5010 - " + _("Identity input guid mismatch");
					return error(errorMessage.c_str());
				}
				if(theIdentity.vchIdentity != vvchArgs[0])
				{
					errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5011 - " + _("Guid in data output doesn't match guid in tx");
					return error(errorMessage.c_str());
				}
				break;
			case OP_IDENTITY_UPDATE:
				if (!IsIdentityOp(prevOp))
				{
					errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5012 - " + _("Identity input to this transaction not found");
					return error(errorMessage.c_str());
				}
				// Check GUID
				if (vvchArgs.size() <= 1 || vvchPrevArgs.size() <= 1 || vvchPrevArgs[1] != vvchArgs[1])
				{
					errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5013 - " + _("Identity Guid input mismatch");
					return error(errorMessage.c_str());
				}
				// Check name
				if (vvchPrevArgs[0] != vvchArgs[0])
				{
					errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5014 - " + _("Identity input mismatch");
					return error(errorMessage.c_str());
				}
				if(!theIdentity.IsNull())
				{
					if(theIdentity.vchIdentity != vvchArgs[0])
					{
						errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5015 - " + _("Guid in data output doesn't match guid in transaction");
						return error(errorMessage.c_str());
					}
				}
				break;
		default:
				errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5016 - " + _("Identity transaction has unknown op");
				return error(errorMessage.c_str());
		}

	}
	
	if (!fJustCheck ) {
		bool pwChange = false;
		bool isExpired = false;
		CIdentityIndex dbIdentity;
		string strName = stringFromVch(vvchArgs[0]);
		boost::algorithm::to_lower(strName);
		vchIdentity = vchFromString(strName);
		// get the identity from the DB
		if(!GetVtxOfIdentity(vchIdentity, dbIdentity, vtxPos, isExpired))	
		{
			if(op == OP_IDENTITY_ACTIVATE)
			{
				if(!isExpired && !vtxPos.empty())
				{
					errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5017 - " + _("Trying to renew an identity that isn't expired");
					return true;
				}
			}
			else if(op == OP_IDENTITY_UPDATE)
			{
				errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5018 - " + _("Failed to read from identity DB");
				return true;
			}
			else if(op == OP_IDENTITY_PAYMENT && vtxPos.empty())
				return true;
		}
		if(!vchData.empty())
		{
			CAmount fee = GetDataFee(tx.vout[nDataOut].scriptPubKey,  (op == OP_IDENTITY_ACTIVATE)? theIdentity.vchIdentityPeg:dbIdentity.vchIdentityPeg, nHeight);	
			// if this is an identity update get expire time and figure out if identity update pays enough fees for updating expiry
			if(!theIdentity.IsNull())
			{
				int nHeightTmp = nHeight;
				if(nHeightTmp > chainActive.Height())
					nHeightTmp = chainActive.Height();
				uint64_t nTimeExpiry = theIdentity.nExpireTime - chainActive[nHeightTmp]->nTime;
				float fYears = nTimeExpiry / ONE_YEAR_IN_SECONDS;
				if(fYears < 1)
					fYears = 1;
				fee *= powf(2.88,fYears);

				// ensure identities are good for atleast an hour
				if(nTimeExpiry < 3600)
					theIdentity.nExpireTime = chainActive[nHeightTmp]->nTime+3600;
			}
			if ((fee-10000) > tx.vout[nDataOut].nValue) 
			{
				errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5019 - " + _("Transaction does not pay enough fees");
				return true;
			}
		}
				
		if(op == OP_IDENTITY_UPDATE)
		{
			if(!vtxPos.empty())
			{
				CTxDestination identityDest;
				if (vvchPrevArgs.size() <= 0 || vvchPrevArgs[0] != vvchArgs[0] || !prevCoins || prevOutput->n >= prevCoins->vout.size() || !ExtractDestination(prevCoins->vout[prevOutput->n].scriptPubKey, identityDest))
				{
					errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5020 - " + _("Cannot extract destination of identity input");
					theIdentity = dbIdentity;
				}
				else
				{
					const CIdentityIndex& destIdentity = vtxPos.back();
					CDynamicAddress prevaddy(identityDest);	
					CDynamicAddress destaddy;
					GetAddress(destIdentity, &destaddy);
					if(destaddy.ToString() != prevaddy.ToString())
					{
						errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5021 - " + _("You are not the owner of this identity");
						theIdentity = dbIdentity;
					}
				}
				if(dbIdentity.vchGUID != vvchArgs[1])
				{
					errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5022 - " + _("Cannot edit this identity, guid mismatch");
					theIdentity = dbIdentity;
				}
				if(theIdentity.IsNull())
					theIdentity = vtxPos.back();
				else
				{
					if(theIdentity.vchPublicValue.empty())
						theIdentity.vchPublicValue = dbIdentity.vchPublicValue;	
					if(theIdentity.vchPrivateValue.empty())
						theIdentity.vchPrivateValue = dbIdentity.vchPrivateValue;	
					if(theIdentity.vchEncryptionPrivateKey.empty())
						theIdentity.vchEncryptionPrivateKey = dbIdentity.vchEncryptionPrivateKey;
					if(theIdentity.vchEncryptionPublicKey.empty())
						theIdentity.vchEncryptionPublicKey = dbIdentity.vchEncryptionPublicKey;
					if(theIdentity.vchPassword.empty())
						theIdentity.vchPassword = dbIdentity.vchPassword;
					else
						pwChange = true;
					// user can't update safety level or rating after creation
					theIdentity.safetyLevel = dbIdentity.safetyLevel;
					theIdentity.nRatingAsBuyer = dbIdentity.nRatingAsBuyer;
					theIdentity.nRatingCountAsBuyer = dbIdentity.nRatingCountAsBuyer;
					theIdentity.nRatingAsSeller = dbIdentity.nRatingAsSeller;
					theIdentity.nRatingCountAsSeller = dbIdentity.nRatingCountAsSeller;
					theIdentity.nRatingAsArbiter = dbIdentity.nRatingAsArbiter;
					theIdentity.nRatingCountAsArbiter= dbIdentity.nRatingCountAsArbiter;
					theIdentity.vchGUID = dbIdentity.vchGUID;
					theIdentity.vchIdentity = dbIdentity.vchIdentity;
					if(!theIdentity.multiSigInfo.IsNull())
					{
						if(theIdentity.multiSigInfo.vchIdentityes.size() > 3 || theIdentity.multiSigInfo.nRequiredSigs > 3)
						{
							errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5023 - " + _("Identity multisig too big, reduce the number of signatures required for this identity and try again");
							theIdentity.multiSigInfo.SetNull();
						}
						std::vector<CPubKey> pubkeys; 
						CPubKey pubkey(theIdentity.vchPubKey);
						pubkeys.push_back(pubkey);
						for(int i =0;i<theIdentity.multiSigInfo.vchIdentityes.size();i++)
						{
							CIdentityIndex multiSigIdentity;
							CTransaction txMultiSigIdentity;
							if (!GetTxOfIdentity(vchFromString(theIdentity.multiSigInfo.vchIdentityes[i]), multiSigIdentity, txMultiSigIdentity))
								continue;
							CPubKey pubkey(multiSigIdentity.vchPubKey);
							pubkeys.push_back(pubkey);

						}	
						if(theIdentity.multiSigInfo.nRequiredSigs > pubkeys.size())
						{
							errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5024 - " + _("Cannot update multisig identity because required signatures is greator than the amount of signatures provided");
							theIdentity.multiSigInfo.SetNull();
						}	
						CScript inner = GetScriptForMultisig(theIdentity.multiSigInfo.nRequiredSigs, pubkeys);
						CScript redeemScript(theIdentity.multiSigInfo.vchRedeemScript.begin(), theIdentity.multiSigInfo.vchRedeemScript.end());
						if(redeemScript != inner)
						{
							errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5025 - " + _("Invalid redeem script provided in transaction");
							theIdentity.multiSigInfo.SetNull();
						}
					}
					// if transfer or change pw
					if(dbIdentity.vchPubKey != theIdentity.vchPubKey)
					{
						// if transfer clear pw
						if(!pwChange)
							theIdentity.vchPassword.clear();
						CDynamicAddress myAddress;
						GetAddress(theIdentity, &myAddress);
						const vector<unsigned char> &vchAddress = vchFromString(myAddress.ToString());
						// make sure xfer to pubkey doesn't point to an identity already, otherwise don't assign pubkey to identity
						// we want to avoid identities with duplicate public keys (addresses)
						if (pidentitydb->ExistsAddress(vchAddress))
						{
							vector<unsigned char> vchMyIdentity;
							if (pidentitydb->ReadAddress(vchAddress, vchMyIdentity) && !vchMyIdentity.empty() && vchMyIdentity != dbIdentity.vchIdentity)
							{
								errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5026 - " + _("An identity already exists with that address, try another public key");
								theIdentity = dbIdentity;
							}
						}					
					}
				}
			}
			else
			{
				errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5027 -" + _("Identity not found when trying to update");
				return true;
			}
		}
		else if(op == OP_IDENTITY_ACTIVATE)
		{
			if(!isExpired && !vtxPos.empty())
			{
				errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5028 - " + _("Trying to renew an identity that isn't expired");
				return true;
			}
			theIdentity.nRatingAsBuyer = 0;
			theIdentity.nRatingCountAsBuyer = 0;
			theIdentity.nRatingAsSeller = 0;
			theIdentity.nRatingCountAsSeller = 0;
			theIdentity.nRatingAsArbiter = 0;
			theIdentity.nRatingCountAsArbiter = 0;
			if(theIdentity.multiSigInfo.vchIdentityes.size() > 0)
			{
				if(theIdentity.multiSigInfo.vchIdentityes.size() > 5 || theIdentity.multiSigInfo.nRequiredSigs > 5)
				{
					theIdentity.multiSigInfo.SetNull();
					errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5029 - " + _("Identity multisig too big, reduce the number of signatures required for this identity and try again");
				}
				std::vector<CPubKey> pubkeys; 
				CPubKey pubkey(theIdentity.vchPubKey);
				pubkeys.push_back(pubkey);
				for(int i =0;i<theIdentity.multiSigInfo.vchIdentityes.size();i++)
				{
					CIdentityIndex multiSigIdentity;
					CTransaction txMultiSigIdentity;
					if (!GetTxOfIdentity(vchFromString(theIdentity.multiSigInfo.vchIdentityes[i]), multiSigIdentity, txMultiSigIdentity))
						continue;

					CPubKey pubkey(multiSigIdentity.vchPubKey);
					pubkeys.push_back(pubkey);

				}
				if(theIdentity.multiSigInfo.nRequiredSigs > pubkeys.size())
				{
					theIdentity.multiSigInfo.SetNull();
					errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5030 - " + _("Cannot update multisig identity because required signatures is greator than the amount of signatures provided");
				}
				CScript inner = GetScriptForMultisig(theIdentity.multiSigInfo.nRequiredSigs, pubkeys);
				CScript redeemScript(theIdentity.multiSigInfo.vchRedeemScript.begin(), theIdentity.multiSigInfo.vchRedeemScript.end());
				if(redeemScript != inner)
				{
					theIdentity.multiSigInfo.SetNull();
					errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5031 - " + _("Invalid redeem script provided in transaction");
				}
			}
		}
		else if(op == OP_IDENTITY_PAYMENT)
		{
			const uint256 &txHash = tx.GetHash();
			vector<CIdentityPayment> vtxPaymentPos;
			if(pidentitydb->ExistsIdentityPayment(vchIdentity))
			{
				if(!pidentitydb->ReadIdentityPayment(vchIdentity, vtxPaymentPos))
				{
					errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5032 - " + _("Cannot read payments from identity DB");
					return true;
				}
			}
			CIdentityPayment payment;
			payment.txHash = txHash;
			payment.nOut = nOut;
			vtxPaymentPos.push_back(payment);
			if (!dontaddtodb && !pidentitydb->WriteIdentityPayment(vchIdentity, vtxPaymentPos))
			{
				errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5034 - " + _("Failed to write payment to identity DB");
				return error(errorMessage.c_str());
			}
			if(fDebug)
				LogPrintf(
					"CONNECTED IDENTITY: name=%s  op=%s  hash=%s  height=%d\n",
					stringFromVch(vchIdentity).c_str(),
					identityFromOp(op).c_str(),
					tx.GetHash().ToString().c_str(), nHeight);
			return true;
		}
		theIdentity.nHeight = nHeight;
		theIdentity.txHash = tx.GetHash();
		PutToIdentityList(vtxPos, theIdentity);
		CDynamicAddress address;
		GetAddress(theIdentity, &address);
		CIdentityUnprunable identityUnprunable;
		identityUnprunable.vchGUID = theIdentity.vchGUID;
		identityUnprunable.nExpireTime = theIdentity.nExpireTime;
		if (!dontaddtodb && !pidentitydb->WriteIdentity(vchIdentity, identityUnprunable, vchFromString(address.ToString()), vtxPos))
		{
			errorMessage = "DYNAMIC_IDENTITY_CONSENSUS_ERROR: ERRCODE: 5034 - " + _("Failed to write to identity DB");
			return error(errorMessage.c_str());
		}

		if(!dontaddtodb && vchIdentity == vchFromString("dynban"))
		{
			updateBans(theIdentity.vchPublicValue);
		}		
		if(fDebug)
			LogPrintf(
				"CONNECTED IDENTITY: name=%s  op=%s  hash=%s  height=%d\n",
				stringFromVch(vchIdentity).c_str(),
				identityFromOp(op).c_str(),
				tx.GetHash().ToString().c_str(), nHeight);
	}

	return true;
}

string stringFromValue(const UniValue& value) {
	string strName = value.get_str();
	return strName;
}

vector<unsigned char> vchFromValue(const UniValue& value) {
	string strName = value.get_str();
	unsigned char *strbeg = (unsigned char*) strName.c_str();
	return vector<unsigned char>(strbeg, strbeg + strName.size());
}

std::vector<unsigned char> vchFromString(const std::string &str) {
	unsigned char *strbeg = (unsigned char*) str.c_str();
	return vector<unsigned char>(strbeg, strbeg + str.size());
}

string stringFromVch(const vector<unsigned char> &vch) {
	string res;
	vector<unsigned char>::const_iterator vi = vch.begin();
	while (vi != vch.end()) {
		res += (char) (*vi);
		vi++;
	}
	return res;
}
bool GetDynamicData(const CTransaction &tx, vector<unsigned char> &vchData, vector<unsigned char> &vchHash, int& nOut)
{
	nOut = GetDynamicDataOutput(tx);
    if(nOut == -1)
	   return false;

	const CScript &scriptPubKey = tx.vout[nOut].scriptPubKey;
	return GetDynamicData(scriptPubKey, vchData, vchHash);
}
bool IsValidIdentityName(const std::vector<unsigned char> &vchIdentity)
{
	return (vchIdentity.size() <= MAX_GUID_LENGTH && vchIdentity.size() >= 3);
}
bool GetDynamicData(const CScript &scriptPubKey, vector<unsigned char> &vchData, vector<unsigned char> &vchHash)
{
	CScript::const_iterator pc = scriptPubKey.begin();
	opcodetype opcode;
	if (!scriptPubKey.GetOp(pc, opcode))
		return false;
	if(opcode != OP_RETURN)
		return false;
	if (!scriptPubKey.GetOp(pc, opcode, vchData))
		return false;
	if (!scriptPubKey.GetOp(pc, opcode, vchHash))
		return false;
	return true;
}
void GetAddress(const CIdentityIndex& identity, CDynamicAddress* address,const uint32_t nPaymentOption)
{
	if(!address)
		return;
	CPubKey identityPubKey(identity.vchPubKey);
	CChainParams::AddressType myAddressType = PaymentOptionToAddressType(nPaymentOption);
	address[0] = CDynamicAddress(identityPubKey.GetID(), myAddressType);
	if(identity.multiSigInfo.vchIdentityes.size() > 0)
	{
		CScript inner(identity.multiSigInfo.vchRedeemScript.begin(), identity.multiSigInfo.vchRedeemScript.end());
		CScriptID innerID(inner);
		address[0] = CDynamicAddress(innerID, myAddressType);
	}
}
void GetAddress(const CIdentityIndex& identity, CDynamicAddress* address,CScript& script,const uint32_t nPaymentOption)
{
	if(!address)
		return;
	CPubKey identityPubKey(identity.vchPubKey);
	CChainParams::AddressType myAddressType = PaymentOptionToAddressType(nPaymentOption);
	address[0] = CDynamicAddress(identityPubKey.GetID(), myAddressType);
	script = GetScriptForDestination(address[0].Get());
	if(identity.multiSigInfo.vchIdentityes.size() > 0)
	{
		script = CScript(identity.multiSigInfo.vchRedeemScript.begin(), identity.multiSigInfo.vchRedeemScript.end());
		CScriptID innerID(script);
		address[0] = CDynamicAddress(innerID, myAddressType);
	}
}
bool CIdentityIndex::UnserializeFromData(const vector<unsigned char> &vchData, const vector<unsigned char> &vchHash) {
    try {
        CDataStream dsIdentity(vchData, SER_NETWORK, PROTOCOL_VERSION);
        dsIdentity >> *this;

		vector<unsigned char> vchIdentityData;
		Serialize(vchIdentityData);
		const uint256 &calculatedHash = Hash(vchIdentityData.begin(), vchIdentityData.end());
		const vector<unsigned char> &vchRandIdentity = vchFromValue(calculatedHash.GetHex());
		if(vchRandIdentity != vchHash)
		{
			SetNull();
			return false;
		}
    } catch (std::exception &e) {
		SetNull();
        return false;
    }
	return true;
}
bool CIdentityIndex::UnserializeFromTx(const CTransaction &tx) {
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
void CIdentityIndex::Serialize(vector<unsigned char>& vchData) {
    CDataStream dsIdentity(SER_NETWORK, PROTOCOL_VERSION);
    dsIdentity << *this;
    vchData = vector<unsigned char>(dsIdentity.begin(), dsIdentity.end());

}
bool CIdentityDB::ScanNames(const std::vector<unsigned char>& vchIdentity, const string& strRegexp, bool safeSearch, 
		unsigned int nMax,
		vector<CIdentityIndex>& nameScan) {
	// regexp
	using namespace boost::xpressive;
	smatch nameparts;
	string strRegexpLower = strRegexp;
	boost::algorithm::to_lower(strRegexpLower);
	sregex cregex = sregex::compile(strRegexpLower);
	boost::scoped_ptr<CDBIterator> pcursor(NewIterator());
	if(!vchIdentity.empty())
		pcursor->Seek(make_pair(string("namei"), vchIdentity));
	else
		pcursor->SeekToFirst();
	vector<CIdentityIndex> vtxPos;
	pair<string, vector<unsigned char> > key;
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        try {
			if (pcursor->GetKey(key) && key.first == "namei") {
            	const vector<unsigned char> &vchMyIdentity = key.second;
				
                
				pcursor->GetValue(vtxPos);
				
				if (vtxPos.empty()){
					pcursor->Next();
					continue;
				}
				const CIdentityIndex &txPos = vtxPos.back();
  				if (chainActive.Tip()->nTime >= txPos.nExpireTime)
				{
					pcursor->Next();
					continue;
				} 
				if(txPos.safetyLevel >= SAFETY_LEVEL1)
				{
					if(safeSearch)
					{
						pcursor->Next();
						continue;
					}
					if(txPos.safetyLevel > SAFETY_LEVEL1)
					{
						pcursor->Next();
						continue;
					}
				}
				if(!txPos.safeSearch && safeSearch)
				{
					pcursor->Next();
					continue;
				}
				const string &name = stringFromVch(vchMyIdentity);
				if (strRegexp != "" && !regex_search(name, nameparts, cregex) && strRegexp != name)
				{
					pcursor->Next();
					continue;
				}
                nameScan.push_back(txPos);
            }
            if (nameScan.size() >= nMax)
                break;

            pcursor->Next();
        } catch (std::exception &e) {
            return error("%s() : deserialize error", __PRETTY_FUNCTION__);
        }
    }
    return true;
}

// TODO: need to cleanout CTxOuts (transactions stored on disk) which have data stored in them after expiry, erase at same time on startup so pruning can happen properly
bool CIdentityDB::CleanupDatabase(int &servicesCleaned)
{
	boost::scoped_ptr<CDBIterator> pcursor(NewIterator());
	pcursor->SeekToFirst();
	vector<CIdentityIndex> vtxPos;
	pair<string, vector<unsigned char> > key;
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        try {
			if (pcursor->GetKey(key) && key.first == "namei") {
            	const vector<unsigned char> &vchMyIdentity = key.second;  
				if(vchMyIdentity == vchFromString("dynrates.peg") || vchMyIdentity == vchFromString("dynban") || vchMyIdentity == vchFromString("dyncategory"))
				{
					pcursor->Next();
					continue;
				}
				pcursor->GetValue(vtxPos);	
				if (vtxPos.empty()){
					servicesCleaned++;
					EraseIdentity(vchMyIdentity);
					pcursor->Next();
					continue;
				}
				const CIdentityIndex &txPos = vtxPos.back();
  				if (chainActive.Tip()->nTime >= txPos.nExpireTime)
				{
					servicesCleaned++;
					EraseIdentity(vchMyIdentity);
				} 
				
            }
            pcursor->Next();
        } catch (std::exception &e) {
            return error("%s() : deserialize error", __PRETTY_FUNCTION__);
        }
    }
	return true;
}
void CleanupDynamicServiceDatabases(int &numServicesCleaned)
{
	if(pofferdb != NULL)
		pofferdb->CleanupDatabase(numServicesCleaned);
	if(pescrowdb!= NULL)
		pescrowdb->CleanupDatabase(numServicesCleaned);
	if(pmessagedb!= NULL)
		pmessagedb->CleanupDatabase(numServicesCleaned);
	if(pcertdb!= NULL)
		pcertdb->CleanupDatabase(numServicesCleaned);
	if(pidentitydb!= NULL)
		pidentitydb->CleanupDatabase(numServicesCleaned);
	if(pidentitydb != NULL)
	{
		if (!pidentitydb->Flush())
			LogPrintf("Failed to write to identity database!");
		delete pidentitydb;
		pidentitydb = NULL;
	}
	if(pofferdb != NULL)
	{
		if (!pofferdb->Flush())
			LogPrintf("Failed to write to offer database!");
		delete pofferdb;
		pofferdb = NULL;
	}
	if(pcertdb != NULL)
	{
		if (!pcertdb->Flush())
			LogPrintf("Failed to write to cert database!");
		delete pcertdb;
		pcertdb = NULL;
	}
	if(pescrowdb != NULL)
	{
		if (!pescrowdb->Flush())
			LogPrintf("Failed to write to escrow database!");
		delete pescrowdb;
		pescrowdb = NULL;
	}
	if(pmessagedb != NULL)
	{
		if (!pmessagedb->Flush())
			LogPrintf("Failed to write to message database!");
		delete pmessagedb;
		pmessagedb = NULL;
	}

}
bool GetTxOfIdentity(const vector<unsigned char> &vchIdentity, 
				  CIdentityIndex& txPos, CTransaction& tx, bool skipExpiresCheck) {
	vector<CIdentityIndex> vtxPos;
	if (!pidentitydb->ReadIdentity(vchIdentity, vtxPos) || vtxPos.empty())
		return false;
	txPos = vtxPos.back();
	int nHeight = txPos.nHeight;
	if(vchIdentity != vchFromString("dynrates.peg") && vchIdentity != vchFromString("dynban") && vchIdentity != vchFromString("dyncategory"))
	{
		if (!skipExpiresCheck && chainActive.Tip()->nTime >= txPos.nExpireTime) {
			string name = stringFromVch(vchIdentity);
			LogPrintf("GetTxOfIdentity(%s) : expired", name.c_str());
			return false;
		}
	}

	if (!GetDynamicTransaction(nHeight, txPos.txHash, tx, Params().GetConsensus()))
		return error("GetTxOfIdentity() : could not read tx from disk");

	return true;
}
bool GetTxAndVtxOfIdentity(const vector<unsigned char> &vchIdentity, 
						CIdentityIndex& txPos, CTransaction& tx, std::vector<CIdentityIndex> &vtxPos, bool &isExpired, bool skipExpiresCheck) {
	isExpired = false;
	if (!pidentitydb->ReadIdentity(vchIdentity, vtxPos) || vtxPos.empty())
		return false;
	txPos = vtxPos.back();
	int nHeight = txPos.nHeight;
	if(vchIdentity != vchFromString("dynrates.peg") && vchIdentity != vchFromString("dynban") && vchIdentity != vchFromString("dyncategory"))
	{
		if (!skipExpiresCheck && chainActive.Tip()->nTime >= txPos.nExpireTime) {
			string name = stringFromVch(vchIdentity);
			LogPrintf("GetTxOfIdentity(%s) : expired", name.c_str());
			isExpired = true;
			return false;
		}
	}

	if (!GetDynamicTransaction(nHeight, txPos.txHash, tx, Params().GetConsensus()))
		return error("GetTxOfIdentity() : could not read tx from disk");
	return true;
}
bool GetVtxOfIdentity(const vector<unsigned char> &vchIdentity, 
						CIdentityIndex& txPos, std::vector<CIdentityIndex> &vtxPos, bool &isExpired, bool skipExpiresCheck) {
	isExpired = false;
	if (!pidentitydb->ReadIdentity(vchIdentity, vtxPos) || vtxPos.empty())
		return false;
	txPos = vtxPos.back();
	int nHeight = txPos.nHeight;
	if(vchIdentity != vchFromString("dynrates.peg") && vchIdentity != vchFromString("dynban") && vchIdentity != vchFromString("dyncategory"))
	{
		if (!skipExpiresCheck && chainActive.Tip()->nTime >= txPos.nExpireTime) {
			string name = stringFromVch(vchIdentity);
			LogPrintf("GetTxOfIdentity(%s) : expired", name.c_str());
			isExpired = true;
			return false;
		}
	}
	return true;
}
bool GetAddressFromIdentity(const std::string& strIdentity, std::string& strAddress, unsigned char& safetyLevel, bool& safeSearch, std::vector<unsigned char> &vchRedeemScript, std::vector<unsigned char> &vchPubKey) {

	string strLowerIdentity = strIdentity;
	boost::algorithm::to_lower(strLowerIdentity);
	const vector<unsigned char> &vchIdentity = vchFromValue(strLowerIdentity);
	if (!pidentitydb || !pidentitydb->ExistsIdentity(vchIdentity))
		return false;

	// check for identity existence in DB
	vector<CIdentityIndex> vtxPos;
	if (!pidentitydb->ReadIdentity(vchIdentity, vtxPos))
		return false;
	if (vtxPos.size() < 1)
		return false;

	const CIdentityIndex &identity = vtxPos.back();
	CDynamicAddress address;
	GetAddress(identity, &address);
	strAddress = address.ToString();
	safetyLevel = identity.safetyLevel;
	safeSearch = identity.safeSearch;
	vchRedeemScript = identity.multiSigInfo.vchRedeemScript;
	vchPubKey = identity.vchPubKey;
	return true;
}

bool GetIdentityFromAddress(const std::string& strAddress, std::string& strIdentity, unsigned char& safetyLevel, bool& safeSearch,  std::vector<unsigned char> &vchRedeemScript, std::vector<unsigned char> &vchPubKey) {

	const vector<unsigned char> &vchAddress = vchFromValue(strAddress);
	if (!pidentitydb || !pidentitydb->ExistsAddress(vchAddress))
		return false;

	// check for identity address mapping existence in DB
	vector<unsigned char> vchIdentity;
	if (!pidentitydb->ReadAddress(vchAddress, vchIdentity))
		return false;
	if (vchIdentity.empty())
		return false;
	
	strIdentity = stringFromVch(vchIdentity);
	vector<CIdentityIndex> vtxPos;
	if (pidentitydb && !pidentitydb->ReadIdentity(vchIdentity, vtxPos))
		return false;
	if (vtxPos.size() < 1)
		return false;
	const CIdentityIndex &identity = vtxPos.back();
	safetyLevel = identity.safetyLevel;
	safeSearch = identity.safeSearch;
	vchRedeemScript = identity.multiSigInfo.vchRedeemScript;
	vchPubKey = identity.vchPubKey;
	return true;
}
int IndexOfIdentityOutput(const CTransaction& tx) {
	vector<vector<unsigned char> > vvch;
	if (tx.nVersion != DYNAMIC_TX_VERSION)
		return -1;
	int op;
	for (unsigned int i = 0; i < tx.vout.size(); i++) {
		const CTxOut& out = tx.vout[i];
		// find an output you own
		if (pwalletMain->IsMine(out) && DecodeIdentityScript(out.scriptPubKey, op, vvch) && op != OP_IDENTITY_PAYMENT) {
			return i;
		}
	}
	return -1;
}

bool GetIdentityOfTx(const CTransaction& tx, vector<unsigned char>& name) {
	if (tx.nVersion != DYNAMIC_TX_VERSION)
		return false;
	vector<vector<unsigned char> > vvchArgs;
	int op;
	int nOut;

	bool good = DecodeIdentityTx(tx, op, nOut, vvchArgs, false) || DecodeIdentityTx(tx, op, nOut, vvchArgs, true);
	if (!good)
		return error("GetIdentityOfTx() : could not decode a dynamic tx");

	switch (op) {
	case OP_IDENTITY_ACTIVATE:
	case OP_IDENTITY_UPDATE:
	case OP_IDENTITY_PAYMENT:
		name = vvchArgs[0];
		return true;
	}
	return false;
}
bool DecodeAndParseDynamicTx(const CTransaction& tx, int& op, int& nOut,
		vector<vector<unsigned char> >& vvch)
{
	return DecodeAndParseIdentityTx(tx, op, nOut, vvch) 
		|| DecodeAndParseCertTx(tx, op, nOut, vvch)
		|| DecodeAndParseOfferTx(tx, op, nOut, vvch)
		|| DecodeAndParseEscrowTx(tx, op, nOut, vvch)
		|| DecodeAndParseMessageTx(tx, op, nOut, vvch);
}
bool DecodeAndParseIdentityTx(const CTransaction& tx, int& op, int& nOut,
		vector<vector<unsigned char> >& vvch)
{
	CIdentityIndex identity;
	bool decode = DecodeIdentityTx(tx, op, nOut, vvch, false);
	if(decode)
	{
		bool parse = identity.UnserializeFromTx(tx);
		return decode && parse;
	}
	return DecodeIdentityTx(tx, op, nOut, vvch, true);
}
bool DecodeIdentityTx(const CTransaction& tx, int& op, int& nOut,
		vector<vector<unsigned char> >& vvch, bool payment) {
	bool found = false;


	// Strict check - bug disallowed
	for (unsigned int i = 0; i < tx.vout.size(); i++) {
		const CTxOut& out = tx.vout[i];
		vector<vector<unsigned char> > vvchRead;
		if (DecodeIdentityScript(out.scriptPubKey, op, vvchRead) && ((op == OP_IDENTITY_PAYMENT && payment) || (op != OP_IDENTITY_PAYMENT && !payment))) {
			nOut = i;
			found = true;
			vvch = vvchRead;
			break;
		}
	}
	if (!found)
		vvch.clear();

	return found;
}


bool DecodeIdentityScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch, CScript::const_iterator& pc) {
	opcodetype opcode;
	vvch.clear();
	if (!script.GetOp(pc, opcode))
		return false;
	if (opcode < OP_1 || opcode > OP_16)
		return false;

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
	return found && IsIdentityOp(op);
}
bool DecodeIdentityScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch) {
	CScript::const_iterator pc = script.begin();
	return DecodeIdentityScript(script, op, vvch, pc);
}
bool RemoveIdentityScriptPrefix(const CScript& scriptIn, CScript& scriptOut) {
	int op;
	vector<vector<unsigned char> > vvch;
	CScript::const_iterator pc = scriptIn.begin();

	if (!DecodeIdentityScript(scriptIn, op, vvch, pc))
		return false;
	scriptOut = CScript(pc, scriptIn.end());
	return true;
}
void CreateRecipient(const CScript& scriptPubKey, CRecipient& recipient)
{
	CRecipient recp = {scriptPubKey, recipient.nAmount, false};
	recipient = recp;
	CTxOut txout(recipient.nAmount,	recipient.scriptPubKey);
    size_t nSize = txout.GetSerializeSize(SER_DISK,0)+148u;
	CAmount fee = 3*minRelayTxFee.GetFee(nSize);
	recipient.nAmount = fee;
}
void CreateFeeRecipient(CScript& scriptPubKey, const vector<unsigned char>& vchIdentityPeg, const uint64_t& nHeight, const vector<unsigned char>& data, CRecipient& recipient)
{
	int precision = 0;
	CAmount nFee = 0;
	// add hash to data output (must match hash in inputs check with the tx scriptpubkey hash)
    uint256 hash = Hash(data.begin(), data.end());
    vector<unsigned char> vchHashRand = vchFromValue(hash.GetHex());
	scriptPubKey << vchHashRand;
	CRecipient recp = {scriptPubKey, 0, false};
	recipient = recp;
	CTxOut txout(0,	recipient.scriptPubKey);
	size_t nSize = txout.GetSerializeSize(SER_DISK,0)+148u;
	int nFeePerByte = getFeePerByte(vchIdentityPeg, vchFromString("DYN"), nHeight, precision);
	if(nFeePerByte <= 0)
		nFee = 3*minRelayTxFee.GetFee(nSize);
	else
		nFee = nFeePerByte * nSize;

	recipient.nAmount = nFee;
}
CAmount GetDataFee(const CScript& scriptPubKey, const vector<unsigned char>& vchIdentityPeg, const uint64_t& nHeight)
{
	int precision = 0;
	CAmount nFee = 0;
	CRecipient recipient;
	CRecipient recp = {scriptPubKey, 0, false};
	recipient = recp;
	CTxOut txout(0,	recipient.scriptPubKey);
    size_t nSize = txout.GetSerializeSize(SER_DISK,0)+148u;
	int nFeePerByte = getFeePerByte(vchIdentityPeg, vchFromString("DYN"), nHeight, precision);
	if(nFeePerByte <= 0)
		nFee = 3*minRelayTxFee.GetFee(nSize);
	else
		nFee = nFeePerByte * nSize;
	
	recipient.nAmount = nFee;
	return recipient.nAmount;
}
UniValue identityauthenticate(const UniValue& params, bool fHelp) {
	if (fHelp || 2 != params.size())
		throw runtime_error("identityauthenticate <identity> <password>\n"
		"Authenticates an identity with a provided password and returns the private key if successful. Warning: Calling this function over a public network can lead to someone reading your password/private key in plain text.\n");
	vector<unsigned char> vchIdentity = vchFromString(params[0].get_str());
	const SecureString &strPassword = params[1].get_str().c_str();
	
	CTransaction tx;
	CIdentityIndex theIdentity;
	if (!GetTxOfIdentity(vchIdentity, theIdentity, tx, true))
		throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5500 - " + _("Could not find an identity with this name"));

	CPubKey identityPubKey(theIdentity.vchPubKey);
	CCrypter crypt;
	uint256 hashIdentityNum = Hash(vchIdentity.begin(), vchIdentity.end());
	vector<unsigned char> vchIdentityHash = vchFromString(hashIdentityNum.GetHex());
	vchIdentityHash.resize(WALLET_CRYPTO_SALT_SIZE);
	if(strPassword.empty())
		throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5501 - " + _("Password cannot be empty"));

    if(!crypt.SetKeyFromPassphrase(strPassword, vchIdentityHash, 25000, 0))
		throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5502 - " + _("Could not determine key from password"));

	CKey key;
	key.Set(crypt.chKey, crypt.chKey + (sizeof crypt.chKey), true);
	CPubKey defaultKey = key.GetPubKey();
	if(!defaultKey.IsFullyValid())
		throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5503 - " + _("Generated public key not fully valid"));

	if(identityPubKey != defaultKey)
		throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5504 - " + _("Password is incorrect"));
	UniValue res(UniValue::VOBJ);
	res.push_back(Pair("privatekey", CDynamicSecret(key).ToString()));
	return res;

}
void TransferIdentityBalances(const vector<unsigned char> &vchIdentity, const CScript& scriptPubKeyTo, vector<CRecipient> &vecSend, CCoinControl& coinControl){

	LOCK(cs_main);
	CAmount nAmount = 0;
	std::vector<CIdentityPayment> vtxPaymentPos;
	if(!pidentitydb->ReadIdentityPayment(vchIdentity, vtxPaymentPos))
		return;
	
	CIdentityIndex theIdentity;
	CTransaction identityTx;
	if (!GetTxOfIdentity(vchIdentity, theIdentity, identityTx, true))
		return;

	CDynamicAddress addressFrom;
	GetAddress(theIdentity, &addressFrom);

	CCoinsViewCache view(pcoinsTip);
	const CCoins *coins;
	CTxDestination payDest;
	CDynamicAddress destaddy;
	// get all identity inputs and transfer them to the new identity destination
    for (unsigned int i = 0;i<vtxPaymentPos.size();i++)
    {
		const CIdentityPayment& identityPayment = vtxPaymentPos[i];
		coins = view.AccessCoins(identityPayment.txHash);
		if(coins == NULL)
			continue;
     
		if(!coins->IsAvailable(identityPayment.nOut))
			continue;
		if (!ExtractDestination(coins->vout[identityPayment.nOut].scriptPubKey, payDest)) 
			continue;
		destaddy = CDynamicAddress(payDest);
        if (destaddy.ToString() == addressFrom.ToString())
		{  
			nAmount += coins->vout[identityPayment.nOut].nValue;
			COutPoint outpt(identityPayment.txHash, identityPayment.nOut);
			coinControl.Select(outpt);
		}	
		
    }
	if(nAmount > 0)
	{
		CAmount nFee = 0;
		for(unsigned int i=0;i<vecSend.size();i++)
			nFee += vecSend[i].nAmount;

		CScript scriptChangeOrig;
		scriptChangeOrig << CScript::EncodeOP_N(OP_IDENTITY_PAYMENT) << vchIdentity << OP_2DROP;
		scriptChangeOrig += scriptPubKeyTo;
		
		CRecipient recipient  = {scriptChangeOrig, nAmount-(nFee*2), false};
		vecSend.push_back(recipient);
	}
}
UniValue identitynew(const UniValue& params, bool fHelp) {
	if (fHelp || 4 > params.size() || 10 < params.size())
		throw runtime_error(
		"identitynew <identitypeg> <identityname> <password> <public value> [private value] [safe search=Yes] [accept transfers=Yes] [expire=31536000] [nrequired=0] [\"identity\",...]\n"
						"<identityname> identity name.\n"
						"<password> used to generate your public/private key that controls this identity. Warning: Calling this function over a public network can lead to someone reading your password in plain text.\n"
						"<public value> identity public profile data, 1024 chars max.\n"
						"<private value> identity private profile data, 1024 chars max. Will be private and readable by owner only.\n"
						"<safe search> set to No if this identity should only show in the search when safe search is not selected. Defaults to Yes (identity shows with or without safe search selected in search lists).\n"	
						"<accept transfers> set to No if this identity should not allow a certificate to be transferred to it. Defaults to Yes.\n"	
						"<expire> String. Time in seconds. Future time when to expire identity. It is exponentially more expensive per year, calculation is FEERATE*(1.5^years). FEERATE is the dynamic satoshi per byte fee set in the rate peg identity used for this identity. Defaults to 1 year.\n"	
						"<nrequired> For multisig identities only. The number of required signatures out of the n identities for a multisig identity update.\n"
						"<identities>     For multisig identities only. A json array of identities which are used to sign on an update to this identity.\n"
						"     [\n"
						"       \"identity\"    Existing dynamic identity name\n"
						"       ,...\n"
						"     ]\n"						
						
						+ HelpRequiringPassphrase());
	vector<unsigned char> vchIdentityPeg = vchFromString(params[0].get_str());
	if(vchIdentityPeg.empty())
		vchIdentityPeg = vchFromString("dynrates.peg");
	vector<unsigned char> vchIdentity = vchFromString(params[1].get_str());
	string strName = stringFromVch(vchIdentity);
	/*Above pattern makes sure domain name matches the following criteria :

	The domain name should be a-z | 0-9 and hyphen(-)
	The domain name should between 3 and 63 characters long
	Last Tld can be 2 to a maximum of 6 characters
	The domain name should not start or end with hyphen (-) (e.g. -dynamic.org or dynamic-.org)
	The domain name can be a subdomain (e.g. dyn.blogspot.com)*/

	
	using namespace boost::xpressive;
	using namespace boost::algorithm;
	to_lower(strName);
	smatch nameparts;
	sregex domainwithtldregex = sregex::compile("^((?!-)[a-z0-9-]{3,64}(?<!-)\\.)+[a-z]{2,6}$");
	sregex domainwithouttldregex = sregex::compile("^((?!-)[a-z0-9-]{3,64}(?<!-))");

	if(find_first(strName, "."))
	{
		if (!regex_search(strName, nameparts, domainwithtldregex) || string(nameparts[0]) != strName)
			throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5505 - " + _("Invalid Dynamic Identity. Must follow the domain name spec of 3 to 64 characters with no preceding or trailing dashes and a TLD of 2 to 6 characters"));	
	}
	else
	{
		if (!regex_search(strName, nameparts, domainwithouttldregex)  || string(nameparts[0]) != strName)
			throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5506 - " + _("Invalid Dynamic Identity. Must follow the domain name spec of 3 to 64 characters with no preceding or trailing dashes"));
	}
	


	vchIdentity = vchFromString(strName);

	vector<unsigned char> vchPublicValue;
	vector<unsigned char> vchPrivateValue;
	string strPassword = params[2].get_str().c_str();
	if(strPassword.size() < 4 && strPassword.size() > 0)
		throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5507 - " + _("Invalid Dynamic Identity. Please enter a password atleast 4 characters long"));
	string strPublicValue = params[3].get_str();
	vchPublicValue = vchFromString(strPublicValue);

	string strPrivateValue = params.size()>=5?params[4].get_str():"";
	string strSafeSearch = "Yes";
	string strAcceptCertTransfers = "Yes";

	if(params.size() >= 6)
	{
		strSafeSearch = params[5].get_str();
	}
	if(params.size() >= 7)
	{
		strAcceptCertTransfers = params[6].get_str();
	}
	uint64_t nTime = chainActive.Tip()->nTime+ONE_YEAR_IN_SECONDS;
	if(params.size() >= 8)
		nTime = boost::lexical_cast<uint64_t>(params[7].get_str());
	// sanity check set to 1 hr
	if(nTime < chainActive.Tip()->nTime+3600)
		nTime = chainActive.Tip()->nTime+3600;
    int nMultiSig = 1;
	if(params.size() >= 9)
		nMultiSig = boost::lexical_cast<int>(params[8].get_str());
    UniValue identityNames;
	if(params.size() >= 10)
		identityNames = params[9].get_array();
	
	vchPrivateValue = vchFromString(strPrivateValue);

	CWalletTx wtx;

	EnsureWalletIsUnlocked();
	CPubKey defaultKey, encryptionKey;
	encryptionKey = pwalletMain->GenerateNewKey(0, false);
	CKey privateEncryptionKey;
	pwalletMain->GetKey(encryptionKey.GetID(), privateEncryptionKey);
	std::vector<unsigned char> vchEncryptionPublicKey(encryptionKey.begin(), encryptionKey.end());
	std::vector<unsigned char> vchEncryptionPrivateKey(privateEncryptionKey.begin(), privateEncryptionKey.end());

	CIdentityIndex oldIdentity;
	vector<CIdentityIndex> vtxPos;
	bool isExpired;
	bool identityExists = GetVtxOfIdentity(vchIdentity, oldIdentity, vtxPos, isExpired);
	if(identityExists && !isExpired)
		throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5508 - " + _("This identity already exists"));
	if(IsMyIdentity(oldIdentity))
	{
		defaultKey = CPubKey(oldIdentity.vchPubKey);	
	}
	else if(strPassword.empty())
		defaultKey = pwalletMain->GenerateNewKey(0, false);

	CDynamicAddress oldAddress(defaultKey.GetID());
	if(!strPassword.empty())
	{
		CCrypter crypt;
		uint256 hashIdentityNum = Hash(vchIdentity.begin(), vchIdentity.end());
		vector<unsigned char> vchIdentityHash = vchFromString(hashIdentityNum.GetHex());
		vchIdentityHash.resize(WALLET_CRYPTO_SALT_SIZE);
		string pwStr = strPassword;
		SecureString password = pwStr.c_str();
		if(!crypt.SetKeyFromPassphrase(password, vchIdentityHash, 25000, 0))
			throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5509 - " + _("Could not determine key from password"));
		CKey key;
		key.Set(crypt.chKey, crypt.chKey + (sizeof crypt.chKey), true);
		defaultKey = key.GetPubKey();
		if(!defaultKey.IsFullyValid())
			throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5510 - " + _("Generated public key not fully valid"));
		CKey keyTmp;
		if(!pwalletMain->GetKey(defaultKey.GetID(), keyTmp) && !pwalletMain->AddKeyPubKey(key, defaultKey))	
			throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5511 - " + _("Please choose a different password"));
	}
	CScript scriptPubKeyOrig;
	CMultiSigIdentityInfo multiSigInfo;
	string strCipherText;
	if(identityNames.size() > 0)
	{
		multiSigInfo.nRequiredSigs = nMultiSig;
		std::vector<CPubKey> pubkeys; 
		pubkeys.push_back(defaultKey);
		for(int i =0;i<identityNames.size();i++)
		{
			CIdentityIndex multiSigIdentity;
			CTransaction txMultiSigIdentity;
			if (!GetTxOfIdentity( vchFromString(identityNames[i].get_str()), multiSigIdentity, txMultiSigIdentity))
				throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5512 - " + _("Could not find multisig identity with the name: ") + identityNames[i].get_str());

			CPubKey pubkey(multiSigIdentity.vchPubKey);
			pubkeys.push_back(pubkey);
			multiSigInfo.vchIdentityes.push_back(identityNames[i].get_str());
			vector<unsigned char> vchMSPubKey(pubkey.begin(), pubkey.end());
			if(!EncryptMessage(vchMSPubKey, vchEncryptionPrivateKey, strCipherText))
				throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5513 - " + _("Could not encrypt private encryption key!"));
			multiSigInfo.vchEncryptionPrivateKeys.push_back(strCipherText);
		}
		scriptPubKeyOrig = GetScriptForMultisig(nMultiSig, pubkeys);
		std::vector<unsigned char> vchRedeemScript(scriptPubKeyOrig.begin(), scriptPubKeyOrig.end());
		multiSigInfo.vchRedeemScript = vchRedeemScript;

	}	
	else
		scriptPubKeyOrig = GetScriptForDestination(defaultKey.GetID());

	CDynamicAddress newAddress = CDynamicAddress(CScriptID(scriptPubKeyOrig));	

	std::vector<unsigned char> vchPubKey(defaultKey.begin(), defaultKey.end());
	
	if(!EncryptMessage(vchEncryptionPublicKey, vchPrivateValue, strCipherText))
	{
		throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5514 - " + _("Could not encrypt private identity value!"));
	}
	vchPrivateValue = vchFromString(strCipherText);

	if(!EncryptMessage(vchPubKey, vchEncryptionPrivateKey, strCipherText))
	{
		throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5515 - " + _("Could not encrypt private encryption key!"));
	}
	vchEncryptionPrivateKey = vchFromString(strCipherText);
	
	if(!strPassword.empty())
	{
		if(!EncryptMessage(vchPubKey, vchFromString(strPassword), strCipherText))
		{
			throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5516 - " + _("Could not encrypt identity password"));
		}
		strPassword = strCipherText;
	}
	vector<unsigned char> vchRandIdentity = vchFromString(GenerateDynamicGuid());

    // build identity
    CIdentityIndex newIdentity;
	newIdentity.vchGUID = vchRandIdentity;
	newIdentity.vchIdentityPeg = vchIdentityPeg;
	newIdentity.vchIdentity = vchIdentity;
	newIdentity.nHeight = chainActive.Tip()->nHeight;
	newIdentity.vchPubKey = vchPubKey;
	newIdentity.vchEncryptionPublicKey = vchEncryptionPublicKey;
	newIdentity.vchEncryptionPrivateKey = vchEncryptionPrivateKey;
	newIdentity.vchPublicValue = vchPublicValue;
	newIdentity.vchPrivateValue = vchPrivateValue;
	newIdentity.nExpireTime = nTime;
	newIdentity.vchPassword = vchFromString(strPassword);
	newIdentity.safetyLevel = 0;
	newIdentity.safeSearch = strSafeSearch == "Yes"? true: false;
	newIdentity.acceptCertTransfers = strAcceptCertTransfers == "Yes"? true: false;
	newIdentity.multiSigInfo = multiSigInfo;
	
	vector<unsigned char> data;
	newIdentity.Serialize(data);
    uint256 hash = Hash(data.begin(), data.end());
    vector<unsigned char> vchHashIdentity = vchFromValue(hash.GetHex());

	CScript scriptPubKey;
	scriptPubKey << CScript::EncodeOP_N(OP_IDENTITY_ACTIVATE) << vchIdentity << vchRandIdentity << vchHashIdentity << OP_2DROP << OP_2DROP;
	scriptPubKey += scriptPubKeyOrig;

    vector<CRecipient> vecSend;
	CRecipient recipient;
	CreateRecipient(scriptPubKey, recipient);
	for(unsigned int i =0;i<MAX_IDENTITY_UPDATES_PER_BLOCK;i++)
		vecSend.push_back(recipient);
	CScript scriptData;
	
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, vchIdentityPeg, chainActive.Tip()->nHeight, data, fee);
	// calculate a fee if renewal is larger than default.. based on how many years you extend for it will be exponentially more expensive
	uint64_t nTimeExpiry = nTime - chainActive.Tip()->nTime;
	float fYears = nTimeExpiry / ONE_YEAR_IN_SECONDS;
	if(fYears < 1)
		fYears = 1;
	fee.nAmount *= powf(2.88,fYears);


	vecSend.push_back(fee);
	CCoinControl coinControl;
	// if renewing your own identity and address changed, transfer balances
	if(!oldIdentity.IsNull() && newAddress.ToString() != oldAddress.ToString() && IsMyIdentity(oldIdentity))
	{
		coinControl.fAllowOtherInputs = true;
		coinControl.fAllowWatchOnly = true;
		TransferIdentityBalances(vchIdentity, scriptPubKeyOrig, vecSend, coinControl);
	}
	SendMoneyDynamic(vecSend, recipient.nAmount + fee.nAmount, false, wtx, NULL, 0, oldIdentity.multiSigInfo.vchIdentityes.size() > 0, coinControl.HasSelected()? &coinControl: NULL);
	UniValue res(UniValue::VARR);
	if(oldIdentity.multiSigInfo.vchIdentityes.size() > 0)
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
			res.push_back(HexStr(vchPubKey));
		}
		else
		{
			res.push_back(hex_str);
			res.push_back(HexStr(vchPubKey));
			res.push_back("false");
		}
	}
	else
	{
		res.push_back(wtx.GetHash().GetHex());
		res.push_back(HexStr(vchPubKey));
	}
	return res;
}
UniValue identityupdate(const UniValue& params, bool fHelp) {
	if (fHelp || 3 > params.size() || 11 < params.size())
		throw runtime_error(
		"identityupdate <identitypeg> <identityname> <public value> [private value=''] [safesearch=Yes] [toidentity_pubkey=''] [password=''] [accept transfers=Yes] [expire=31536000] [nrequired=0] [\"identity\",...]\n"
						"Update and possibly transfer an identity.\n"
						"<identityname> identity name.\n"
						"<public value> identity public profile data, 1024 chars max.\n"
						"<private value> identity private profile data, 1024 chars max. Will be private and readable by owner only.\n"				
						"<password> used to generate your public/private key that controls this identity. Warning: Calling this function over a public network can lead to someone reading your password in plain text. Leave empty to leave current password unchanged.\n"
						"<safesearch> is this identity safe to search. Defaults to Yes, No for not safe and to hide in GUI search queries\n"
						"<toidentity_pubkey> receiver dynamic identity pub key, if transferring identity.\n"
						"<accept transfers> set to No if this identity should not allow a certificate to be transferred to it. Defaults to Yes.\n"		
						"<expire> String. Time in seconds. Future time when to expire identity. It is exponentially more expensive per year, calculation is 1.5^years. FEERATE is the dynamic satoshi per byte fee set in the rate peg identity used for this identity. Defaults to 1 year.\n"		
						"<nrequired> For multisig identities only. The number of required signatures out of the n identities for a multisig identity update.\n"
						"<identities>     For multisig identities only. A json array of identities which are used to sign on an update to this identity.\n"
						"     [\n"
						"       \"identity\"    Existing dynamic identity name\n"
						"       ,...\n"
						"     ]\n"							
						+ HelpRequiringPassphrase());
	vector<unsigned char> vchIdentityPeg = vchFromString(params[0].get_str());
	if(vchIdentityPeg.empty())
		vchIdentityPeg = vchFromString("dynrates.peg");
	vector<unsigned char> vchIdentity = vchFromString(params[1].get_str());
	vector<unsigned char> vchPublicValue;
	vector<unsigned char> vchPrivateValue;
	string strPublicValue = params[2].get_str();
	vchPublicValue = vchFromString(strPublicValue);
	string strPrivateValue = params.size()>=4 && params[3].get_str().size() > 0?params[3].get_str():"";
	vchPrivateValue = vchFromString(strPrivateValue);
	vector<unsigned char> vchPubKeyByte;
	
	CWalletTx wtx;
	CIdentityIndex updateIdentity;

	string strSafeSearch = "Yes";
	if(params.size() >= 5)
	{
		strSafeSearch = params[4].get_str();
	}
	string strPubKey;
	bool transferIdentity = false;
    if (params.size() >= 6 && params[5].get_str().size() > 1) {
		transferIdentity = true;
		vector<unsigned char> vchPubKey;
		vchPubKey = vchFromString(params[5].get_str());
		boost::algorithm::unhex(vchPubKey.begin(), vchPubKey.end(), std::back_inserter(vchPubKeyByte));
	}
	string strPassword;
	if(params.size() >= 7 && params[6].get_str().size() > 0 && vchPubKeyByte.empty())
		strPassword = params[6].get_str();

	if(strPassword.size() < 4 && strPassword.size() > 0)
		throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5517 - " + _("Invalid Dynamic Identity. Please enter a password atleast 4 characters long"));

	string strAcceptCertTransfers = "Yes";
	if(params.size() >= 8)
	{
		strAcceptCertTransfers = params[7].get_str();
	}
	uint64_t nTime = chainActive.Tip()->nTime+ONE_YEAR_IN_SECONDS;
	if(params.size() >= 9)
		nTime = boost::lexical_cast<uint64_t>(params[8].get_str());
	// sanity check set to 1 hr
	if(nTime < chainActive.Tip()->nTime+3600)
		nTime = chainActive.Tip()->nTime+3600;
    int nMultiSig = 1;
	if(params.size() >= 10)
		nMultiSig = boost::lexical_cast<int>(params[9].get_str());
    UniValue identityNames;
	if(params.size() >= 11)
		identityNames = params[10].get_array();
	EnsureWalletIsUnlocked();
	CTransaction tx;
	CIdentityIndex theIdentity;
	if (!GetTxOfIdentity(vchIdentity, theIdentity, tx, true))
		throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5518 - " + _("Could not find an identity with this name"));

	COutPoint outPoint;
	int numResults  = identityunspent(vchIdentity, outPoint);
	const CWalletTx* wtxIn = pwalletMain->GetWalletTx(outPoint.hash);
	if (wtxIn == NULL)
		throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5519 - " + _("This identity is not in your wallet"));

	CDynamicAddress oldAddress;
	GetAddress(theIdentity, &oldAddress);
	CPubKey pubKey(theIdentity.vchPubKey);	
	if(!strPassword.empty())
	{
		CCrypter crypt;
		uint256 hashIdentityNum = Hash(vchIdentity.begin(), vchIdentity.end());
		vector<unsigned char> vchIdentityHash = vchFromString(hashIdentityNum.GetHex());
		vchIdentityHash.resize(WALLET_CRYPTO_SALT_SIZE);
		string pwStr = strPassword;
		SecureString password = pwStr.c_str();
		if(!crypt.SetKeyFromPassphrase(password, vchIdentityHash, 25000, 0))
			throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5520 - " + _("Could not determine key from password"));
		CKey key;
		key.Set(crypt.chKey, crypt.chKey + (sizeof crypt.chKey), true);
		pubKey = key.GetPubKey();
		
		if(!pubKey.IsFullyValid())
			throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5521 - " + _("Generated public key not fully valid"));	
		CKey keyTmp;
		if(!pwalletMain->GetKey(pubKey.GetID(), keyTmp) && !pwalletMain->AddKeyPubKey(key, pubKey))	
			throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5522 - " + _("Please choose a different password"));	
	}
	CIdentityIndex copyIdentity = theIdentity;
	theIdentity.ClearIdentity();
	CKey vchSecret;
	if(vchPubKeyByte.empty())
	{
		vchPubKeyByte = vector<unsigned char>(pubKey.begin(), pubKey.end());
	}
	pubKey = CPubKey(vchPubKeyByte);
	string strCipherText;
	vector<unsigned char> vchEncryptionPrivateKey = copyIdentity.vchEncryptionPrivateKey;
	vector<unsigned char> vchEncryptionPublicKey = copyIdentity.vchEncryptionPublicKey;
	string strDecryptedText = "";
	if(!DecryptPrivateKey(copyIdentity.vchPubKey, vchEncryptionPrivateKey, strDecryptedText))
	{
		throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5523 - " + _("Could not decrypt identity encryption private key"));
	}
	vchEncryptionPrivateKey = vchFromString(strDecryptedText);
	if(!vchPrivateValue.empty())
	{
		// see if data changed, if not dont send payload
		if(!copyIdentity.vchPrivateValue.empty() && !transferIdentity)
		{
			if(!DecryptMessage(copyIdentity, copyIdentity.vchPrivateValue, strDecryptedText))
			{
				throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5524 - " + _("Could not decrypt identity private data"));
			}
			if(vchPrivateValue == vchFromString(strDecryptedText))
				vchPrivateValue = copyIdentity.vchPrivateValue;
			else
			{
				if(!EncryptMessage(vchEncryptionPublicKey, vchPrivateValue, strCipherText))
				{
					throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5525 - " + _("Could not encrypt identity private data"));
				}
				vchPrivateValue = vchFromString(strCipherText);
			}
		}
		else
		{
			if(!EncryptMessage(vchEncryptionPublicKey, vchPrivateValue, strCipherText))
			{
				throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5526 - " + _("Could not encrypt identity private data"));
			}
			vchPrivateValue = vchFromString(strCipherText);
		}
	}
	if(!strPassword.empty())
	{
		// encrypt using new key
		if(!EncryptMessage(vchPubKeyByte, vchFromString(strPassword), strCipherText))
		{
			throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5527 - " + _("Could not encrypt identity password"));
		}
		strPassword = strCipherText;
	}
	CMultiSigIdentityInfo multiSigInfo;
	if(identityNames.size() > 0)
	{
		multiSigInfo.nRequiredSigs = nMultiSig;
		std::vector<CPubKey> pubkeys; 
		pubkeys.push_back(pubKey);
		for(int i =0;i<identityNames.size();i++)
		{
			CIdentityIndex multiSigIdentity;
			CTransaction txMultiSigIdentity;
			if (!GetTxOfIdentity( vchFromString(identityNames[i].get_str()), multiSigIdentity, txMultiSigIdentity))
				throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5528 - " + _("Could not find multisig identity with the name: ") + identityNames[i].get_str());

			CPubKey pubkey(multiSigIdentity.vchPubKey);
			pubkeys.push_back(pubkey);
			multiSigInfo.vchIdentityes.push_back(identityNames[i].get_str());
			vector<unsigned char> vchMSPubKey(pubkey.begin(), pubkey.end());
			if(!EncryptMessage(vchMSPubKey, vchEncryptionPrivateKey, strCipherText))
				throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5529 - " + _("Could not encrypt private encryption key!"));
			multiSigInfo.vchEncryptionPrivateKeys.push_back(strCipherText);
		}	
		CScript script = GetScriptForMultisig(nMultiSig, pubkeys);
		std::vector<unsigned char> vchRedeemScript(script.begin(), script.end());
		multiSigInfo.vchRedeemScript = vchRedeemScript;
	}

	if(!EncryptMessage(vchPubKeyByte, vchEncryptionPrivateKey, strCipherText))
	{
		throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5530 - " + _("Could not encrypt private encryption key!"));
	}
	vchEncryptionPrivateKey = vchFromString(strCipherText);

	theIdentity.nHeight = chainActive.Tip()->nHeight;
	if(copyIdentity.vchPublicValue != vchPublicValue)
		theIdentity.vchPublicValue = vchPublicValue;
	if(copyIdentity.vchPrivateValue != vchPrivateValue)
		theIdentity.vchPrivateValue = vchPrivateValue;
	if(copyIdentity.vchEncryptionPrivateKey != vchEncryptionPrivateKey)
		theIdentity.vchEncryptionPrivateKey = vchEncryptionPrivateKey;
	if(copyIdentity.vchEncryptionPublicKey != vchEncryptionPublicKey)
		theIdentity.vchEncryptionPublicKey = vchEncryptionPublicKey;
	if(copyIdentity.vchPassword != vchFromString(strPassword))
		theIdentity.vchPassword = vchFromString(strPassword);

	theIdentity.vchIdentityPeg = vchIdentityPeg;
	theIdentity.multiSigInfo = multiSigInfo;
	theIdentity.vchPubKey = vchPubKeyByte;
	theIdentity.nExpireTime = nTime;
	theIdentity.safeSearch = strSafeSearch == "Yes"? true: false;
	theIdentity.acceptCertTransfers = strAcceptCertTransfers == "Yes"? true: false;
	
	CDynamicAddress newAddress;
	CScript scriptPubKeyOrig;
	GetAddress(theIdentity, &newAddress, scriptPubKeyOrig);
	vector<unsigned char> data;
	theIdentity.Serialize(data);
    uint256 hash = Hash(data.begin(), data.end());
    vector<unsigned char> vchHashIdentity = vchFromValue(hash.GetHex());

	CScript scriptPubKey;
	scriptPubKey << CScript::EncodeOP_N(OP_IDENTITY_UPDATE) << copyIdentity.vchIdentity << copyIdentity.vchGUID << vchHashIdentity << OP_2DROP << OP_2DROP;
	scriptPubKey += scriptPubKeyOrig;

    vector<CRecipient> vecSend;
	CRecipient recipient;
	CreateRecipient(scriptPubKey, recipient); 
	for(unsigned int i =numResults;i<=MAX_IDENTITY_UPDATES_PER_BLOCK;i++)
		vecSend.push_back(recipient);

	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, copyIdentity.vchIdentityPeg,  chainActive.Tip()->nHeight, data, fee);
	// calculate a fee if renewal is larger than default.. based on how many years you extend for it will be exponentially more expensive
	uint64_t nTimeExpiry = nTime - chainActive.Tip()->nTime;
	float fYears = nTimeExpiry / ONE_YEAR_IN_SECONDS;
	if(fYears < 1)
		fYears = 1;
	fee.nAmount *= powf(2.88,fYears);
	
	vecSend.push_back(fee);
	CCoinControl coinControl;
	// for now dont transfer balances on an identity transfer (TODO add option to transfer balances)
	if(!transferIdentity && newAddress.ToString() != oldAddress.ToString())
	{
		coinControl.fAllowOtherInputs = true;
		coinControl.fAllowWatchOnly = true;
		TransferIdentityBalances(vchIdentity, scriptPubKeyOrig, vecSend, coinControl);
	}
	
	SendMoneyDynamic(vecSend, recipient.nAmount+fee.nAmount, false, wtx, wtxIn, outPoint.n, copyIdentity.multiSigInfo.vchIdentityes.size() > 0, coinControl.HasSelected()? &coinControl: NULL);
	UniValue res(UniValue::VARR);
	if(copyIdentity.multiSigInfo.vchIdentityes.size() > 0)
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
			res.push_back(wtx.GetHash().GetHex());
		else
		{
			res.push_back(hex_str);
			res.push_back("false");
		}
	}
	else
		res.push_back(wtx.GetHash().GetHex());
	return res;
}
UniValue dynamicdecoderawtransaction(const UniValue& params, bool fHelp) {
	if (fHelp || 1 != params.size())
		throw runtime_error("dynamicdecoderawtransaction <identity> <hexstring>\n"
		"Decode raw dynamic transaction (serialized, hex-encoded) and display information pertaining to the service that is included in the transactiion data output(OP_RETURN)\n"
				"<hexstring> The transaction hex string.\n");
	string hexstring = params[0].get_str();
	CTransaction rawTx;
	DecodeHexTx(rawTx,hexstring);
	if(rawTx.IsNull())
	{
		throw runtime_error("DYNAMIC_RPC_ERROR: ERRCODE: 5531 - " + _("Could not decode transaction"));
	}
	vector<unsigned char> vchData;
	int nOut;
	int op;
	vector<vector<unsigned char> > vvch;
	vector<unsigned char> vchHash;
	GetDynamicData(rawTx, vchData, vchHash, nOut);	
	UniValue output(UniValue::VOBJ);
	if(DecodeAndParseDynamicTx(rawTx, op, nOut, vvch))
		DynTxToJSON(op, vchData, vchHash, output);
	
	bool sendCoin = false;
	for (unsigned int i = 0; i < rawTx.vout.size(); i++) {
		int tmpOp;
		vector<vector<unsigned char> > tmpvvch;	
		if(!IsDynamicDataOutput(rawTx.vout[i]) && (!IsDynamicScript(rawTx.vout[i].scriptPubKey, tmpOp, tmpvvch) || tmpOp == OP_IDENTITY_PAYMENT))
		{
			if(!pwalletMain->IsMine(rawTx.vout[i]))
			{
				sendCoin = true;
				break;
			}
		}

	}
	if(sendCoin)
		output.push_back(Pair("warning", _("Warning: This transaction sends coins to an address or identity you do not own")));
	return output;
}
void DynTxToJSON(const int op, const vector<unsigned char> &vchData, const vector<unsigned char> &vchHash, UniValue &entry)
{
	if(IsIdentityOp(op))
		IdentityTxToJSON(op, vchData, vchHash, entry);
	if(IsCertOp(op))
		CertTxToJSON(op, vchData, vchHash, entry);
	if(IsMessageOp(op))
		MessageTxToJSON(op,vchData, vchHash, entry);
	if(IsEscrowOp(op))
		EscrowTxToJSON(op, vchData, vchHash, entry);
	if(IsOfferOp(op))
		OfferTxToJSON(op, vchData, vchHash, entry);
}
void IdentityTxToJSON(const int op, const vector<unsigned char> &vchData, const vector<unsigned char> &vchHash, UniValue &entry)
{
	string opName = identityFromOp(op);
	CIdentityIndex identity;
	if(!identity.UnserializeFromData(vchData, vchHash))
		return;
	bool isExpired = false;
	vector<CIdentityIndex> identityVtxPos;
	CTransaction identitytx;
	CIdentityIndex dbIdentity;
	if(GetTxAndVtxOfIdentity(identity.vchIdentity, dbIdentity, identitytx, identityVtxPos, isExpired, true))
	{
		dbIdentity.nHeight = identity.nHeight;
		dbIdentity.GetIdentityFromList(identityVtxPos);
	}
	string noDifferentStr = _("<No Difference Detected>");

	entry.push_back(Pair("txtype", opName));
	entry.push_back(Pair("name", stringFromVch(identity.vchIdentity)));

	string identityPegValue = noDifferentStr;
	if(!identity.vchIdentityPeg.empty() && identity.vchIdentityPeg != dbIdentity.vchIdentityPeg)
		identityPegValue = stringFromVch(identity.vchIdentityPeg);

	entry.push_back(Pair("identitypeg", identityPegValue));

	string publicValue = noDifferentStr;
	if(!identity.vchPublicValue .empty() && identity.vchPublicValue != dbIdentity.vchPublicValue)
		publicValue = stringFromVch(identity.vchPublicValue);
	entry.push_back(Pair("publicvalue", publicValue));

	string strPrivateValue = "";
	if(!identity.vchPrivateValue.empty())
		strPrivateValue = _("Encrypted for identity owner");
	string strDecrypted = "";
	if(DecryptMessage(identity, identity.vchPrivateValue, strDecrypted))
		strPrivateValue = strDecrypted;		

	string privateValue = noDifferentStr;
	if(!identity.vchPrivateValue.empty() && identity.vchPrivateValue != dbIdentity.vchPrivateValue)
		privateValue = strPrivateValue;

	entry.push_back(Pair("privatevalue", privateValue));

	string strPassword = "";
	if(!identity.vchPassword.empty())
		strPassword = _("Encrypted for identity owner");
	strDecrypted = "";
	if(DecryptPrivateKey(identity.vchPubKey, identity.vchPassword, strDecrypted))
		strPassword = strDecrypted;		

	string password = noDifferentStr;
	if(!identity.vchPassword.empty() && identity.vchPassword != dbIdentity.vchPassword)
		password = strPassword;

	entry.push_back(Pair("password", password));


	CDynamicAddress address;
	GetAddress(identity, &address);
	CDynamicAddress dbaddress;
	GetAddress(dbIdentity, &dbaddress);

	string addressValue = noDifferentStr;
	if(address.ToString() != dbaddress.ToString())
		addressValue = address.ToString();

	entry.push_back(Pair("address", addressValue));


	string safeSearchValue = noDifferentStr;
	if(identity.safeSearch != dbIdentity.safeSearch)
		safeSearchValue = identity.safeSearch? "Yes": "No";

	entry.push_back(Pair("safesearch", safeSearchValue));
	
	string acceptTransfersValue = noDifferentStr;
	if(identity.acceptCertTransfers != dbIdentity.acceptCertTransfers)
		acceptTransfersValue = identity.acceptCertTransfers? "Yes": "No";

	entry.push_back(Pair("acceptcerttransfers", acceptTransfersValue));

	string expireValue = noDifferentStr;
	if(identity.nExpireTime != dbIdentity.nExpireTime)
		expireValue = strprintf("%d", identity.nExpireTime);

	entry.push_back(Pair("renewal", expireValue));

	string safetyLevelValue = noDifferentStr;
	if(identity.safetyLevel != dbIdentity.safetyLevel)
		safetyLevelValue = identity.safetyLevel;

	entry.push_back(Pair("safetylevel", safetyLevelValue ));

	UniValue msInfo(UniValue::VOBJ);

	string reqsigsValue = noDifferentStr;
	if(identity.multiSigInfo != dbIdentity.multiSigInfo)
	{
		msInfo.push_back(Pair("reqsigs", (int)identity.multiSigInfo.nRequiredSigs));
		UniValue msIdentityes(UniValue::VARR);
		for(int i =0;i<identity.multiSigInfo.vchIdentityes.size();i++)
		{
			msIdentityes.push_back(identity.multiSigInfo.vchIdentityes[i]);
		}
		msInfo.push_back(Pair("reqsigners", msIdentityes));
		
	}
	else
	{
		msInfo.push_back(Pair("reqsigs", noDifferentStr));
		msInfo.push_back(Pair("reqsigners", noDifferentStr));
	}
	entry.push_back(Pair("multisiginfo", msInfo));

}
UniValue dynamicsignrawtransaction(const UniValue& params, bool fHelp) {
	if (fHelp || 1 != params.size())
		throw runtime_error("dynamicsignrawtransaction <hexstring>\n"
				"Sign inputs for raw transaction (serialized, hex-encoded) and sends them out to the network if signing is complete\n"
				"<hexstring> The transaction hex string.\n");
	string hexstring = params[0].get_str();
	string doNotSend = params.size() >= 2? params[1].get_str(): "0";
	UniValue res;
	UniValue arraySignParams(UniValue::VARR);
	arraySignParams.push_back(hexstring);
	try
	{
		res = tableRPC.execute("signrawtransaction", arraySignParams);
	}
	catch (UniValue& objError)
	{
		throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5532 - " + _("Could not sign multisig transaction: ") + find_value(objError, "message").get_str());
	}	
	if (!res.isObject())
		throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5533 - " + _("Could not sign multisig transaction: Invalid response from signrawtransaction"));
	
	const UniValue& so = res.get_obj();
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
		UniValue arraySendParams(UniValue::VARR);
		arraySendParams.push_back(hex_str);
		UniValue returnRes;
		try
		{
			returnRes = tableRPC.execute("sendrawtransaction", arraySendParams);
		}
		catch (UniValue& objError)
		{
			throw runtime_error(find_value(objError, "message").get_str());
		}
		if (!returnRes.isStr())
			throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5534 - " + _("Could not send raw transaction: Invalid response from sendrawtransaction"));
	}
	return res;
}
bool IsMyIdentity(const CIdentityIndex& identity)
{

	CPubKey identityPubKey(identity.vchPubKey);
	CDynamicAddress address(identityPubKey.GetID());
	if(identity.multiSigInfo.vchIdentityes.size() > 0)
	{
		CScript inner(identity.multiSigInfo.vchRedeemScript.begin(), identity.multiSigInfo.vchRedeemScript.end());
		return IsMine(*pwalletMain, inner);
	}
	else
		return IsMine(*pwalletMain, address.Get());
}
UniValue identitylist(const UniValue& params, bool fHelp) {
	if (fHelp || 2 < params.size())
		throw runtime_error("identitylist [<identityname>] [<privatekey>]\n"
				"list my own identities.\n"
				"<identityname> identity name to use as filter.\n");

	vector<unsigned char> vchIdentity;
	if (params.size() >= 1)
		vchIdentity = vchFromValue(params[0]);

	string strPrivateKey;
	if(params.size() >= 2)
		strPrivateKey = params[1].get_str();	

	UniValue oRes(UniValue::VARR);
	map<vector<unsigned char>, int> vNamesI;
	map<vector<unsigned char>, UniValue> vNamesO;

	uint256 hash;
	CTransaction tx;
	int pending = 0;
	BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, pwalletMain->mapWallet) {
		pending = 0;
		// get txn hash, read txn index
		hash = item.second.GetHash();
		const CWalletTx &wtx = item.second;
		// skip non-dynamic txns
		if (wtx.nVersion != DYNAMIC_TX_VERSION)
			continue;

		vector<CIdentityIndex> vtxPos;
		CIdentityIndex identity(wtx);
		if(identity.IsNull())
			continue;
		// skip this identity if it doesn't match the given filter value
		if (vchIdentity.size() > 0 && identity.vchIdentity != vchIdentity)
			continue;
		if (!pidentitydb->ReadIdentity(identity.vchIdentity, vtxPos) || vtxPos.empty())
		{
			pending = 1;
			if(!IsDynamicTxMine(wtx, "identity"))
				continue;
		}
		else
		{
			identity = vtxPos.back();
			CTransaction tx;
			if (!GetDynamicTransaction(identity.nHeight, identity.txHash, tx, Params().GetConsensus()))
			{
				pending = 1;
				if(!IsDynamicTxMine(wtx, "identity"))
					continue;
			}
			else{
				if(!IsMyIdentity(identity))
					continue;
			}
		}
		// get last active name only
		if (vNamesI.find(identity.vchIdentity) != vNamesI.end() && (identity.nHeight <= vNamesI[identity.vchIdentity] || vNamesI[identity.vchIdentity] < 0))
			continue;	
		UniValue oName(UniValue::VOBJ);
		if(BuildIdentityJson(identity, pending, oName, strPrivateKey))
		{
			vNamesI[identity.vchIdentity] = identity.nHeight;
			vNamesO[identity.vchIdentity] = oName;	
		}
	}
	BOOST_FOREACH(const PAIRTYPE(vector<unsigned char>, UniValue)& item, vNamesO)
		oRes.push_back(item.second);
	return oRes;
}

UniValue identityaffiliates(const UniValue& params, bool fHelp) {
	if (fHelp || 1 < params.size())
		throw runtime_error("identityaffiliates \n"
				"list my own affiliations with merchant offers.\n");
	

	vector<unsigned char> vchOffer;
	UniValue oRes(UniValue::VARR);
	map<vector<unsigned char>, int> vOfferI;
	map<vector<unsigned char>, UniValue> vOfferO;
	{
		uint256 hash;
		CTransaction tx;
		uint64_t nHeight;
		BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, pwalletMain->mapWallet) {
			// get txn hash, read txn index
			hash = item.second.GetHash();
			const CWalletTx &wtx = item.second;
			// skip non-dynamic txns
			if (wtx.nVersion != DYNAMIC_TX_VERSION)
				continue;

			// decode txn, skip non-identity txns
            vector<vector<unsigned char> > vvch;
            int op, nOut;
            if (!DecodeOfferTx(wtx, op, nOut, vvch) 
            	|| !IsOfferOp(op) 
            	|| (op == OP_OFFER_ACCEPT))
                continue;
			if(!IsDynamicTxMine(wtx, "offer"))
					continue;
            vchOffer = vvch[0];

			vector<COffer> vtxPos;
			COffer theOffer;
			if (!pofferdb->ReadOffer(vchOffer, vtxPos) || vtxPos.empty())
				continue;
			
			theOffer = vtxPos.back();
			nHeight = theOffer.nHeight;
			// get last active name only
			if (vOfferI.find(vchOffer) != vOfferI.end() && (nHeight < vOfferI[vchOffer] || vOfferI[vchOffer] < 0))
				continue;
			vOfferI[vchOffer] = nHeight;
			// if this is my offer and it is linked go through else skip
			if(theOffer.vchLinkOffer.empty())
				continue;
			// get parent offer
			CTransaction tx;
			COffer linkOffer;
			vector<COffer> offerVtxPos;
			if (!GetTxAndVtxOfOffer( theOffer.vchLinkOffer, linkOffer, tx, offerVtxPos))
				continue;

			for(unsigned int i=0;i<linkOffer.linkWhitelist.entries.size();i++) {
				CTransaction txIdentity;
				CIdentityIndex theIdentity;
				COfferLinkWhitelistEntry& entry = linkOffer.linkWhitelist.entries[i];
				if (GetTxOfIdentity(entry.identityLinkVchRand, theIdentity, txIdentity))
				{
					if (!IsMyIdentity(theIdentity))
						continue;
					UniValue oList(UniValue::VOBJ);
					oList.push_back(Pair("offer", stringFromVch(vchOffer)));
					oList.push_back(Pair("identity", stringFromVch(entry.identityLinkVchRand)));
					oList.push_back(Pair("expires_on",theIdentity.nExpireTime));
					oList.push_back(Pair("offer_discount_percentage", strprintf("%d%%", entry.nDiscountPct)));
					vOfferO[vchOffer] = oList;	
				}  
			}
		}
	}

	BOOST_FOREACH(const PAIRTYPE(vector<unsigned char>, UniValue)& item, vOfferO)
		oRes.push_back(item.second);

	return oRes;
}
string GenerateDynamicGuid()
{
	int64_t rand = GetRand(std::numeric_limits<int64_t>::max());
	vector<unsigned char> vchGuidRand = CScriptNum(rand).getvch();
	return HexStr(vchGuidRand);
}
UniValue identitybalance(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "identitybalance \"identity\" ( minconf )\n"
            "\nReturns the total amount received by the given identity in transactions with at least minconf confirmations.\n"
            "\nArguments:\n"
            "1. \"identity\"  (string, required) The dynamic identity for transactions.\n"
            "2. minconf             (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
       );
	LOCK(cs_main);
	vector<unsigned char> vchIdentity = vchFromValue(params[0]);

	CAmount nAmount = 0;
	vector<CIdentityPayment> vtxPaymentPos;
	CIdentityIndex theIdentity;
	CTransaction identityTx;
	if (!GetTxOfIdentity(vchIdentity, theIdentity, identityTx, true))
		return ValueFromAmount(nAmount);

	CDynamicAddress addressFrom;
	GetAddress(theIdentity, &addressFrom);

	if(!pidentitydb->ReadIdentityPayment(vchIdentity, vtxPaymentPos))
		return ValueFromAmount(nAmount);
	
	CCoinsViewCache view(pcoinsTip);
	const CCoins *coins;
	CTxDestination payDest;
	CDynamicAddress destaddy;
	// get all identity inputs and transfer them to the new identity destination
    for (unsigned int i = 0;i<vtxPaymentPos.size();i++)
    {
		const CIdentityPayment& identityPayment = vtxPaymentPos[i];
		coins = view.AccessCoins(identityPayment.txHash);
		if(coins == NULL)
			continue;
       
		if(!coins->IsAvailable(identityPayment.nOut))
			continue;
		if (!ExtractDestination(coins->vout[identityPayment.nOut].scriptPubKey, payDest)) 
			continue;
		destaddy = CDynamicAddress(payDest);
		if (destaddy.ToString() == addressFrom.ToString())
		{  
			nAmount += coins->vout[identityPayment.nOut].nValue;
		}		
		
    }
    return  ValueFromAmount(nAmount);
}
int identityunspent(const vector<unsigned char> &vchIdentity, COutPoint& outpoint)
{
	LOCK2(cs_main, mempool.cs);
	vector<CIdentityIndex> vtxPos;
	CIdentityIndex theIdentity;
	CTransaction identityTx;
	bool isExpired = false;
	if (!GetTxAndVtxOfIdentity(vchIdentity, theIdentity, identityTx, vtxPos, isExpired, true))
		return 0;
	CDynamicAddress destaddy;
	GetAddress(theIdentity, &destaddy);
	CTxDestination identityDest;
	CDynamicAddress prevaddy;
	int numResults = 0;
	CCoinsViewCache view(pcoinsTip);
	const CCoins *coins;
	bool found = false;
    for (unsigned int i = 0;i<vtxPos.size();i++)
    {
		const CIdentityIndex& identity = vtxPos[i];
		coins = view.AccessCoins(identity.txHash);

		if(coins == NULL)
			continue;
         for (unsigned int j = 0;j<coins->vout.size();j++)
		 {
			int op;
			vector<vector<unsigned char> > vvch;

			if(!coins->IsAvailable(j))
				continue;
			if(!pwalletMain->IsMine(coins->vout[j]))
				continue;
			if(pwalletMain->IsLockedCoin(identity.txHash, j))
				continue;
			
			if(!DecodeIdentityScript(coins->vout[j].scriptPubKey, op, vvch) || vvch[0] != theIdentity.vchIdentity || vvch[1] != theIdentity.vchGUID)
				continue;
			if (!ExtractDestination(coins->vout[j].scriptPubKey, identityDest))
				continue;
			prevaddy = CDynamicAddress(identityDest);
			if(destaddy.ToString() != prevaddy.ToString())
				continue;

			numResults++;
			if(!found)
			{
				auto it = mempool.mapNextTx.find(COutPoint(identity.txHash, j));
				if (it != mempool.mapNextTx.end())
					continue;

				outpoint = COutPoint(identity.txHash, j);
				found = true;
			}
			
		 }	
    }
	return numResults;
}
/**
 * [identityinfo description]
 * @param  params [description]
 * @param  fHelp  [description]
 * @return        [description]
 */
UniValue identityinfo(const UniValue& params, bool fHelp) {
	if (fHelp || 2 < params.size())
		throw runtime_error("identityinfo <identityname> [<privatekey>]\n"
				"Show values of an identity.\n");
	vector<unsigned char> vchIdentity = vchFromValue(params[0]);
	string strPrivateKey;
	if(params.size() >= 2)
		strPrivateKey = params[1].get_str();

	vector<CIdentityIndex> vtxPos;
	if (!pidentitydb->ReadIdentity(vchIdentity, vtxPos) || vtxPos.empty())
		throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5535 - " + _("Failed to read from identity DB"));

	UniValue oName(UniValue::VOBJ);
	if(!BuildIdentityJson(vtxPos.back(), 0, oName, strPrivateKey))
		throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5536 - " + _("Could not find this identity"));
		
	return oName;
}
bool BuildIdentityJson(const CIdentityIndex& identity, const int pending, UniValue& oName, const string &strPrivKey)
{
	uint64_t nHeight;
	int expired = 0;
	int64_t expires_in = 0;
	int64_t expired_time = 0;
	nHeight = identity.nHeight;
	oName.push_back(Pair("name", stringFromVch(identity.vchIdentity)));

	if(identity.safetyLevel >= SAFETY_LEVEL2)
		return false;
	oName.push_back(Pair("value", stringFromVch(identity.vchPublicValue)));
	string strPrivateValue = "";
	if(!identity.vchPrivateValue.empty())
		strPrivateValue = _("Encrypted for identity owner");
	string strDecrypted = "";
	if(DecryptMessage(identity, identity.vchPrivateValue, strDecrypted, strPrivKey))
		strPrivateValue = strDecrypted;		
	oName.push_back(Pair("privatevalue", strPrivateValue));

	string strPassword = "";
	if(!identity.vchPassword.empty())
		strPassword = _("Encrypted for identity owner");
	strDecrypted = "";
	if(DecryptPrivateKey(identity.vchPubKey, identity.vchPassword, strDecrypted, strPrivKey))
		strPassword = strDecrypted;		
	oName.push_back(Pair("password", strPassword));


	oName.push_back(Pair("txid", identity.txHash.GetHex()));
	CDynamicAddress address;
	GetAddress(identity, &address);
	if(!address.IsValid())
		return false;

	oName.push_back(Pair("address", address.ToString()));

	oName.push_back(Pair("identity_peg", stringFromVch(identity.vchIdentityPeg)));

	UniValue balanceParams(UniValue::VARR);
	balanceParams.push_back(stringFromVch(identity.vchIdentity));
	const UniValue &resBalance = tableRPC.execute("identitybalance", balanceParams);
	CAmount nIdentityBalance = AmountFromValue(resBalance);
	oName.push_back(Pair("balance", ValueFromAmount(nIdentityBalance)));

	oName.push_back(Pair("ismine", IsMyIdentity(identity)? true:  false));
	oName.push_back(Pair("safesearch", identity.safeSearch ? "Yes" : "No"));
	oName.push_back(Pair("acceptcerttransfers", identity.acceptCertTransfers ? "Yes" : "No"));
	oName.push_back(Pair("safetylevel", identity.safetyLevel ));
	float ratingAsBuyer = 0;
	if(identity.nRatingCountAsBuyer > 0)
	{
		ratingAsBuyer = identity.nRatingAsBuyer/(float)identity.nRatingCountAsBuyer;
		ratingAsBuyer = floor(ratingAsBuyer * 10) / 10;
	}
	float ratingAsSeller = 0;
	if(identity.nRatingCountAsSeller > 0)
	{
		ratingAsSeller = identity.nRatingAsSeller/(float)identity.nRatingCountAsSeller;
		ratingAsSeller = floor(ratingAsSeller * 10) / 10;
	}
	float ratingAsArbiter = 0;
	if(identity.nRatingCountAsArbiter > 0)
	{
		ratingAsArbiter = identity.nRatingAsArbiter/(float)identity.nRatingCountAsArbiter;
		ratingAsArbiter = floor(ratingAsArbiter * 10) / 10;
	}
	oName.push_back(Pair("buyer_rating", ratingAsBuyer));
	oName.push_back(Pair("buyer_ratingcount", (int)identity.nRatingCountAsBuyer));
	oName.push_back(Pair("buyer_rating_display", strprintf("%.1f/5 (%d %s)", ratingAsBuyer, identity.nRatingCountAsBuyer, _("Votes"))));
	oName.push_back(Pair("seller_rating", ratingAsSeller));
	oName.push_back(Pair("seller_ratingcount", (int)identity.nRatingCountAsSeller));
	oName.push_back(Pair("seller_rating_display", strprintf("%.1f/5 (%d %s)", ratingAsSeller, identity.nRatingCountAsSeller, _("Votes"))));
	oName.push_back(Pair("arbiter_rating", ratingAsArbiter));
	oName.push_back(Pair("arbiter_ratingcount", (int)identity.nRatingCountAsArbiter));
	oName.push_back(Pair("arbiter_rating_display", strprintf("%.1f/5 (%d %s)", ratingAsArbiter, identity.nRatingCountAsArbiter, _("Votes"))));
	string sTime;
	CBlockIndex *pindex = chainActive[identity.nHeight];
	if (pindex) {
		sTime = strprintf("%llu", pindex->nTime);
	}
	oName.push_back(Pair("time", sTime));
	if(identity.vchIdentity != vchFromString("dynrates.peg") && identity.vchIdentity != vchFromString("dynban") && identity.vchIdentity != vchFromString("dyncategory"))
	{
		expired_time = identity.nExpireTime;
		if(expired_time <= chainActive.Tip()->nTime)
		{
			expired = 1;
		}  
		expires_in = expired_time - chainActive.Tip()->nTime;
		if(expires_in < -1)
			expires_in = -1;
	}
	else
	{
		expires_in = -1;
		expired = 0;
		expired_time = -1;
	}
	oName.push_back(Pair("expires_in", expires_in));
	oName.push_back(Pair("expires_on", expired_time));
	oName.push_back(Pair("expired", expired));
	oName.push_back(Pair("pending", pending));
	UniValue msInfo(UniValue::VOBJ);
	msInfo.push_back(Pair("reqsigs", (int)identity.multiSigInfo.nRequiredSigs));
	UniValue msIdentityes(UniValue::VARR);
	for(int i =0;i<identity.multiSigInfo.vchIdentityes.size();i++)
	{
		msIdentityes.push_back(identity.multiSigInfo.vchIdentityes[i]);
	}
	msInfo.push_back(Pair("reqsigners", msIdentityes));
	msInfo.push_back(Pair("redeemscript", HexStr(identity.multiSigInfo.vchRedeemScript)));
	oName.push_back(Pair("multisiginfo", msInfo));
	return true;
}
/**
 * [identityhistory description]
 * @param  params [description]
 * @param  fHelp  [description]
 * @return        [description]
 */
UniValue identityhistory(const UniValue& params, bool fHelp) {
	if (fHelp || 1 != params.size())
		throw runtime_error("identityhistory <identityname>\n"
				"List all stored values of an identity.\n");
	UniValue oRes(UniValue::VARR);
	vector<unsigned char> vchIdentity = vchFromValue(params[0]);
	
	vector<CIdentityIndex> vtxPos;
	if (!pidentitydb->ReadIdentity(vchIdentity, vtxPos) || vtxPos.empty())
		throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5537 - " + _("Failed to read from identity DB"));

	CIdentityIndex txPos2;
	CTransaction tx;
    vector<vector<unsigned char> > vvch;
    int op, nOut;
	string opName;
	BOOST_FOREACH(txPos2, vtxPos) {
		if (!GetDynamicTransaction(txPos2.nHeight, txPos2.txHash, tx, Params().GetConsensus()))
			continue;

		if(DecodeOfferTx(tx, op, nOut, vvch) )
		{
			opName = offerFromOp(op);
			COffer offer(tx);
			if(offer.accept.bPaymentAck)
				opName += "("+_("acknowledged")+")";
			else if(!offer.accept.feedback.empty())
				opName += "("+_("feedback")+")";

		}
		else if(DecodeMessageTx(tx, op, nOut, vvch) )
			opName = messageFromOp(op);
		else if(DecodeEscrowTx(tx, op, nOut, vvch) )
		{
			CEscrow escrow(tx);
			opName = escrowFromOp(escrow.op);
			if(escrow.bPaymentAck)
				opName += "("+_("acknowledged")+")";
			else if(!escrow.feedback.empty())
				opName += "("+_("feedback")+")";
		}
		else if(DecodeCertTx(tx, op, nOut, vvch) )
			opName = certFromOp(op);
		else if(DecodeIdentityTx(tx, op, nOut, vvch) )
			opName = stringFromVch(vvch[0]);
		else
			continue;
		UniValue oName(UniValue::VOBJ);
		oName.push_back(Pair("type", opName));
		if(BuildIdentityJson(txPos2, 0, oName))
			oRes.push_back(oName);
	}
	
	return oRes;
}
UniValue generatepublickey(const UniValue& params, bool fHelp) {
	if(!pwalletMain)
		throw runtime_error("No wallet defined!");
	EnsureWalletIsUnlocked();
	CPubKey PubKey = pwalletMain->GenerateNewKey(0, false);
	std::vector<unsigned char> vchPubKey(PubKey.begin(), PubKey.end());
	UniValue res(UniValue::VARR);
	res.push_back(HexStr(vchPubKey));
	return res;
}
/**
 * [identityfilter description]
 * @param  params [description]
 * @param  fHelp  [description]
 * @return        [description]
 */
UniValue identityfilter(const UniValue& params, bool fHelp) {
	if (fHelp || params.size() > 3)
		throw runtime_error(
				"identityfilter [[[[[regexp]] from='']] safesearch='Yes']\n"
						"scan and filter identities\n"
						"[regexp] : apply [regexp] on identities, empty means all identities\n"
						"[from] : show results from this GUID [from], empty means first.\n"
						"[identityfilter] : shows all identities that are safe to display (not on the ban list)\n"
						"identityfilter \"\" 5 # list identities updated in last 5 blocks\n"
						"identityfilter \"^identity\" # list all identities starting with \"identity\"\n"
						"identityfilter 36000 0 0 stat # display stats (number of identities) on active identities\n");

	vector<unsigned char> vchIdentity;
	string strRegexp;
	string strName;
	bool safeSearch = true;


	if (params.size() > 0)
		strRegexp = params[0].get_str();

	if (params.size() > 1)
	{
		vchIdentity = vchFromValue(params[1]);
		strName = params[1].get_str();
	}

	if (params.size() > 2)
		safeSearch = params[2].get_str()=="On"? true: false;

	UniValue oRes(UniValue::VARR);

	
	vector<CIdentityIndex> nameScan;
	boost::algorithm::to_lower(strName);
	vchIdentity = vchFromString(strName);
	CTransaction identitytx;
	if (!pidentitydb->ScanNames(vchIdentity, strRegexp, safeSearch, 25, nameScan))
		throw runtime_error("DYNAMIC_IDENTITY_RPC_ERROR: ERRCODE: 5538 - " + _("Scan failed"));

	BOOST_FOREACH(const CIdentityIndex &identity, nameScan) {
		UniValue oName(UniValue::VOBJ);
		if(BuildIdentityJson(identity, 0, oName))
			oRes.push_back(oName);
	}


	return oRes;
}
void GetPrivateKeysFromScript(const CScript& script, vector<string> &strKeys)
{
    vector<CTxDestination> addrs;
    int nRequired;
	txnouttype whichType;
    ExtractDestinations(script, whichType, addrs, nRequired);
	BOOST_FOREACH(const CTxDestination& txDest, addrs) {
		CDynamicAddress address(txDest);
		CKeyID keyID;
		if (!address.GetKeyID(keyID))
			continue;
		CKey vchSecret;
		if (!pwalletMain->GetKey(keyID, vchSecret))
			continue;
		strKeys.push_back(CDynamicSecret(vchSecret).ToString());
	}
}
UniValue identitypay(const UniValue& params, bool fHelp) {

    if (fHelp || params.size() < 2 || params.size() > 4)
        throw runtime_error(
            "identitypay identityfrom {\"address\":amount,...} ( minconf \"comment\")\n"
            "\nSend multiple times from an identity. Amounts are double-precision floating point numbers."
            + HelpRequiringPassphrase() + "\n"
            "\nArguments:\n"
			"1. \"identity\"				(string, required) identity to pay from\n"
            "2. \"amounts\"             (string, required) A json object with identities and amounts\n"
            "    {\n"
            "      \"address\":amount   (numeric or string) The dynamic identity is the key, the numeric amount (can be string) in " + CURRENCY_UNIT + " is the value\n"
            "      ,...\n"
            "    }\n"
			"3. minconf                 (numeric, optional, default=1) Only use the balance confirmed at least this many times.\n"
            "4. \"comment\"             (string, optional) A comment\n"
            "\nResult:\n"
            "\"transactionid\"          (string) The transaction id for the send. Only 1 transaction is created regardless of \n"
            "                                    the number of addresses.\n"
            "\nExamples:\n"
            "\nSend two amounts to two different addresses\identities:\n"
            + HelpExampleCli("identitypay", "\"myidentity\" \"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\\\":0.01,\\\"identity2\\\":0.02}\"") +
            "\nSend two amounts to two different addresses setting the comment:\n"
            + HelpExampleCli("identitypay", "\"myidentity\" \"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\\\":0.01,\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\":0.02}\" \"testing\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    string strFromIdentity = params[0].get_str();
	CIdentityIndex theIdentity;
	CTransaction identityTx;
	if (!GetTxOfIdentity(vchFromString(strFromIdentity), theIdentity, identityTx, true))
		throw JSONRPCError(RPC_TYPE_ERROR, "Invalid identity");
    UniValue sendTo = params[1].get_obj();
    int nMinDepth = 1;
    if (params.size() > 2)
        nMinDepth = params[2].get_int();
    CWalletTx wtx;
    if (params.size() > 3 && !params[3].isNull() && !params[3].get_str().empty())
        wtx.mapValue["comment"] = params[3].get_str();

    set<CDynamicAddress> setAddress;
    vector<CRecipient> vecSend;

    CAmount totalAmount = 0;
    vector<string> keys = sendTo.getKeys();
    BOOST_FOREACH(const string& name_, keys)
    {
        CDynamicAddress address(name_);
        if (!address.IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid Dynamic address: ")+name_);

        if (setAddress.count(address))
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+name_);
        setAddress.insert(address);

        CScript scriptPubKey = GetScriptForDestination(address.Get());
        CAmount nAmount = AmountFromValue(sendTo[name_]);
        if (nAmount <= 0)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
        totalAmount += nAmount;
        CRecipient recipient = {scriptPubKey, nAmount, false};
        vecSend.push_back(recipient);
    }

    EnsureWalletIsUnlocked();
    // Check funds
	UniValue balanceParams(UniValue::VARR);
	balanceParams.push_back(strFromIdentity);
	const UniValue &resBalance = tableRPC.execute("identitybalance", balanceParams);
	CAmount nBalance = AmountFromValue(resBalance);
    if (totalAmount > nBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Identity has insufficient funds");

    // Send
    CReserveKey keyChange(pwalletMain);
    CAmount nFeeRequired = 0;
    int nChangePosRet = -1;
    string strFailReason;

    bool fCreated = pwalletMain->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired, nChangePosRet,
												   strFailReason, NULL, true, ALL_COINS, false);
								
    if (!fCreated)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strFailReason);
    if (!pwalletMain->CommitTransaction(wtx, keyChange))
        throw JSONRPCError(RPC_WALLET_ERROR, "Transaction commit failed");

    return wtx.GetHash().GetHex();
}
