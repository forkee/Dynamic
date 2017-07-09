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

#include "cert.h"
#include "identity.h"
#include "offer.h"
#include "init.h"
#include "main.h"
#include "util.h"
#include "random.h"
#include "base58.h"
#include "core_io.h"
#include "rpcserver.h"
#include "wallet/wallet.h"
#include "chainparams.h"
#include "messagecrypter.h"

#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <boost/xpressive/xpressive_dynamic.hpp>
#include <boost/foreach.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/thread.hpp>
#include <boost/algorithm/string/predicate.hpp>

using namespace std;

extern void SendMoneyDynamic(const vector<CRecipient> &vecSend, CAmount nValue, bool fSubtractFeeFromAmount, CWalletTx& wtxNew, const CWalletTx* wtxInIdentity=NULL, int nTxOutIdentity = 0, bool dynamicMultiSigTx=false, const CCoinControl* coinControl=NULL, const CWalletTx* wtxInLinkIdentity=NULL,  int nTxOutLinkIdentity = 0);

bool EncryptMessage(const vector<unsigned char> &vchPubKey, const vector<unsigned char> &vchMessage, string &strCipherText)
{
	strCipherText.clear();
	CMessageCrypter crypter;
	if(!crypter.Encrypt(stringFromVch(vchPubKey), stringFromVch(vchMessage), strCipherText))
		return false;

	return true;
}
bool EncryptMessage(const CIdentityIndex& identity, const vector<unsigned char> &vchMessage, string &strCipherText)
{
	strCipherText.clear();
	CMessageCrypter crypter;
	if(!crypter.Encrypt(stringFromVch(identity.vchEncryptionPublicKey), stringFromVch(vchMessage), strCipherText))
		return false;

	return true;
}
bool DecryptPrivateKey(const vector<unsigned char> &vchPubKey, const vector<unsigned char> &vchCipherText, string &strMessage, const string &strPrivKey)
{
	strMessage.clear();
	std::vector<unsigned char> vchPrivateKey;
	CMessageCrypter crypter;
	// if priv key passed in try to use that, fallback to private key from wallet of pubkey passed in
	if(!strPrivKey.empty())
	{
		CDynamicSecret vchSecret;
		bool fGood = vchSecret.SetString(strPrivKey);
		if (!fGood) return false;
		CKey key = vchSecret.GetKey();
		vchPrivateKey = std::vector<unsigned char>(key.begin(), key.end());
		
		if(!crypter.Decrypt(stringFromVch(vchPrivateKey), stringFromVch(vchCipherText), strMessage))
		{
			// backup plan try to get priv key from pubkey in wallet
			CKey PrivateKey;
			CPubKey PubKey(vchPubKey);
			CKeyID pubKeyID = PubKey.GetID();
			if (!pwalletMain->GetKey(pubKeyID, PrivateKey))
				return false;
			CDynamicSecret Secret(PrivateKey);
			PrivateKey = Secret.GetKey();
			vchPrivateKey = std::vector<unsigned char>(PrivateKey.begin(), PrivateKey.end());
			strMessage.clear();
			if(!crypter.Decrypt(stringFromVch(vchPrivateKey), stringFromVch(vchCipherText), strMessage))
				return false;
		}
	}
	// otherwise try to get private key from wallet from pubkey passed in
	else
	{
		CKey PrivateKey;
		CPubKey PubKey(vchPubKey);
		CKeyID pubKeyID = PubKey.GetID();
		if (!pwalletMain->GetKey(pubKeyID, PrivateKey))
			return false;
		CDynamicSecret Secret(PrivateKey);
		PrivateKey = Secret.GetKey();
		vchPrivateKey = std::vector<unsigned char>(PrivateKey.begin(), PrivateKey.end());
		strMessage.clear();
		if(!crypter.Decrypt(stringFromVch(vchPrivateKey), stringFromVch(vchCipherText), strMessage))
			return false;
	}
	
	return true;
}
bool DecryptMessage(const CIdentityIndex& identity, const vector<unsigned char> &vchCipherText, string &strMessage, const string &strPrivKey)
{
	strMessage.clear();
	// get private key from identity or use one passed in to get the encryption private key
	string strKey = "";
	if(!identity.multiSigInfo.IsNull())
	{
		for(int i =0;i<identity.multiSigInfo.vchIdentityes.size();i++)
		{
			vector<CIdentityIndex> vtxPos;
			if (!pidentitydb->ReadIdentity(vchFromString(identity.multiSigInfo.vchIdentityes[i]), vtxPos) || vtxPos.empty())
				continue;
			if(DecryptPrivateKey(vtxPos.back().vchPubKey, vchFromString(identity.multiSigInfo.vchEncryptionPrivateKeys[i]), strKey, strPrivKey))
				break;
		}	
	}
	else
		DecryptPrivateKey(identity.vchPubKey, identity.vchEncryptionPrivateKey, strKey, strPrivKey);
	// use encryption private key to get data
	CMessageCrypter crypter;
	if(!crypter.Decrypt(strKey, stringFromVch(vchCipherText), strMessage))
		return false;
	
	return true;
}
void PutToCertList(std::vector<CCert> &certList, CCert& index) {
	int i = certList.size() - 1;
	BOOST_REVERSE_FOREACH(CCert &o, certList) {
        if(!o.txHash.IsNull() && o.txHash == index.txHash) {
        	certList[i] = index;
            return;
        }
        i--;
	}
    certList.push_back(index);
}
bool IsCertOp(int op) {
    return op == OP_CERT_ACTIVATE
        || op == OP_CERT_UPDATE
        || op == OP_CERT_TRANSFER;
}

uint64_t GetCertExpiration(const CCert& cert) {
	uint64_t nTime = chainActive.Tip()->nTime + 1;
	CIdentityUnprunable identityUnprunable;
	if (pidentitydb && pidentitydb->ReadIdentityUnprunable(cert.vchIdentity, identityUnprunable) && !identityUnprunable.IsNull())
		nTime = identityUnprunable.nExpireTime;
	
	return nTime;
}


string certFromOp(int op) {
    switch (op) {
    case OP_CERT_ACTIVATE:
        return "certactivate";
    case OP_CERT_UPDATE:
        return "certupdate";
    case OP_CERT_TRANSFER:
        return "certtransfer";
    default:
        return "<unknown cert op>";
    }
}
bool CCert::UnserializeFromData(const vector<unsigned char> &vchData, const vector<unsigned char> &vchHash) {
    try {
        CDataStream dsCert(vchData, SER_NETWORK, PROTOCOL_VERSION);
        dsCert >> *this;

		vector<unsigned char> vchCertData;
		Serialize(vchCertData);
		const uint256 &calculatedHash = Hash(vchCertData.begin(), vchCertData.end());
		const vector<unsigned char> &vchRandCert = vchFromValue(calculatedHash.GetHex());
		if(vchRandCert != vchHash)
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
bool CCert::UnserializeFromTx(const CTransaction &tx) {
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
void CCert::Serialize( vector<unsigned char> &vchData) {
    CDataStream dsCert(SER_NETWORK, PROTOCOL_VERSION);
    dsCert << *this;
	vchData = vector<unsigned char>(dsCert.begin(), dsCert.end());

}
bool CCertDB::CleanupDatabase(int &servicesCleaned)
{
	boost::scoped_ptr<CDBIterator> pcursor(NewIterator());
	pcursor->SeekToFirst();
	vector<CCert> vtxPos;
	pair<string, vector<unsigned char> > key;
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        try {
			if (pcursor->GetKey(key) && key.first == "certi") {
            	const vector<unsigned char> &vchMyCert= key.second;         
				pcursor->GetValue(vtxPos);	
				if (vtxPos.empty()){
					servicesCleaned++;
					EraseCert(vchMyCert);
					pcursor->Next();
					continue;
				}
				const CCert &txPos = vtxPos.back();
  				if (chainActive.Tip()->nTime >= GetCertExpiration(txPos))
				{
					servicesCleaned++;
					EraseCert(vchMyCert);
				} 
				
            }
            pcursor->Next();
        } catch (std::exception &e) {
            return error("%s() : deserialize error", __PRETTY_FUNCTION__);
        }
    }
	return true;
}
bool CCertDB::ScanCerts(const std::vector<unsigned char>& vchCert, const string &strRegexp, const vector<string>& identityArray, bool safeSearch, const string& strCategory, unsigned int nMax,
        std::vector<CCert>& certScan) {
    // regexp
    using namespace boost::xpressive;
    smatch certparts;
	string strRegexpLower = strRegexp;
	boost::algorithm::to_lower(strRegexpLower);
    sregex cregex = sregex::compile(strRegexpLower);
	vector<CCert> vtxPos;
	boost::scoped_ptr<CDBIterator> pcursor(NewIterator());
	if(!vchCert.empty())
		pcursor->Seek(make_pair(string("certi"), vchCert));
	else
		pcursor->SeekToFirst();
	pair<string, vector<unsigned char> > key;
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        try {
			if (pcursor->GetKey(key) && key.first == "certi") {
            	const vector<unsigned char> &vchMyCert = key.second;
                
				pcursor->GetValue(vtxPos);
				if (vtxPos.empty()){
					pcursor->Next();
					continue;
				}
				const CCert &txPos = vtxPos.back();
  				if (chainActive.Tip()->nTime >= GetCertExpiration(txPos))
				{
					pcursor->Next();
					continue;
				}


				if(strCategory.size() > 0 && !boost::algorithm::starts_with(stringFromVch(txPos.sCategory), strCategory))
				{
					pcursor->Next();
					continue;
				}
				if(identityArray.size() > 0)
				{
					if (std::find(identityArray.begin(), identityArray.end(), stringFromVch(txPos.vchIdentity)) == identityArray.end())
					{
						pcursor->Next();
						continue;
					}
				}
				else
				{
					if(txPos.safetyLevel >= SAFETY_LEVEL1)
					{
						if(safeSearch)
						{
							pcursor->Next();
							continue;
						}
						if(txPos.safetyLevel >= SAFETY_LEVEL2)
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
					CIdentityIndex theIdentity;
					CTransaction identitytx;
					if(!GetTxOfIdentity(txPos.vchIdentity, theIdentity, identitytx))
					{
						pcursor->Next();
						continue;
					}
					if(!theIdentity.safeSearch && safeSearch)
					{
						pcursor->Next();
						continue;
					}
					if((safeSearch && theIdentity.safetyLevel > txPos.safetyLevel) || (!safeSearch && theIdentity.safetyLevel > SAFETY_LEVEL1))
					{
						pcursor->Next();
						continue;
					}
					if(strRegexp != "")
					{
						const string &cert = stringFromVch(vchMyCert);
						string title = stringFromVch(txPos.vchTitle);
						boost::algorithm::to_lower(title);
						if (!regex_search(title, certparts, cregex) && strRegexp != cert && strRegexpLower != stringFromVch(txPos.vchIdentity))
						{
							pcursor->Next();
							continue;
						}
					}
				}
				certScan.push_back(txPos);
			}
			if (certScan.size() >= nMax)
				break;

			pcursor->Next();
        } catch (std::exception &e) {
            return error("%s() : deserialize error", __PRETTY_FUNCTION__);
        }
    }
    return true;
}

int IndexOfCertOutput(const CTransaction& tx) {
	if (tx.nVersion != DYNAMIC_TX_VERSION)
		return -1;
    vector<vector<unsigned char> > vvch;
	int op;
	for (unsigned int i = 0; i < tx.vout.size(); i++) {
		const CTxOut& out = tx.vout[i];
		// find an output you own
		if (pwalletMain->IsMine(out) && DecodeCertScript(out.scriptPubKey, op, vvch)) {
			return i;
		}
	}
	return -1;
}

bool GetTxOfCert(const vector<unsigned char> &vchCert,
        CCert& txPos, CTransaction& tx, bool skipExpiresCheck) {
    vector<CCert> vtxPos;
    if (!pcertdb->ReadCert(vchCert, vtxPos) || vtxPos.empty())
        return false;
    txPos = vtxPos.back();
    int nHeight = txPos.nHeight;
    if (!skipExpiresCheck && chainActive.Tip()->nTime >= GetCertExpiration(txPos)) {
        string cert = stringFromVch(vchCert);
        LogPrintf("GetTxOfCert(%s) : expired", cert.c_str());
        return false;
    }

    if (!GetDynamicTransaction(nHeight, txPos.txHash, tx, Params().GetConsensus()))
        return error("GetTxOfCert() : could not read tx from disk");

    return true;
}

bool GetTxAndVtxOfCert(const vector<unsigned char> &vchCert,
        CCert& txPos, CTransaction& tx,  vector<CCert> &vtxPos, bool skipExpiresCheck) {
    if (!pcertdb->ReadCert(vchCert, vtxPos) || vtxPos.empty())
        return false;
    txPos = vtxPos.back();
    int nHeight = txPos.nHeight;
    if (!skipExpiresCheck && chainActive.Tip()->nTime >= GetCertExpiration(txPos)) {
        string cert = stringFromVch(vchCert);
        LogPrintf("GetTxOfCert(%s) : expired", cert.c_str());
        return false;
    }

    if (!GetDynamicTransaction(nHeight, txPos.txHash, tx, Params().GetConsensus()))
        return error("GetTxOfCert() : could not read tx from disk");

    return true;
}
bool GetVtxOfCert(const vector<unsigned char> &vchCert,
        CCert& txPos, vector<CCert> &vtxPos, bool skipExpiresCheck) {
    if (!pcertdb->ReadCert(vchCert, vtxPos) || vtxPos.empty())
        return false;
    txPos = vtxPos.back();
    int nHeight = txPos.nHeight;
    if (!skipExpiresCheck && chainActive.Tip()->nTime >= GetCertExpiration(txPos)) {
        string cert = stringFromVch(vchCert);
        LogPrintf("GetTxOfCert(%s) : expired", cert.c_str());
        return false;
    }

    return true;
}
bool DecodeAndParseCertTx(const CTransaction& tx, int& op, int& nOut,
		vector<vector<unsigned char> >& vvch)
{
	CCert cert;
	bool decode = DecodeCertTx(tx, op, nOut, vvch);
	bool parse = cert.UnserializeFromTx(tx);
	return decode && parse;
}
bool DecodeCertTx(const CTransaction& tx, int& op, int& nOut,
        vector<vector<unsigned char> >& vvch) {
    bool found = false;


    // Strict check - bug disallowed
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& out = tx.vout[i];
        vector<vector<unsigned char> > vvchRead;
        if (DecodeCertScript(out.scriptPubKey, op, vvchRead)) {
            nOut = i; found = true; vvch = vvchRead;
            break;
        }
    }
    if (!found) vvch.clear();
    return found;
}


bool DecodeCertScript(const CScript& script, int& op,
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
	return found && IsCertOp(op);
}
bool DecodeCertScript(const CScript& script, int& op,
        vector<vector<unsigned char> > &vvch) {
    CScript::const_iterator pc = script.begin();
    return DecodeCertScript(script, op, vvch, pc);
}
bool RemoveCertScriptPrefix(const CScript& scriptIn, CScript& scriptOut) {
    int op;
    vector<vector<unsigned char> > vvch;
    CScript::const_iterator pc = scriptIn.begin();

    if (!DecodeCertScript(scriptIn, op, vvch, pc))
		return false;
	scriptOut = CScript(pc, scriptIn.end());
	return true;
}

bool CheckCertInputs(const CTransaction &tx, int op, int nOut, const vector<vector<unsigned char> > &vvchArgs,
        const CCoinsViewCache &inputs, bool fJustCheck, int nHeight, string &errorMessage, bool dontaddtodb) {
	if (tx.IsCoinBase() && !fJustCheck && !dontaddtodb)
	{
		LogPrintf("*Trying to add cert in coinbase transaction, skipping...");
		return true;
	}
	if (fDebug)
		LogPrintf("*** CERT %d %d %s %s\n", nHeight,
			chainActive.Tip()->nHeight, tx.GetHash().ToString().c_str(),
			fJustCheck ? "JUSTCHECK" : "BLOCK");
	bool foundIdentity = false;
    const COutPoint *prevOutput = NULL;
    const CCoins *prevCoins;

	int prevIdentityOp = 0;
    // Make sure cert outputs are not spent by a regular transaction, or the cert would be lost
	if (tx.nVersion != DYNAMIC_TX_VERSION) 
	{
		errorMessage = "DYNAMIC_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2000 - " + _("Non-Dynamic transaction found");
		return true;
	}
	vector<vector<unsigned char> > vvchPrevIdentityArgs;
	// unserialize cert from txn, check for valid
	CCert theCert;
	vector<unsigned char> vchData;
	vector<unsigned char> vchHash;
	int nDataOut;
	if(!GetDynamicData(tx, vchData, vchHash, nDataOut) || !theCert.UnserializeFromData(vchData, vchHash))
	{
		errorMessage = "DYNAMIC_CERTIFICATE_CONSENSUS_ERROR ERRCODE: 2001 - " + _("Cannot unserialize data inside of this transaction relating to a certificate");
		return true;
	}

	if(fJustCheck)
	{
		if(vvchArgs.size() != 2)
		{
			errorMessage = "DYNAMIC_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2002 - " + _("Certificate arguments incorrect size");
			return error(errorMessage.c_str());
		}

					
		if(vvchArgs.size() <= 1 || vchHash != vvchArgs[1])
		{
			errorMessage = "DYNAMIC_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2003 - " + _("Hash provided doesn't match the calculated hash of the data");
			return true;
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
			if(foundIdentity)
				break;
			else if (!foundIdentity && IsIdentityOp(pop))
			{
				foundIdentity = true; 
				prevIdentityOp = pop;
				vvchPrevIdentityArgs = vvch;
			}
		}
	}


	
	CIdentityIndex identity;
	CTransaction identityTx;
	vector<CCert> vtxPos;
	string retError = "";
	if(fJustCheck)
	{
		if (vvchArgs.empty() ||  vvchArgs[0].size() > MAX_GUID_LENGTH)
		{
			errorMessage = "DYNAMIC_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2004 - " + _("Certificate hex guid too long");
			return error(errorMessage.c_str());
		}
		if(theCert.sCategory.size() > MAX_NAME_LENGTH)
		{
			errorMessage = "DYNAMIC_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2005 - " + _("Certificate category too big");
			return error(errorMessage.c_str());
		}
		if(theCert.vchData.size() > MAX_ENCRYPTED_VALUE_LENGTH)
		{
			errorMessage = "DYNAMIC_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2006 - " + _("Certificate private data too big");
			return error(errorMessage.c_str());
		}
		if(theCert.vchPubData.size() > MAX_VALUE_LENGTH)
		{
			errorMessage = "DYNAMIC_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2007 - " + _("Certificate public data too big");
			return error(errorMessage.c_str());
		}
		if(!theCert.vchCert.empty() && theCert.vchCert != vvchArgs[0])
		{
			errorMessage = "DYNAMIC_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2008 - " + _("Guid in data output doesn't match guid in transaction");
			return error(errorMessage.c_str());
		}
		switch (op) {
		case OP_CERT_ACTIVATE:
			if (theCert.vchCert != vvchArgs[0])
			{
				errorMessage = "DYNAMIC_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2009 - " + _("Certificate guid mismatch");
				return error(errorMessage.c_str());
			}
			if(!theCert.vchLinkIdentity.empty())
			{
				errorMessage = "DYNAMIC_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2010 - " + _("Certificate linked identity not allowed in activate");
				return error(errorMessage.c_str());
			}
			if(!IsIdentityOp(prevIdentityOp) || vvchPrevIdentityArgs.empty() || theCert.vchIdentity != vvchPrevIdentityArgs[0])
			{
				errorMessage = "DYNAMIC_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2011 - " + _("Identity input mismatch");
				return error(errorMessage.c_str());
			}
			if((theCert.vchTitle.size() > MAX_NAME_LENGTH || theCert.vchTitle.empty()))
			{
				errorMessage = "DYNAMIC_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2012 - " + _("Certificate title too big or is empty");
				return error(errorMessage.c_str());
			}
			if(!boost::algorithm::starts_with(stringFromVch(theCert.sCategory), "certificates"))
			{
				errorMessage = "DYNAMIC_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2013 - " + _("Must use a certificate category");
				return true;
			}
			break;

		case OP_CERT_UPDATE:
			if (theCert.vchCert != vvchArgs[0])
			{
				errorMessage = "DYNAMIC_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2014 - " + _("Certificate guid mismatch");
				return error(errorMessage.c_str());
			}
			if(theCert.vchTitle.size() > MAX_NAME_LENGTH)
			{
				errorMessage = "DYNAMIC_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2015 - " + _("Certificate title too big");
				return error(errorMessage.c_str());
			}
			if(!IsIdentityOp(prevIdentityOp) || vvchPrevIdentityArgs.empty() || theCert.vchIdentity != vvchPrevIdentityArgs[0])
			{
				errorMessage = "DYNAMIC_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2016 - " + _("Identity input mismatch");
				return error(errorMessage.c_str());
			}
			if(theCert.sCategory.size() > 0 && !boost::algorithm::starts_with(stringFromVch(theCert.sCategory), "certificates"))
			{
				errorMessage = "DYNAMIC_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2017 - " + _("Must use a certificate category");
				return true;
			}
			break;

		case OP_CERT_TRANSFER:
			if (theCert.vchCert != vvchArgs[0])
			{
				errorMessage = "DYNAMIC_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2018 - " + _("Certificate guid mismatch");
				return error(errorMessage.c_str());
			}
			if(!IsIdentityOp(prevIdentityOp) || vvchPrevIdentityArgs.empty() || theCert.vchIdentity != vvchPrevIdentityArgs[0])
			{
				errorMessage = "DYNAMIC_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2019 - " + _("Identity input mismatch");
				return error(errorMessage.c_str());
			}
			if(theCert.sCategory.size() > 0 && !boost::algorithm::starts_with(stringFromVch(theCert.sCategory), "certificates"))
			{
				errorMessage = "DYNAMIC_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2020 - " + _("Must use a certificate category");
				return true;
			}
			break;

		default:
			errorMessage = "DYNAMIC_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2021 - " + _("Certificate transaction has unknown op");
			return error(errorMessage.c_str());
		}
	}

    if (!fJustCheck ) {
		if(op != OP_CERT_ACTIVATE) 
		{
			// if not an certnew, load the cert data from the DB
			CCert dbCert;
			if(!GetVtxOfCert(vvchArgs[0], dbCert, vtxPos))	
			{
				errorMessage = "DYNAMIC_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2022 - " + _("Failed to read from certificate DB");
				return true;
			}
			if(theCert.vchData.empty())
				theCert.vchData = dbCert.vchData;
			if(theCert.vchPubData.empty())
				theCert.vchPubData = dbCert.vchPubData;
			if(theCert.vchTitle.empty())
				theCert.vchTitle = dbCert.vchTitle;
			if(theCert.sCategory.empty())
				theCert.sCategory = dbCert.sCategory;

			// user can't update safety level after creation
			theCert.safetyLevel = dbCert.safetyLevel;
			theCert.vchCert = dbCert.vchCert;
			if(theCert.vchIdentity != dbCert.vchIdentity)
			{
				errorMessage = "DYNAMIC_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2023 - " + _("Wrong identity input provided in this certificate transaction");
				theCert.vchIdentity = dbCert.vchIdentity;
			}
			else if(!theCert.vchLinkIdentity.empty())
				theCert.vchIdentity = theCert.vchLinkIdentity;

			if(op == OP_CERT_TRANSFER)
			{
				vector<CIdentityIndex> vtxIdentity;
				bool isExpired = false;
				// check toidentity
				if(!GetVtxOfIdentity(theCert.vchLinkIdentity, identity, vtxIdentity, isExpired))
				{
					errorMessage = "DYNAMIC_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2024 - " + _("Cannot find identity you are transferring to. It may be expired");		
				}
				else
				{
							
					if(!identity.acceptCertTransfers)
					{
						errorMessage = "DYNAMIC_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2025 - " + _("The identity you are transferring to does not accept certificate transfers");
						theCert = dbCert;	
					}
				}
			}
			else
			{
				theCert.bTransferViewOnly = dbCert.bTransferViewOnly;
			}
			theCert.vchLinkIdentity.clear();
			if(dbCert.bTransferViewOnly)
			{
				errorMessage = "DYNAMIC_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2026 - " + _("Cannot edit or transfer this certificate. It is view-only.");
				theCert = dbCert;
			}
		}
		else
		{
			if (pcertdb->ExistsCert(vvchArgs[0]))
			{
				errorMessage = "DYNAMIC_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2027 - " + _("Certificate already exists");
				return true;
			}
		}
        // set the cert's txn-dependent values
		theCert.nHeight = nHeight;
		theCert.txHash = tx.GetHash();
		PutToCertList(vtxPos, theCert);
        // write cert  

        if (!dontaddtodb && !pcertdb->WriteCert(vvchArgs[0], vtxPos))
		{
			errorMessage = "DYNAMIC_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2028 - " + _("Failed to write to certifcate DB");
            return error(errorMessage.c_str());
		}
		

      			
        // debug
		if(fDebug)
			LogPrintf( "CONNECTED CERT: op=%s cert=%s title=%s hash=%s height=%d\n",
                certFromOp(op).c_str(),
                stringFromVch(vvchArgs[0]).c_str(),
                stringFromVch(theCert.vchTitle).c_str(),
                tx.GetHash().ToString().c_str(),
                nHeight);
    }
    return true;
}





UniValue certnew(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() < 4 || params.size() > 6)
        throw runtime_error(
		"certnew <identity> <title> <private> <public> [safe search=Yes] [category=certificates]\n"
						"<identity> An identity you own.\n"
                        "<title> title, 256 characters max.\n"
						"<private> private data, 1024 characters max.\n"
                        "<public> public data, 1024 characters max.\n"
 						"<safe search> set to No if this cert should only show in the search when safe search is not selected. Defaults to Yes (cert shows with or without safe search selected in search lists).\n"                     
						"<category> category, 25 characters max. Defaults to certificates\n"
						+ HelpRequiringPassphrase());
	vector<unsigned char> vchIdentity = vchFromValue(params[0]);
	vector<unsigned char> vchTitle = vchFromString(params[1].get_str());
    vector<unsigned char> vchData = vchFromString(params[2].get_str());
	vector<unsigned char> vchPubData = vchFromString(params[3].get_str());
	vector<unsigned char> vchCat = vchFromString("certificates");
	// check for identity existence in DB
	CTransaction identitytx;
	CIdentityIndex theIdentity;
	const CWalletTx *wtxIdentityIn = NULL;
	if (!GetTxOfIdentity(vchIdentity, theIdentity, identitytx))
		throw runtime_error("DYNAMIC_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2500 - " + _("failed to read identity from identity DB"));

	if(!IsMyIdentity(theIdentity)) {
		throw runtime_error("DYNAMIC_CERTIFICATE_CONSENSUS_ERROR ERRCODE: 2501 - " + _("This identity is not yours"));
	}
	COutPoint outPoint;
	int numResults  = identityunspent(vchIdentity, outPoint);
	wtxIdentityIn = pwalletMain->GetWalletTx(outPoint.hash);
	if (wtxIdentityIn == NULL)
		throw runtime_error("DYNAMIC_CERTIFICATE_CONSENSUS_ERROR ERRCODE: 2502 - " + _("This identity is not in your wallet"));


	if(params.size() >= 6)
		vchCat = vchFromValue(params[5]);


	string strSafeSearch = "Yes";
	if(params.size() >= 5)
	{
		strSafeSearch = params[4].get_str();
	}
    if (vchData.size() < 1)
        vchData = vchFromString(" ");
	
    // gather inputs
	vector<unsigned char> vchCert = vchFromString(GenerateDynamicGuid());
    // this is a dynamic transaction
    CWalletTx wtx;

	EnsureWalletIsUnlocked();
    CScript scriptPubKeyOrig;
	CDynamicAddress identityAddress;
	GetAddress(theIdentity, &identityAddress, scriptPubKeyOrig);


    CScript scriptPubKey,scriptPubKeyIdentity;
	if(!vchData.empty())
	{
		string strCipherText;
		if(!EncryptMessage(theIdentity, vchData, strCipherText))
		{
			throw runtime_error("DYNAMIC_CERTIFICATE_RPC_ERROR: ERRCODE: 2503 - " + _("Could not encrypt certificate data"));
		}	
		vchData = vchFromString(strCipherText);	
	}

	// calculate net
    // build cert object
    CCert newCert;
	newCert.vchCert = vchCert;
	newCert.sCategory = vchCat;
    newCert.vchTitle = vchTitle;
	newCert.vchData = vchData;
	newCert.vchPubData = vchPubData;
	newCert.nHeight = chainActive.Tip()->nHeight;
	newCert.vchIdentity = vchIdentity;
	newCert.safetyLevel = 0;
	newCert.safeSearch = strSafeSearch == "Yes"? true: false;


	vector<unsigned char> data;
	newCert.Serialize(data);
    uint256 hash = Hash(data.begin(), data.end());
 	
    vector<unsigned char> vchHashCert = vchFromValue(hash.GetHex());

    scriptPubKey << CScript::EncodeOP_N(OP_CERT_ACTIVATE) << vchCert << vchHashCert << OP_2DROP << OP_DROP;
    scriptPubKey += scriptPubKeyOrig;
	scriptPubKeyIdentity << CScript::EncodeOP_N(OP_IDENTITY_UPDATE) << theIdentity.vchIdentity << theIdentity.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
	scriptPubKeyIdentity += scriptPubKeyOrig;

	// use the script pub key to create the vecsend which sendmoney takes and puts it into vout
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
	CreateFeeRecipient(scriptData, theIdentity.vchIdentityPeg, chainActive.Tip()->nHeight, data, fee);
	vecSend.push_back(fee);

	
	
	
	SendMoneyDynamic(vecSend, recipient.nAmount+fee.nAmount+identityRecipient.nAmount, false, wtx, wtxIdentityIn, outPoint.n, theIdentity.multiSigInfo.vchIdentityes.size() > 0);
	UniValue res(UniValue::VARR);
	if(theIdentity.multiSigInfo.vchIdentityes.size() > 0)
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
			res.push_back(stringFromVch(vchCert));
		}
		else
		{
			res.push_back(hex_str);
			res.push_back(stringFromVch(vchCert));
			res.push_back("false");
		}
	}
	else
	{
		res.push_back(wtx.GetHash().GetHex());
		res.push_back(stringFromVch(vchCert));
	}
	return res;
}

UniValue certupdate(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() < 5 || params.size() > 7)
        throw runtime_error(
		"certupdate <guid> <identity> <title> <private> <public> [safesearch=Yes] [category=certificates]\n"
                        "Perform an update on an certificate you control.\n"
                        "<guid> certificate guidkey.\n"
						"<identity> an identity you own to associate with this certificate.\n"
                        "<title> certificate title, 256 characters max.\n"
                        "<private> private certificate data, 1024 characters max.\n"
						"<public> public certificate data, 1024 characters max.\n"
						"<safe search> set to No if this cert should only show in the search when safe search is not selected. Defaults to Yes (cert shows with or without safe search selected in search lists).\n"                     
						"<category> category, 256 characters max. Defaults to certificates\n"
                        + HelpRequiringPassphrase());
    // gather & validate inputs
    vector<unsigned char> vchCert = vchFromValue(params[0]);
	vector<unsigned char> vchIdentity = vchFromValue(params[1]);
    vector<unsigned char> vchTitle = vchFromValue(params[2]);
    vector<unsigned char> vchData = vchFromValue(params[3]);
	vector<unsigned char> vchPubData = vchFromValue(params[4]);
	vector<unsigned char> vchCat = vchFromString("certificates");
	if(params.size() >= 7)
		vchCat = vchFromValue(params[6]);

	string strSafeSearch = "Yes";
	if(params.size() >= 6)
	{
		strSafeSearch = params[5].get_str();
	}

    if (vchData.size() < 1)
        vchData = vchFromString(" ");
    // this is a dynamicd txn
    CWalletTx wtx;
    CScript scriptPubKeyOrig;

    EnsureWalletIsUnlocked();

    // look for a transaction with this key
    CTransaction tx;
	CCert theCert;
	
    if (!GetTxOfCert( vchCert, theCert, tx))
        throw runtime_error("DYNAMIC_CERTIFICATE_RPC_ERROR: ERRCODE: 2504 - " + _("Could not find a certificate with this key"));

	CTransaction identitytx;
	CIdentityIndex theIdentity;
	const CWalletTx *wtxIdentityIn = NULL;
	if (!GetTxOfIdentity(theCert.vchIdentity, theIdentity, identitytx))
		throw runtime_error("DYNAMIC_CERTIFICATE_CONSENSUS_ERROR: ERRCODE: 2505 - " + _("Failed to read identity from identity DB"));
	if(!IsMyIdentity(theIdentity)) {
		throw runtime_error("DYNAMIC_CERTIFICATE_RPC_ERROR ERRCODE: 2506 - " + _("This identity is not yours"));
	}
	COutPoint outPoint;
	int numResults  = identityunspent(theCert.vchIdentity, outPoint);
	wtxIdentityIn = pwalletMain->GetWalletTx(outPoint.hash);
	if (wtxIdentityIn == NULL)
		throw runtime_error("DYNAMIC_CERTIFICATE_RPC_ERROR ERRCODE: 2507 - " + _("This identity is not in your wallet"));

	CCert copyCert = theCert;
	theCert.ClearCert();
	CDynamicAddress identityAddress;
	GetAddress(theIdentity, &identityAddress, scriptPubKeyOrig);

    // create CERTUPDATE txn keys
    CScript scriptPubKey;
	// if we want to make data private, encrypt it
	if(!vchData.empty())
	{
		string strCipherText;
		if(!EncryptMessage(theIdentity, vchData, strCipherText))
		{
			throw runtime_error("DYNAMIC_CERTIFICATE_RPC_ERROR: ERRCODE: 2508 - " + _("Could not encrypt certificate data"));
		}
		// decrypt old identity data if private
		// detect if data payload changed
		if(!copyCert.vchData.empty() && copyCert.vchIdentity == vchIdentity)
		{
			string strDecryptedText = "";
			if(DecryptMessage(theIdentity, copyCert.vchData, strDecryptedText))
			{
				if(vchData == vchFromString(strDecryptedText))
					vchData = copyCert.vchData;
				else
					vchData = vchFromString(strCipherText);
			}
			else
				vchData = vchFromString(strCipherText);
		}
		else
			vchData = vchFromString(strCipherText);
	}


    if(copyCert.vchTitle != vchTitle)
		theCert.vchTitle = vchTitle;
	if(copyCert.vchData != vchData)
		theCert.vchData = vchData;
	if(copyCert.vchPubData != vchPubData)
		theCert.vchPubData = vchPubData;
	if(copyCert.sCategory != vchCat)
		theCert.sCategory = vchCat;
	theCert.vchIdentity = theIdentity.vchIdentity;
	if(!vchIdentity.empty() && vchIdentity != theIdentity.vchIdentity)
		theCert.vchLinkIdentity = vchIdentity;
	theCert.nHeight = chainActive.Tip()->nHeight;
	theCert.safeSearch = strSafeSearch == "Yes"? true: false;

	vector<unsigned char> data;
	theCert.Serialize(data);
    uint256 hash = Hash(data.begin(), data.end());
 	
    vector<unsigned char> vchHashCert = vchFromValue(hash.GetHex());
    scriptPubKey << CScript::EncodeOP_N(OP_CERT_UPDATE) << vchCert << vchHashCert << OP_2DROP << OP_DROP;
    scriptPubKey += scriptPubKeyOrig;

	vector<CRecipient> vecSend;
	CRecipient recipient;
	CreateRecipient(scriptPubKey, recipient);
	vecSend.push_back(recipient);
	CScript scriptPubKeyIdentity;
	scriptPubKeyIdentity << CScript::EncodeOP_N(OP_IDENTITY_UPDATE) << theIdentity.vchIdentity << theIdentity.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
	scriptPubKeyIdentity += scriptPubKeyOrig;
	CRecipient identityRecipient;
	CreateRecipient(scriptPubKeyIdentity, identityRecipient);
	for(unsigned int i =numResults;i<=MAX_IDENTITY_UPDATES_PER_BLOCK;i++)
		vecSend.push_back(identityRecipient);
	
	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, theIdentity.vchIdentityPeg, chainActive.Tip()->nHeight, data, fee);
	vecSend.push_back(fee);
	
	
	
	SendMoneyDynamic(vecSend, recipient.nAmount+identityRecipient.nAmount+fee.nAmount, false, wtx, wtxIdentityIn, outPoint.n, theIdentity.multiSigInfo.vchIdentityes.size() > 0);	
 	UniValue res(UniValue::VARR);
	if(theIdentity.multiSigInfo.vchIdentityes.size() > 0)
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
	{
		res.push_back(wtx.GetHash().GetHex());
	}
	return res;
}


UniValue certtransfer(const UniValue& params, bool fHelp) {
 if (fHelp || params.size() < 2 || params.size() > 3)
        throw runtime_error(
		"certtransfer <certkey> <identity> [viewonly=0]\n"
                "<certkey> certificate guidkey.\n"
				"<identity> Identity to transfer this certificate to.\n"
				"<viewonly> Transfer the certificate as view-only. Recipient cannot edit, transfer or sell this certificate in the future.\n"
                 + HelpRequiringPassphrase());

    // gather & validate inputs
	bool bViewOnly = false;
	vector<unsigned char> vchCert = vchFromValue(params[0]);
	vector<unsigned char> vchIdentity = vchFromValue(params[1]);
	if(params.size() >= 3)
		bViewOnly = params[2].get_str() == "1"? true: false;
	// check for identity existence in DB
	CTransaction tx;
	CIdentityIndex toIdentity;
	if (!GetTxOfIdentity(vchIdentity, toIdentity, tx))
		throw runtime_error("DYNAMIC_CERTIFICATE_RPC_ERROR: ERRCODE: 2509 - " + _("Failed to read transfer identity from DB"));

    // this is a dynamic txn
    CWalletTx wtx;
    CScript scriptPubKeyOrig, scriptPubKeyFromOrig;

    EnsureWalletIsUnlocked();
    CTransaction identitytx;
	CCert theCert;
    if (!GetTxOfCert( vchCert, theCert, tx))
        throw runtime_error("DYNAMIC_CERTIFICATE_RPC_ERROR: ERRCODE: 2510 - " + _("Could not find a certificate with this key"));

	CIdentityIndex fromIdentity;
	const CWalletTx *wtxIdentityIn = NULL;
	if(!GetTxOfIdentity(theCert.vchIdentity, fromIdentity, identitytx))
	{
		 throw runtime_error("DYNAMIC_CERTIFICATE_RPC_ERROR: ERRCODE: 2511 - " + _("Could not find the certificate identity"));
	}
	if(!IsMyIdentity(fromIdentity)) {
		throw runtime_error("DYNAMIC_CERTIFICATE_RPC_ERROR ERRCODE: 2512 - " + _("This identity is not yours"));
	}
	COutPoint outPoint;
	int numResults  = identityunspent(theCert.vchIdentity, outPoint);
	wtxIdentityIn = pwalletMain->GetWalletTx(outPoint.hash);
	if (wtxIdentityIn == NULL)
		throw runtime_error("DYNAMIC_CERTIFICATE_RPC_ERROR ERRCODE: 2513 - " + _("This identity is not in your wallet"));

	// if cert is private, decrypt the data
	vector<unsigned char> vchData = theCert.vchData;
	if(!theCert.vchData.empty())
	{		
		string strData = "";
		string strCipherText = "";
		
		// decrypt using old key
		if(DecryptMessage(fromIdentity, theCert.vchData, strData))
		{
			// encrypt using new key
			if(!EncryptMessage(toIdentity, vchFromString(strData), strCipherText))
			{
				throw runtime_error("DYNAMIC_CERTIFICATE_RPC_ERROR: ERRCODE: 2514 - " + _("Could not encrypt certificate data"));
			}
			vchData = vchFromString(strCipherText);
		}
		else
			vchData = theCert.vchData;	
	}	
	CDynamicAddress sendAddr;
	GetAddress(toIdentity, &sendAddr, scriptPubKeyOrig);
	CDynamicAddress fromAddr;
	GetAddress(fromIdentity, &fromAddr, scriptPubKeyFromOrig);

	CCert copyCert = theCert;
	theCert.ClearCert();
    CScript scriptPubKey;
	theCert.nHeight = chainActive.Tip()->nHeight;
	theCert.vchIdentity = fromIdentity.vchIdentity;
	theCert.vchLinkIdentity = toIdentity.vchIdentity;
	theCert.safeSearch = copyCert.safeSearch;
	theCert.safetyLevel = copyCert.safetyLevel;
	theCert.bTransferViewOnly = bViewOnly;
	theCert.vchData = vchData;

	vector<unsigned char> data;
	theCert.Serialize(data);
    uint256 hash = Hash(data.begin(), data.end());
 	
    vector<unsigned char> vchHashCert = vchFromValue(hash.GetHex());
    scriptPubKey << CScript::EncodeOP_N(OP_CERT_TRANSFER) << vchCert << vchHashCert << OP_2DROP << OP_DROP;
	scriptPubKey += scriptPubKeyOrig;
    // send the cert pay txn
	vector<CRecipient> vecSend;
	CRecipient recipient;
	CreateRecipient(scriptPubKey, recipient);
	vecSend.push_back(recipient);

	CScript scriptPubKeyIdentity;
	scriptPubKeyIdentity << CScript::EncodeOP_N(OP_IDENTITY_UPDATE) << fromIdentity.vchIdentity << fromIdentity.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
	scriptPubKeyIdentity += scriptPubKeyFromOrig;
	CRecipient identityRecipient;
	CreateRecipient(scriptPubKeyIdentity, identityRecipient);
	for(unsigned int i =numResults;i<=MAX_IDENTITY_UPDATES_PER_BLOCK;i++)
		vecSend.push_back(identityRecipient);

	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, fromIdentity.vchIdentityPeg, chainActive.Tip()->nHeight, data, fee);
	vecSend.push_back(fee);
	
	
	
	SendMoneyDynamic(vecSend, recipient.nAmount+identityRecipient.nAmount+fee.nAmount, false, wtx, wtxIdentityIn, outPoint.n, fromIdentity.multiSigInfo.vchIdentityes.size() > 0);

	UniValue res(UniValue::VARR);
	if(fromIdentity.multiSigInfo.vchIdentityes.size() > 0)
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
	{
		res.push_back(wtx.GetHash().GetHex());
	}
	return res;
}


UniValue certinfo(const UniValue& params, bool fHelp) {
    if (fHelp || 1 != params.size())
        throw runtime_error("certinfo <guid>\n"
                "Show stored values of a single certificate and its .\n");

    vector<unsigned char> vchCert = vchFromValue(params[0]);

	vector<CCert> vtxPos;

	UniValue oCert(UniValue::VOBJ);
    vector<unsigned char> vchValue;

	if (!pcertdb->ReadCert(vchCert, vtxPos) || vtxPos.empty())
		throw runtime_error("DYNAMIC_CERTIFICATE_RPC_ERROR: ERRCODE: 2515 - " + _("Failed to read from cert DB"));

	CIdentityIndex identity;
	CTransaction identitytx;
	if (!GetTxOfIdentity(vtxPos.back().vchIdentity, identity, identitytx, true))
		throw runtime_error("DYNAMIC_CERTIFICATE_RPC_ERROR: ERRCODE: 2516 - " + _("Failed to read xfer identity from identity DB"));

	if(!BuildCertJson(vtxPos.back(), identity, oCert))
		oCert.clear();
    return oCert;
}

UniValue certlist(const UniValue& params, bool fHelp) {
    if (fHelp || 3 < params.size())
        throw runtime_error("certlist [\"identity\",...] [<cert>] [<privatekey>]\n"
                "list certificates that an array of identities own. Set of identities to look up based on identity, and private key to decrypt any data found in certificates.");
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
	vector<CCert> certScan;
	if(identities.size() > 0)
	{
		if (!pcertdb->ScanCerts(vchNameUniq, "", identities, true, "", 1000,certScan))
			throw runtime_error("DYNAMIC_CERTIFICATE_RPC_ERROR: ERRCODE: 2517 - " + _("Scan failed"));
	}
	CTransaction identitytx;
	BOOST_FOREACH(const CCert& cert, certScan) {
		vector<CIdentityIndex> vtxPos;
		if (!pidentitydb->ReadIdentity(cert.vchIdentity, vtxPos) || vtxPos.empty())
			continue;
		const CIdentityIndex &identity = vtxPos.back();
		UniValue oCert(UniValue::VOBJ);
		if(BuildCertJson(cert, identity, oCert, strPrivateKey))
			oRes.push_back(oCert);
	}
    return oRes;
}
bool BuildCertJson(const CCert& cert, const CIdentityIndex& identity, UniValue& oCert, const string &strPrivKey)
{
	if(cert.safetyLevel >= SAFETY_LEVEL2)
		return false;
	if(identity.safetyLevel >= SAFETY_LEVEL2)
		return false;
	string sHeight = strprintf("%llu", cert.nHeight);
    oCert.push_back(Pair("cert", stringFromVch(cert.vchCert)));
    oCert.push_back(Pair("txid", cert.txHash.GetHex()));
    oCert.push_back(Pair("height", sHeight));
    oCert.push_back(Pair("title", stringFromVch(cert.vchTitle)));
	string sTime;
	CBlockIndex *pindex = chainActive[cert.nHeight];
	if (pindex) {
		sTime = strprintf("%llu", pindex->nTime);
	}
	oCert.push_back(Pair("time", sTime));
	string strData = stringFromVch(cert.vchData);
	string strDecrypted = "";
	if(!cert.vchData.empty())
	{
		strData = _("Encrypted for owner of certificate private data");
		if(!cert.vchData.empty() && strDecrypted == "")
		{
			if(DecryptMessage(identity, cert.vchData, strDecrypted, strPrivKey))
				strData = strDecrypted;		
		}
	}
    oCert.push_back(Pair("data", strData));
	oCert.push_back(Pair("pubdata", stringFromVch(cert.vchPubData)));
	oCert.push_back(Pair("category", stringFromVch(cert.sCategory)));
	oCert.push_back(Pair("safesearch", cert.safeSearch? "Yes" : "No"));
	unsigned char safetyLevel = max(cert.safetyLevel, identity.safetyLevel );
	oCert.push_back(Pair("safetylevel", safetyLevel));

    oCert.push_back(Pair("ismine", IsMyIdentity(identity) ? "true" : "false"));

	oCert.push_back(Pair("identity", stringFromVch(cert.vchIdentity)));
	oCert.push_back(Pair("transferviewonly", cert.bTransferViewOnly? "true": "false"));
	int64_t expired_time = GetCertExpiration(cert);
	int expired = 0;
    if(expired_time <= chainActive.Tip()->nTime)
	{
		expired = 1;
	}  
	int64_t expires_in = expired_time - chainActive.Tip()->nTime;
	if(expires_in < -1)
		expires_in = -1;

	oCert.push_back(Pair("expires_in", expires_in));
	oCert.push_back(Pair("expires_on", expired_time));
	oCert.push_back(Pair("expired", expired));
	return true;
}

UniValue certhistory(const UniValue& params, bool fHelp) {
    if (fHelp || 1 != params.size())
        throw runtime_error("certhistory <cert>\n"
                "List all stored values of an cert.\n");

    UniValue oRes(UniValue::VARR);
    vector<unsigned char> vchCert = vchFromValue(params[0]);
 
    vector<CCert> vtxPos;
    if (!pcertdb->ReadCert(vchCert, vtxPos) || vtxPos.empty())
		throw runtime_error("DYNAMIC_CERTIFICATE_RPC_ERROR: ERRCODE: 2518 - " + _("Failed to read from cert DB"));

	vector<CIdentityIndex> vtxIdentityPos;
	if (!pidentitydb->ReadIdentity(vtxPos.back().vchIdentity, vtxIdentityPos) || vtxIdentityPos.empty())
		throw runtime_error("DYNAMIC_CERTIFICATE_RPC_ERROR: ERRCODE: 2519 - " + _("Failed to read from identity DB"));
	
    CCert txPos2;
	CIdentityIndex identity;
	CTransaction tx;
	vector<vector<unsigned char> > vvch;
	int op, nOut;
    BOOST_FOREACH(txPos2, vtxPos) {
		vector<CIdentityIndex> vtxIdentityPos;
		if(!pidentitydb->ReadIdentity(txPos2.vchIdentity, vtxIdentityPos) || vtxIdentityPos.empty())
			continue;
		if (!GetDynamicTransaction(txPos2.nHeight, txPos2.txHash, tx, Params().GetConsensus())) {
			continue;
		}
		if (!DecodeCertTx(tx, op, nOut, vvch) )
			continue;

		identity.nHeight = txPos2.nHeight;
		identity.GetIdentityFromList(vtxIdentityPos);

		UniValue oCert(UniValue::VOBJ);
		string opName = certFromOp(op);
		oCert.push_back(Pair("certtype", opName));
		if(BuildCertJson(txPos2, identity, oCert))
			oRes.push_back(oCert);
    }
    
    return oRes;
}
UniValue certfilter(const UniValue& params, bool fHelp) {
	if (fHelp || params.size() > 4)
		throw runtime_error(
				"certfilter [[[[[regexp]] from=0]] safesearch='Yes' category]\n"
						"scan and filter certs\n"
						"[regexp] : apply [regexp] on certs, empty means all certs\n"
						"[from] : show results from this GUID [from], 0 means first.\n"
						"[certfilter] : shows all certs that are safe to display (not on the ban list)\n"
						"[safesearch] : shows all certs that are safe to display (not on the ban list)\n"
						"[category] : category you want to search in, empty for all\n"
						"certfilter \"\" 5 # list certs updated in last 5 blocks\n"
						"certfilter \"^cert\" # list all certs starting with \"cert\"\n"
						"certfilter 36000 0 0 stat # display stats (number of certs) on active certs\n");

	vector<unsigned char> vchCert;
	string strRegexp;
	string strCategory;
	bool safeSearch = true;


	if (params.size() > 0)
		strRegexp = params[0].get_str();

	if (params.size() > 1)
		vchCert = vchFromValue(params[1]);

	if (params.size() > 2)
		safeSearch = params[2].get_str()=="On"? true: false;

	if (params.size() > 3)
		strCategory = params[3].get_str();

    UniValue oRes(UniValue::VARR);
    
    vector<CCert> certScan;
	vector<string> identities;
    if (!pcertdb->ScanCerts(vchCert, strRegexp, identities, safeSearch, strCategory, 25, certScan))
		throw runtime_error("DYNAMIC_CERTIFICATE_RPC_ERROR: ERRCODE: 2520 - " + _("Scan failed"));
  
	CTransaction identitytx;
	uint256 txHash;
	BOOST_FOREACH(const CCert &txCert, certScan) {
		vector<CIdentityIndex> vtxIdentityPos;
		if(!pidentitydb->ReadIdentity(txCert.vchIdentity, vtxIdentityPos) || vtxIdentityPos.empty())
			continue;
		const CIdentityIndex& identity = vtxIdentityPos.back();
		UniValue oCert(UniValue::VOBJ);
		if(BuildCertJson(txCert, identity, oCert))
			oRes.push_back(oCert);
	}


	return oRes;
}
void CertTxToJSON(const int op, const std::vector<unsigned char> &vchData, const std::vector<unsigned char> &vchHash, UniValue &entry)
{
	string opName = certFromOp(op);
	CCert cert;
	if(!cert.UnserializeFromData(vchData, vchHash))
		return;

	bool isExpired = false;
	vector<CIdentityIndex> identityVtxPos;
	vector<CCert> certVtxPos;
	CTransaction certtx, identitytx;
	CCert dbCert;
	if(GetTxAndVtxOfCert(cert.vchCert, dbCert, certtx, certVtxPos, true))
	{
		dbCert.nHeight = cert.nHeight;
		dbCert.GetCertFromList(certVtxPos);
	}
	CIdentityIndex dbIdentity;
	if(GetTxAndVtxOfIdentity(cert.vchIdentity, dbIdentity, identitytx, identityVtxPos, isExpired, true))
	{
		dbIdentity.nHeight = cert.nHeight;
		dbIdentity.GetIdentityFromList(identityVtxPos);
	}
	string noDifferentStr = _("<No Difference Detected>");

	entry.push_back(Pair("txtype", opName));
	entry.push_back(Pair("cert", stringFromVch(cert.vchCert)));

	string titleValue = noDifferentStr;
	if(!cert.vchTitle.empty() && cert.vchTitle != dbCert.vchTitle)
		titleValue = stringFromVch(cert.vchTitle);
	entry.push_back(Pair("title", titleValue));

	string strDataValue = "";
	if(cert.vchData.empty())
	{
		strDataValue = _("Encrypted for owner of certificate private data");
		string strDecrypted = "";
		if(DecryptMessage(dbIdentity, cert.vchData, strDecrypted))
			strDataValue = strDecrypted;		
	}
	string dataValue = noDifferentStr;
	if(!cert.vchData.empty() && cert.vchData != dbCert.vchData)
		dataValue = strDataValue;

	entry.push_back(Pair("data", dataValue));

	string dataPubValue = noDifferentStr;
	if(!cert.vchPubData.empty() && cert.vchPubData != dbCert.vchPubData)
		dataPubValue = stringFromVch(cert.vchPubData);

	entry.push_back(Pair("pubdata", dataPubValue));

	string identityValue = noDifferentStr;
	if(!cert.vchLinkIdentity.empty() && cert.vchLinkIdentity != dbCert.vchIdentity)
		identityValue = stringFromVch(cert.vchLinkIdentity);
	if(cert.vchIdentity != dbCert.vchIdentity)
		identityValue = stringFromVch(cert.vchIdentity);

	entry.push_back(Pair("identity", identityValue));


	string categoryValue = noDifferentStr;
	if(!cert.sCategory.empty() && cert.sCategory != dbCert.sCategory)
		categoryValue = stringFromVch(cert.sCategory);

	entry.push_back(Pair("category", categoryValue ));

	string transferViewOnlyValue = noDifferentStr;
	if(cert.bTransferViewOnly != dbCert.bTransferViewOnly)
		transferViewOnlyValue = cert.bTransferViewOnly? "Yes": "No";

	entry.push_back(Pair("transferviewonly", transferViewOnlyValue));

	string safeSearchValue = noDifferentStr;
	if(cert.safeSearch != dbCert.safeSearch)
		safeSearchValue = cert.safeSearch? "Yes": "No";

	entry.push_back(Pair("safesearch", safeSearchValue));

	string safetyLevelValue = noDifferentStr;
	if(cert.safetyLevel != dbCert.safetyLevel)
		safetyLevelValue = cert.safetyLevel;

	entry.push_back(Pair("safetylevel", safetyLevelValue));



}



