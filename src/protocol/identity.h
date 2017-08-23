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

#ifndef IDENTITY_H
#define IDENTITY_H

#include "rpcserver.h"
#include "dbwrapper.h"
#include "script/script.h"
#include "serialize.h"
#include "consensus/params.h"
#include "sync.h" 
#include "script/interpreter.h"

class CWalletTx;
class CTransaction;
class CTxOut;
class COutPoint;
class CReserveKey;
class CCoinsViewCache;
class CCoins;
class CBlock;
class CDynamicAddress;
class COutPoint;

struct CRecipient;

static const unsigned int MAX_GUID_LENGTH = 71;
// static const unsigned int MAX_NAME_LENGTH = 256;
// static const unsigned int MAX_VALUE_LENGTH = 1024;
static const unsigned int MAX_ID_LENGTH = 20;
static const unsigned int MAX_ENCRYPTED_VALUE_LENGTH = MAX_VALUE_LENGTH + 85;
static const unsigned int MAX_ENCRYPTED_NAME_LENGTH = MAX_NAME_LENGTH + 85;
static const unsigned int MAX_IDENTITY_UPDATES_PER_BLOCK = 5;

static const uint64_t ONE_YEAR_IN_SECONDS = 31536000;
static const unsigned int SAFETY_LEVEL1 = 1;
static const unsigned int SAFETY_LEVEL2 = 2;

class CIdentityUnprunable
{
	public:
	std::vector<unsigned char> vchGUID;
    uint64_t nExpireTime;
	CIdentityUnprunable() {
        SetNull();
    }

	ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
		READWRITE(vchGUID);
		READWRITE(VARINT(nExpireTime));
	}

    inline friend bool operator==(const CIdentityUnprunable &a, const CIdentityUnprunable &b) {
        return (
		a.vchGUID == b.vchGUID
		&& a.nExpireTime == b.nExpireTime
        );
    }

    inline CIdentityUnprunable operator=(const CIdentityUnprunable &b) {
		vchGUID = b.vchGUID;
		nExpireTime = b.nExpireTime;
        return *this;
    }

    inline friend bool operator!=(const CIdentityUnprunable &a, const CIdentityUnprunable &b) {
        return !(a == b);
    }

    inline void SetNull() { vchGUID.clear(); nExpireTime = 0;}
    inline bool IsNull() const { return (vchGUID.empty() && nExpireTime == 0 ); }
};
class CIdentityPayment {
public:
	
	unsigned char nOut;
	uint256 txHash;
	CIdentityPayment() {
        SetNull();
    }

	ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
		READWRITE(txHash);
		READWRITE(VARINT(nOut));
	}

    inline friend bool operator==(const CIdentityPayment &a, const CIdentityPayment &b) {
        return (
		a.txHash == b.txHash
        && a.nOut == b.nOut
        );
    }

    inline CIdentityPayment operator=(const CIdentityPayment &b) {
		txHash = b.txHash;
        nOut = b.nOut;
        return *this;
    }

    inline friend bool operator!=(const CIdentityPayment &a, const CIdentityPayment &b) {
        return !(a == b);
    }

    inline void SetNull() { txHash.SetNull(); nOut = 0;}
    inline bool IsNull() const { return (txHash.IsNull() && nOut == 0); }

};
class CMultiSigIdentityInfo {
public:
	std::vector<std::string> vchIdentityes;
	unsigned char nRequiredSigs;
	std::vector<unsigned char> vchRedeemScript;
	std::vector<std::string> vchEncryptionPrivateKeys;
	CMultiSigIdentityInfo() {
        SetNull();
    }

	ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
		READWRITE(vchIdentityes);
		READWRITE(VARINT(nRequiredSigs));
		READWRITE(vchRedeemScript);
		READWRITE(vchEncryptionPrivateKeys);
	}

    inline friend bool operator==(const CMultiSigIdentityInfo &a, const CMultiSigIdentityInfo &b) {
        return (
		a.vchIdentityes == b.vchIdentityes
        && a.nRequiredSigs == b.nRequiredSigs
		&& a.vchRedeemScript == b.vchRedeemScript
		&& a.vchEncryptionPrivateKeys == b.vchEncryptionPrivateKeys
        );
    }

    inline CMultiSigIdentityInfo operator=(const CMultiSigIdentityInfo &b) {
		vchIdentityes = b.vchIdentityes;
        nRequiredSigs = b.nRequiredSigs;
		vchRedeemScript = b.vchRedeemScript;
		vchEncryptionPrivateKeys = b.vchEncryptionPrivateKeys;
        return *this;
    }

    inline friend bool operator!=(const CMultiSigIdentityInfo &a, const CMultiSigIdentityInfo &b) {
        return !(a == b);
    }

    inline void SetNull() { vchEncryptionPrivateKeys.clear(); vchRedeemScript.clear(); vchIdentityes.clear(); nRequiredSigs = 0;}
    inline bool IsNull() const { return (vchEncryptionPrivateKeys.empty() && vchRedeemScript.empty() && vchIdentityes.empty() && nRequiredSigs == 0); }

};
class CIdentityIndex {
public:
	std::vector<unsigned char> vchIdentity;
	std::vector<unsigned char> vchGUID;
    uint256 txHash;
    uint64_t nHeight;
	uint64_t nExpireTime;
	std::vector<unsigned char> vchIdentityPeg;
    std::vector<unsigned char> vchPublicValue;
	std::vector<unsigned char> vchPrivateValue;
	std::vector<unsigned char> vchPubKey;
	std::vector<unsigned char> vchEncryptionPublicKey;
	std::vector<unsigned char> vchEncryptionPrivateKey;
	std::vector<unsigned char> vchPassword;
	CMultiSigIdentityInfo multiSigInfo;
	unsigned char safetyLevel;
	unsigned int nRatingAsBuyer;
	unsigned int nRatingCountAsBuyer;
	unsigned int nRatingAsSeller;
	unsigned int nRatingCountAsSeller;
	unsigned int nRatingAsArbiter;
	unsigned int nRatingCountAsArbiter;
	bool safeSearch;
	bool acceptCertTransfers;
    CIdentityIndex() { 
        SetNull();
    }
    CIdentityIndex(const CTransaction &tx) {
        SetNull();
        UnserializeFromTx(tx);
    }
	void ClearIdentity()
	{
		vchEncryptionPublicKey.clear();
		vchEncryptionPrivateKey.clear();
		vchPublicValue.clear();
		vchPrivateValue.clear();
		vchGUID.clear();
		multiSigInfo.SetNull();
		vchPassword.clear();
	}
    bool GetIdentityFromList(std::vector<CIdentityIndex> &identityList) {
        if(identityList.size() == 0) return false;
		CIdentityIndex myIdentity = identityList.front();
		if(nHeight <= 0)
		{
			*this = myIdentity;
			return true;
		}
			
		// find the closest identity without going over in height, assuming identityList orders entries by nHeight ascending
        for(std::vector<CIdentityIndex>::reverse_iterator it = identityList.rbegin(); it != identityList.rend(); ++it) {
            const CIdentityIndex &a = *it;
			// skip if this height is greater than our identity height
			if(a.nHeight > nHeight)
				continue;
            myIdentity = a;
			break;
        }
        *this = myIdentity;
        return true;
    }
	ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {        
		READWRITE(txHash);
		READWRITE(VARINT(nHeight));
		READWRITE(vchPublicValue);
		READWRITE(vchPrivateValue);
		READWRITE(vchEncryptionPublicKey);
		READWRITE(vchEncryptionPrivateKey);
		READWRITE(vchPubKey);
		READWRITE(vchPassword);
		READWRITE(vchIdentity);
		READWRITE(vchIdentityPeg);
		READWRITE(vchGUID);
		READWRITE(VARINT(safetyLevel));
		READWRITE(VARINT(nExpireTime));
		READWRITE(safeSearch);
		READWRITE(acceptCertTransfers);
		READWRITE(multiSigInfo);
		READWRITE(VARINT(nRatingAsBuyer));
		READWRITE(VARINT(nRatingCountAsBuyer));
		READWRITE(VARINT(nRatingAsSeller));
		READWRITE(VARINT(nRatingCountAsSeller));
		READWRITE(VARINT(nRatingAsArbiter));
		READWRITE(VARINT(nRatingCountAsArbiter));
	}
    friend bool operator==(const CIdentityIndex &a, const CIdentityIndex &b) {
		return (a.vchEncryptionPublicKey == b.vchEncryptionPublicKey && a.vchEncryptionPrivateKey == b.vchEncryptionPrivateKey && a.vchPassword ==b.vchPassword && a.acceptCertTransfers == b.acceptCertTransfers && a.multiSigInfo == b.multiSigInfo && a.nExpireTime == b.nExpireTime && a.vchGUID == b.vchGUID && a.vchIdentity == b.vchIdentity && a.nRatingCountAsArbiter == b.nRatingCountAsArbiter && a.nRatingAsArbiter == b.nRatingAsArbiter && a.nRatingCountAsSeller == b.nRatingCountAsSeller && a.nRatingAsSeller == b.nRatingAsSeller && a.nRatingCountAsBuyer == b.nRatingCountAsBuyer && a.nRatingAsBuyer == b.nRatingAsBuyer && a.safetyLevel == b.safetyLevel && a.safeSearch == b.safeSearch && a.nHeight == b.nHeight && a.txHash == b.txHash && a.vchPublicValue == b.vchPublicValue && a.vchPrivateValue == b.vchPrivateValue && a.vchPubKey == b.vchPubKey);
    }

    friend bool operator!=(const CIdentityIndex &a, const CIdentityIndex &b) {
        return !(a == b);
    }
    CIdentityIndex operator=(const CIdentityIndex &b) {
		vchGUID = b.vchGUID;
		nExpireTime = b.nExpireTime;
		vchIdentity = b.vchIdentity;
		vchIdentityPeg = b.vchIdentityPeg;
        txHash = b.txHash;
        nHeight = b.nHeight;
        vchPublicValue = b.vchPublicValue;
        vchPrivateValue = b.vchPrivateValue;
        vchPubKey = b.vchPubKey;
		vchPassword = b.vchPassword;
		safetyLevel = b.safetyLevel;
		safeSearch = b.safeSearch;
		acceptCertTransfers = b.acceptCertTransfers;
		multiSigInfo = b.multiSigInfo;
		nRatingAsBuyer = b.nRatingAsBuyer;
		nRatingCountAsBuyer = b.nRatingCountAsBuyer;
		nRatingAsSeller = b.nRatingAsSeller;
		nRatingCountAsSeller = b.nRatingCountAsSeller;
		nRatingAsArbiter = b.nRatingAsArbiter;
		nRatingCountAsArbiter = b.nRatingCountAsArbiter;
		vchEncryptionPrivateKey = b.vchEncryptionPrivateKey;
		vchEncryptionPublicKey = b.vchEncryptionPublicKey;
        return *this;
    }   
    void SetNull() {vchEncryptionPublicKey.clear();vchEncryptionPrivateKey.clear();vchIdentityPeg.clear();vchPassword.clear(); acceptCertTransfers = true; multiSigInfo.SetNull(); nExpireTime = 0; vchGUID.clear(); vchIdentity.clear(); nRatingCountAsBuyer = 0; nRatingAsBuyer = 0; nRatingCountAsSeller = 0; nRatingAsSeller = 0; nRatingCountAsArbiter = 0; nRatingAsArbiter = 0; safetyLevel = 0; safeSearch = true; txHash.SetNull(); nHeight = 0; vchPublicValue.clear(); vchPrivateValue.clear(); vchPubKey.clear(); }
    bool IsNull() const { return (vchEncryptionPrivateKey.empty() && vchEncryptionPrivateKey.empty() && vchIdentityPeg.empty() && vchPassword.empty() && acceptCertTransfers && multiSigInfo.IsNull() && nExpireTime == 0 && vchGUID.empty() && vchIdentity.empty() && nRatingCountAsBuyer == 0 && nRatingAsBuyer == 0 && nRatingCountAsArbiter == 0 && nRatingAsArbiter == 0 && nRatingCountAsSeller == 0 && nRatingAsSeller == 0 && safetyLevel == 0 && safeSearch && nHeight == 0 && txHash.IsNull() && vchPublicValue.empty() && vchPrivateValue.empty() && vchPubKey.empty()); }
	bool UnserializeFromTx(const CTransaction &tx);
	bool UnserializeFromData(const std::vector<unsigned char> &vchData, const std::vector<unsigned char> &vchHash);
	void Serialize(std::vector<unsigned char>& vchData);
};

class CIdentityDB : public CDBWrapper {
public:
    CIdentityDB(size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(GetDataDir() / "identities", nCacheSize, fMemory, fWipe) {
    }
	bool WriteIdentity(const std::vector<unsigned char>& name, const std::vector<CIdentityIndex>& vtxPos) {	
		return Write(make_pair(std::string("namei"), name), vtxPos);
	}
	bool WriteIdentity(const std::vector<unsigned char>& name, const CIdentityUnprunable &identityUnprunable, const std::vector<unsigned char>& address, const std::vector<CIdentityIndex>& vtxPos) {
		if(address.empty())
			return false;		
		return Write(make_pair(std::string("namei"), name), vtxPos) && Write(make_pair(std::string("namea"), address), name) && Write(make_pair(std::string("nameu"), name), identityUnprunable);
	}
	bool WriteIdentityPayment(const std::vector<unsigned char>& name, const std::vector<CIdentityPayment>& vtxPaymentPos)
	{
		return Write(make_pair(std::string("namep"), name), vtxPaymentPos);
	}

	bool EraseIdentity(const std::vector<unsigned char>& name) {
	    bool eraseIdentity =  Erase(make_pair(std::string("namei"), name)) ;
		bool eraseIdentityPayment = Erase(make_pair(std::string("namep"), name));
		return eraseIdentity && eraseIdentityPayment;
	}
	bool EraseIdentityPayment(const std::vector<unsigned char>& name) {
	    return Erase(make_pair(std::string("namep"), name));
	}
	bool ReadIdentity(const std::vector<unsigned char>& name, std::vector<CIdentityIndex>& vtxPos) {
		return Read(make_pair(std::string("namei"), name), vtxPos);
	}
	bool ReadAddress(const std::vector<unsigned char>& address, std::vector<unsigned char>& name) {
		return Read(make_pair(std::string("namea"), address), name);
	}
	bool ReadIdentityPayment(const std::vector<unsigned char>& name, std::vector<CIdentityPayment>& vtxPaymentPos) {
		return Read(make_pair(std::string("namep"), name), vtxPaymentPos);
	}
	bool ReadIdentityUnprunable(const std::vector<unsigned char>& name, CIdentityUnprunable& identityUnprunable) {
		return Read(make_pair(std::string("nameu"), name), identityUnprunable);
	}
	bool ExistsIdentity(const std::vector<unsigned char>& name) {
	    return Exists(make_pair(std::string("namei"), name));
	}
	bool ExistsIdentityPayment(const std::vector<unsigned char>& name) {
	    return Exists(make_pair(std::string("namep"), name));
	}
	bool ExistsIdentityUnprunable(const std::vector<unsigned char>& name) {
	    return Exists(make_pair(std::string("nameu"), name));
	}
	bool ExistsAddress(const std::vector<unsigned char>& address) {
	    return Exists(make_pair(std::string("namea"), address));
	}
    bool ScanNames(
		const std::vector<unsigned char>& vchIdentity, const std::string& strRegExp, bool safeSearch,
            unsigned int nMax,
            std::vector<CIdentityIndex>& nameScan);
	bool CleanupDatabase(int &servicesCleaned);

};

class COfferDB;
class CCertDB;
class CEscrowDB;
class CMessageDB;
extern CIdentityDB *pidentitydb;
extern COfferDB *pofferdb;
extern CCertDB *pcertdb;
extern CEscrowDB *pescrowdb;
extern CMessageDB *pmessagedb;



std::string stringFromVch(const std::vector<unsigned char> &vch);
std::vector<unsigned char> vchFromValue(const UniValue& value);
std::vector<unsigned char> vchFromString(const std::string &str);
std::string stringFromValue(const UniValue& value);
int GetDynamicTxVersion();
const int DYNAMIC_TX_VERSION = 0x7400;
bool IsValidIdentityName(const std::vector<unsigned char> &vchIdentity);
bool CheckIdentityInputs(const CTransaction &tx, int op, int nOut, const std::vector<std::vector<unsigned char> > &vvchArgs, const CCoinsViewCache &inputs, bool fJustCheck, int nHeight, std::string &errorMessage, bool dontaddtodb=false);
void CreateRecipient(const CScript& scriptPubKey, CRecipient& recipient);
void CreateFeeRecipient(CScript& scriptPubKey, const std::vector<unsigned char>& vchIdentityPeg, const uint64_t& nHeight, const std::vector<unsigned char>& data, CRecipient& recipient);
CAmount GetDataFee(const CScript& scriptPubKey, const std::vector<unsigned char>& vchIdentityPeg, const uint64_t& nHeight);
bool IsDynamicTxMine(const CTransaction& tx,const std::string &type);
bool IsIdentityOp(int op);
bool getCategoryList(std::vector<std::string>& categoryList);
bool getBanList(const std::vector<unsigned char> &banData, std::map<std::string, unsigned char> &banIdentityList,  std::map<std::string, unsigned char>& banCertList,  std::map<std::string, unsigned char>& banOfferList);
bool GetTxOfIdentity(const std::vector<unsigned char> &vchIdentity, CIdentityIndex& identity, CTransaction& tx, bool skipExpiresCheck=false);
bool GetTxAndVtxOfIdentity(const std::vector<unsigned char> &vchIdentity, CIdentityIndex& identity, CTransaction& tx, std::vector<CIdentityIndex> &vtxPos, bool &isExpired, bool skipExpiresCheck=false);
bool GetVtxOfIdentity(const std::vector<unsigned char> &vchIdentity, CIdentityIndex& identity, std::vector<CIdentityIndex> &vtxPos, bool &isExpired, bool skipExpiresCheck=false);

int IndexOfIdentityOutput(const CTransaction& tx);
bool GetIdentityOfTx(const CTransaction& tx, std::vector<unsigned char>& name);
bool DecodeIdentityTx(const CTransaction& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch, bool payment=false);
bool DecodeAndParseIdentityTx(const CTransaction& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch);
bool DecodeAndParseDynamicTx(const CTransaction& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch);
bool DecodeIdentityScript(const CScript& script, int& op,
		std::vector<std::vector<unsigned char> > &vvch);
bool GetAddressFromIdentity(const std::string& strIdentity, std::string& strAddress, unsigned char& safetyLevel, bool& safeSearch, std::vector<unsigned char> &vchRedeemScript, std::vector<unsigned char> &vchPubKey);
bool GetIdentityFromAddress(const std::string& strAddress, std::string& strIdentity, unsigned char& safetyLevel, bool& safeSearch, std::vector<unsigned char> &vchRedeemScript, std::vector<unsigned char> &vchPubKey);
CAmount convertCurrencyCodeToDynamic(const std::vector<unsigned char> &vchIdentityPeg, const std::vector<unsigned char> &vchCurrencyCode, const double &nPrice, const unsigned int &nHeight, int &precision);
int getFeePerByte(const std::vector<unsigned char> &vchIdentityPeg, const std::vector<unsigned char> &vchCurrencyCode, const unsigned int &nHeight, int &precision);
float getEscrowFee(const std::vector<unsigned char> &vchIdentityPeg, const std::vector<unsigned char> &vchCurrencyCode, const unsigned int &nHeight, int &precision);
CAmount convertDynamicToCurrencyCode(const std::vector<unsigned char> &vchIdentityPeg, const std::vector<unsigned char> &vchCurrencyCode, const CAmount &nPrice, const unsigned int &nHeight, int &precision);
std::string getCurrencyToDYNFromIdentity(const std::vector<unsigned char> &vchIdentityPeg, const std::vector<unsigned char> &vchCurrency, double &nFee, const unsigned int &nHeightToFind, std::vector<std::string>& rateList, int &precision, int &nFeePerByte, float &fEscrowFee);
std::string identityFromOp(int op);
std::string GenerateDynamicGuid();
bool IsIdentityOp(int op);
bool RemoveIdentityScriptPrefix(const CScript& scriptIn, CScript& scriptOut);
int GetDynamicDataOutput(const CTransaction& tx);
bool IsDynamicDataOutput(const CTxOut& out);
bool GetDynamicData(const CTransaction &tx, std::vector<unsigned char> &vchData, std::vector<unsigned char> &vchHash, int& nOut);
bool GetDynamicData(const CScript &scriptPubKey, std::vector<unsigned char> &vchData, std::vector<unsigned char> &vchHash);
bool IsDynServiceExpired(const uint64_t &nTime);
bool GetTimeToPrune(const CScript& scriptPubKey, uint64_t &nTime);
bool GetDynamicTransaction(int nHeight, const uint256 &hash, CTransaction &txOut, const Consensus::Params& consensusParams);
bool IsDynamicScript(const CScript& scriptPubKey, int &op, std::vector<std::vector<unsigned char> > &vvchArgs);
void RemoveDynamicScript(const CScript& scriptPubKeyIn, CScript& scriptPubKeyOut);
void PutToIdentityList(std::vector<CIdentityIndex> &identityList, CIdentityIndex& index);
void DynTxToJSON(const int op, const std::vector<unsigned char> &vchData, const std::vector<unsigned char> &vchHash, UniValue &entry);
void IdentityTxToJSON(const int op, const std::vector<unsigned char> &vchData, const std::vector<unsigned char> &vchHash, UniValue &entry);
bool BuildIdentityJson(const CIdentityIndex& identity, const int pending, UniValue& oName, const std::string &strPrivKey="");
void CleanupDynamicServiceDatabases(int &servicesCleaned);
int identityunspent(const std::vector<unsigned char> &vchIdentity, COutPoint& outpoint);
bool IsMyIdentity(const CIdentityIndex& identity);
void GetAddress(const CIdentityIndex &identity, CDynamicAddress* address, const uint32_t nPaymentOption=1);
void GetAddress(const CIdentityIndex &identity, CDynamicAddress* address, CScript& script, const uint32_t nPaymentOption=1);
void GetPrivateKeysFromScript(const CScript& script, std::vector<std::string> &strKeys);
#endif // IDENTITY_H
