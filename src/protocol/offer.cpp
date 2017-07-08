// Copyright (c) 2017 The Dynamic Developers
// Copyright (c) 2014-2017 The Syscoin Developers
// Copyright (c) 2016-2017 Duality Blockchain Solutions Ltd.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "offer.h"
#include "identity.h"
#include "escrow.h"
#include "cert.h"
#include "message.h"
#include "init.h"
#include "main.h"
#include "util.h"
#include "random.h"
#include "base58.h"
#include "core_io.h"
#include "rpcserver.h"
#include "wallet/wallet.h"
#include "consensus/validation.h"
#include "chainparams.h"

#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <boost/xpressive/xpressive_dynamic.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/foreach.hpp>
#include <boost/thread.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/predicate.hpp>

using namespace std;

extern void SendMoneyDynamic(const vector<CRecipient> &vecSend, CAmount nValue, bool fSubtractFeeFromAmount, CWalletTx& wtxNew, const CWalletTx* wtxInIdentity=NULL, int nTxOutIdentity = 0, bool dynamicMultiSigTx=false, const CCoinControl* coinControl=NULL, const CWalletTx* wtxInLinkIdentity=NULL,  int nTxOutLinkIdentity = 0);

bool DisconnectIdentity(const CBlockIndex *pindex, const CTransaction &tx, int op, vector<vector<unsigned char> > &vvchArgs );
bool DisconnectOffer(const CBlockIndex *pindex, const CTransaction &tx, int op, vector<vector<unsigned char> > &vvchArgs );
bool DisconnectCertificate(const CBlockIndex *pindex, const CTransaction &tx, int op, vector<vector<unsigned char> > &vvchArgs );
bool DisconnectMessage(const CBlockIndex *pindex, const CTransaction &tx, int op, vector<vector<unsigned char> > &vvchArgs );
bool DisconnectEscrow(const CBlockIndex *pindex, const CTransaction &tx, int op, vector<vector<unsigned char> > &vvchArgs );

bool IsOfferOp(int op) {
	return op == OP_OFFER_ACTIVATE
        || op == OP_OFFER_UPDATE
        || op == OP_OFFER_ACCEPT;
}

bool ValidatePaymentOptionsMask(const uint32_t paymentOptionsMask) {
	uint32_t maxVal = PAYMENTOPTION_DYN | PAYMENTOPTION_BTC | PAYMENTOPTION_SEQ;
	return !(paymentOptionsMask < 1 || paymentOptionsMask > maxVal);
}

bool IsValidPaymentOption(const uint32_t paymentOptionsMask) {
	return (paymentOptionsMask == PAYMENTOPTION_DYN || paymentOptionsMask == PAYMENTOPTION_BTC || paymentOptionsMask == PAYMENTOPTION_SEQ);
}

bool ValidatePaymentOptionsString(const std::string &paymentOptionsString) {
	bool retval = true;
	vector<string> strs;
	boost::split(strs, paymentOptionsString, boost::is_any_of("+"));
	for (size_t i = 0; i < strs.size(); i++) {
		if(strs[i].compare("BTC") != 0 && strs[i].compare("DYN") != 0 && strs[i].compare("SEQ") != 0) {
			retval = false;
			break;
		}
	}
	return retval;
}

uint32_t GetPaymentOptionsMaskFromString(const std::string &paymentOptionsString) {
	vector<string> strs;
	uint32_t retval = 0;
	boost::split(strs, paymentOptionsString, boost::is_any_of("+"));
	for (size_t i = 0; i < strs.size(); i++) {
		if(!strs[i].compare("DYN")) {
			retval |= PAYMENTOPTION_DYN;
		}
		else if(!strs[i].compare("BTC")) {
			retval |= PAYMENTOPTION_BTC;
		}
		else if(!strs[i].compare("SEQ")) {
			retval |= PAYMENTOPTION_SEQ;
		}
		else return 0;
	}
	return retval;
}

bool IsPaymentOptionInMask(const uint32_t mask, const uint32_t paymentOption) {
  return mask & paymentOption ? true : false;
}

uint64_t GetOfferExpiration(const COffer& offer) {
	// dont prunte by default, set nHeight to future time
	uint64_t nTime = chainActive.Tip()->nTime + 1;
	CIdentityUnprunable identityUnprunable;
	// if service identity exists in unprunable db (this should always exist for any identity that ever existed) then get the last expire height set for this identity and check against it for pruning
	if (pidentitydb && pidentitydb->ReadIdentityUnprunable(offer.vchIdentity, identityUnprunable) && !identityUnprunable.IsNull())
		nTime = identityUnprunable.nExpireTime;
	return nTime;
}

string offerFromOp(int op) {
	switch (op) {
	case OP_OFFER_ACTIVATE:
		return "offeractivate";
	case OP_OFFER_UPDATE:
		return "offerupdate";
	case OP_OFFER_ACCEPT:
		return "offeraccept";
	default:
		return "<unknown offer op>";
	}
}
bool COffer::UnserializeFromData(const vector<unsigned char> &vchData, const vector<unsigned char> &vchHash) {
    try {
        CDataStream dsOffer(vchData, SER_NETWORK, PROTOCOL_VERSION);
        dsOffer >> *this;

		vector<unsigned char> vchOfferData;
		Serialize(vchOfferData);
		const uint256 &calculatedHash = Hash(vchOfferData.begin(), vchOfferData.end());
		const vector<unsigned char> &vchRandOffer = vchFromValue(calculatedHash.GetHex());
		if(vchRandOffer != vchHash)
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
bool COffer::UnserializeFromTx(const CTransaction &tx) {
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
void COffer::Serialize(vector<unsigned char> &vchData) {
    CDataStream dsOffer(SER_NETWORK, PROTOCOL_VERSION);
    dsOffer << *this;
	vchData = vector<unsigned char>(dsOffer.begin(), dsOffer.end());
}
bool COfferDB::CleanupDatabase(int &servicesCleaned)
{
	boost::scoped_ptr<CDBIterator> pcursor(NewIterator());
	pcursor->SeekToFirst();
	vector<COffer> vtxPos;
	pair<string, vector<unsigned char> > key;
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        try {
			if (pcursor->GetKey(key) && key.first == "offeri") {
            	const vector<unsigned char> &vchMyOffer = key.second;         
				pcursor->GetValue(vtxPos);	
				if (vtxPos.empty()){
					servicesCleaned++;
					EraseOffer(vchMyOffer);
					pcursor->Next();
					continue;
				}
				const COffer &txPos = vtxPos.back();
  				if (chainActive.Tip()->nTime >= GetOfferExpiration(txPos))
				{
					servicesCleaned++;
					EraseOffer(vchMyOffer);
				} 
				
            }
            pcursor->Next();
        } catch (std::exception &e) {
            return error("%s() : deserialize error", __PRETTY_FUNCTION__);
        }
    }
	return true;
}
bool COfferDB::ScanOffers(const std::vector<unsigned char>& vchOffer, const string& strRegexp, bool safeSearch,const string& strCategory, unsigned int nMax,
		std::vector<COffer>& offerScan) {
   // regexp
    using namespace boost::xpressive;
    smatch offerparts;
	smatch nameparts;
	string strRegexpLower = strRegexp;
	boost::algorithm::to_lower(strRegexpLower);
	sregex cregex = sregex::compile(strRegexpLower);
	boost::scoped_ptr<CDBIterator> pcursor(NewIterator());
	if(!vchOffer.empty())
		pcursor->Seek(make_pair(string("offeri"), vchOffer));
	else
		pcursor->SeekToFirst();
	vector<COffer> vtxPos;
	boost::this_thread::interruption_point();
    while (pcursor->Valid()) {
		pair<string, vector<unsigned char> > key;
        try {
			if (pcursor->GetKey(key) && key.first == "offeri") {
            	const vector<unsigned char> &vchMyOffer = key.second;
                
				pcursor->GetValue(vtxPos);

				if (vtxPos.empty()){
					pcursor->Next();
					continue;
				}
				const COffer &txPos = vtxPos.back();
				int nQty = txPos.nQty;
  				if (chainActive.Tip()->nTime >= GetOfferExpiration(txPos))
				{
					pcursor->Next();
					continue;
				}
				CIdentityIndex linkIdentity;
				if( !txPos.vchLinkOffer.empty())
				{
					vector<COffer> myLinkedOfferVtxPos;
					vector<CIdentityIndex> myLinkedIdentityVtxPos;
					if (!pofferdb->ReadOffer(txPos.vchLinkOffer, myLinkedOfferVtxPos) || myLinkedOfferVtxPos.empty())
					{
						pcursor->Next();
						continue;
					}
					const COffer &linkOffer = myLinkedOfferVtxPos.back();
					nQty = linkOffer.nQty;
					if (!pidentitydb->ReadIdentity(linkOffer.vchIdentity, myLinkedIdentityVtxPos) || myLinkedIdentityVtxPos.empty())
					{
						pcursor->Next();
						continue;
					}

					linkIdentity = myLinkedIdentityVtxPos.back();
					if(linkOffer.safetyLevel >= SAFETY_LEVEL1 || linkIdentity.safetyLevel >= SAFETY_LEVEL1)
					{
						if(safeSearch)
						{
							pcursor->Next();
							continue;
						}
						if(linkOffer.safetyLevel >= SAFETY_LEVEL2 || linkIdentity.safetyLevel >= SAFETY_LEVEL2)
						{
							pcursor->Next();
							continue;
						}
					}
					if((!linkOffer.safeSearch || !linkIdentity.safeSearch) && safeSearch)
					{
						pcursor->Next();
						continue;
					}
				}
				// dont return sold out offers
				if(nQty <= 0 && nQty != -1)
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
				if(txPos.safetyLevel >= SAFETY_LEVEL1  || linkIdentity.safetyLevel >= SAFETY_LEVEL1)
				{
					if(safeSearch)
					{
						pcursor->Next();
						continue;
					}
					if(txPos.safetyLevel >= SAFETY_LEVEL2 || linkIdentity.safetyLevel >= SAFETY_LEVEL2)
					{
						pcursor->Next();
						continue;
					}
				}
				if((!txPos.safeSearch || !theIdentity.safeSearch) && safeSearch)
				{
					pcursor->Next();
					continue;
				}
				if(strCategory.size() > 0 && !boost::algorithm::starts_with(stringFromVch(txPos.sCategory), strCategory))
				{
					pcursor->Next();
					continue;
				}

				string title = stringFromVch(txPos.sTitle);
				string offer = stringFromVch(vchMyOffer);
				boost::algorithm::to_lower(title);
				string description = stringFromVch(txPos.sDescription);
				boost::algorithm::to_lower(description);
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
				string identity = stringFromVch(txPos.vchIdentity);
				if (strRegexp != "" && !regex_search(title, offerparts, cregex) && !regex_search(description, offerparts, cregex) && strRegexp != offer && strRegexpLower != identity)
				{
					pcursor->Next();
					continue;
				}
				if(txPos.bPrivate)
				{
					if(strRegexp == "")
					{
						pcursor->Next();
						continue;
					}
					else if(strRegexp != offer)
					{
						pcursor->Next();
						continue;
					}
				}
                offerScan.push_back(txPos);
            }
            if (offerScan.size() >= nMax)
                break;

            pcursor->Next();
        } catch (std::exception &e) {
            return error("%s() : deserialize error", __PRETTY_FUNCTION__);
        }
    }
    return true;
}

int IndexOfOfferOutput(const CTransaction& tx) {
	if (tx.nVersion != DYNAMIC_TX_VERSION)
		return -1;
	vector<vector<unsigned char> > vvch;
	int op;
	for (unsigned int i = 0; i < tx.vout.size(); i++) {
		const CTxOut& out = tx.vout[i];
		// find an output you own
		if (pwalletMain->IsMine(out) && DecodeOfferScript(out.scriptPubKey, op, vvch)) {
			return i;
		}
	}
	return -1;
}

bool GetTxOfOffer(const vector<unsigned char> &vchOffer,
				  COffer& txPos, CTransaction& tx, bool skipExpiresCheck) {
	vector<COffer> vtxPos;
	if (!pofferdb->ReadOffer(vchOffer, vtxPos) || vtxPos.empty())
		return false;
	txPos = vtxPos.back();
	int nHeight = txPos.nHeight;

	if (!skipExpiresCheck && chainActive.Tip()->nTime >= GetOfferExpiration(txPos)) {
		string offer = stringFromVch(vchOffer);
		if(fDebug)
			LogPrintf("GetTxOfOffer(%s) : expired", offer.c_str());
		return false;
	}

	if (!GetDynamicTransaction(nHeight, txPos.txHash, tx, Params().GetConsensus()))
		return false;

	return true;
}
bool GetTxAndVtxOfOffer(const vector<unsigned char> &vchOffer,
				  COffer& txPos, CTransaction& tx, vector<COffer> &vtxPos, bool skipExpiresCheck) {
	if (!pofferdb->ReadOffer(vchOffer, vtxPos) || vtxPos.empty())
		return false;

	txPos = vtxPos.back();
	int nHeight = txPos.nHeight;

	if (!skipExpiresCheck && chainActive.Tip()->nTime >= GetOfferExpiration(txPos))
	{
		string offer = stringFromVch(vchOffer);
		if(fDebug)
			LogPrintf("GetTxOfOffer(%s) : expired", offer.c_str());
		return false;
	}

	if (!GetDynamicTransaction(nHeight, txPos.txHash, tx, Params().GetConsensus()))
		return false;

	return true;
}
bool GetVtxOfOffer(const vector<unsigned char> &vchOffer,
				  COffer& txPos, vector<COffer> &vtxPos, bool skipExpiresCheck) {
	if (!pofferdb->ReadOffer(vchOffer, vtxPos) || vtxPos.empty())
		return false;

	txPos = vtxPos.back();
	int nHeight = txPos.nHeight;

	if (!skipExpiresCheck && chainActive.Tip()->nTime >= GetOfferExpiration(txPos))
	{
		string offer = stringFromVch(vchOffer);
		if(fDebug)
			LogPrintf("GetTxOfOffer(%s) : expired", offer.c_str());
		return false;
	}
	return true;
}
bool GetTxOfOfferAccept(const vector<unsigned char> &vchOffer, const vector<unsigned char> &vchOfferAccept,
		COffer &acceptOffer,  COfferAccept &theOfferAccept, CTransaction& tx, bool skipExpiresCheck) {
	vector<COffer> vtxPos;
	if (!pofferdb->ReadOffer(vchOffer, vtxPos) || vtxPos.empty()) return false;
	theOfferAccept.SetNull();
	theOfferAccept.vchAcceptRand = vchOfferAccept;
	if(!GetAcceptByHash(vtxPos, theOfferAccept, acceptOffer))
		return false;

	if (!skipExpiresCheck && chainActive.Tip()->nTime >= GetOfferExpiration(acceptOffer))
	{
		string offer = stringFromVch(vchOfferAccept);
		if(fDebug)
			LogPrintf("GetTxOfOfferAccept(%s) : expired", offer.c_str());
		return false;
	}

	if (!GetDynamicTransaction(acceptOffer.nHeight, acceptOffer.txHash, tx, Params().GetConsensus()))
		return false;

	return true;
}
bool GetOfferAccept(const vector<unsigned char> &vchOffer, const vector<unsigned char> &vchOfferAccept,
		COffer &acceptOffer,  COfferAccept &theOfferAccept,  bool skipExpiresCheck) {
	vector<COffer> vtxPos;
	if (!pofferdb->ReadOffer(vchOffer, vtxPos) || vtxPos.empty()) return false;
	theOfferAccept.SetNull();
	theOfferAccept.vchAcceptRand = vchOfferAccept;
	if(!GetAcceptByHash(vtxPos, theOfferAccept, acceptOffer))
		return false;

	if (!skipExpiresCheck && chainActive.Tip()->nTime >= GetOfferExpiration(acceptOffer))
	{
		string offer = stringFromVch(vchOfferAccept);
		if(fDebug)
			LogPrintf("GetTxOfOfferAccept(%s) : expired", offer.c_str());
		return false;
	}
	return true;
}
bool DecodeAndParseOfferTx(const CTransaction& tx, int& op, int& nOut,
		vector<vector<unsigned char> >& vvch)
{
	COffer offer;
	bool decode = DecodeOfferTx(tx, op, nOut, vvch);
	bool parse = offer.UnserializeFromTx(tx);
	return decode && parse;
}
bool DecodeOfferTx(const CTransaction& tx, int& op, int& nOut,
		vector<vector<unsigned char> >& vvch) {
	bool found = false;

	// Strict check - bug disallowed
	for (unsigned int i = 0; i < tx.vout.size(); i++) {
		const CTxOut& out = tx.vout[i];
		if (DecodeOfferScript(out.scriptPubKey, op, vvch)) {
			nOut = i; found = true;
			break;
		}
	}
	if (!found) vvch.clear();
	return found;
}
int FindOfferAcceptPayment(const CTransaction& tx, const CAmount &nPrice) {
	for (unsigned int i = 0; i < tx.vout.size(); i++) {
		if(tx.vout[i].nValue == nPrice)
			return i;
	}
	return -1;
}

bool DecodeOfferScript(const CScript& script, int& op,
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
	return found && IsOfferOp(op);
}
bool DecodeOfferScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch) {
	CScript::const_iterator pc = script.begin();
	return DecodeOfferScript(script, op, vvch, pc);
}
bool RemoveOfferScriptPrefix(const CScript& scriptIn, CScript& scriptOut) {
	int op;
	vector<vector<unsigned char> > vvch;
	CScript::const_iterator pc = scriptIn.begin();

	if (!DecodeOfferScript(scriptIn, op, vvch, pc))
		return false;
	scriptOut = CScript(pc, scriptIn.end());
	return true;
}

bool CheckOfferInputs(const CTransaction &tx, int op, int nOut, const vector<vector<unsigned char> > &vvchArgs, const CCoinsViewCache &inputs, bool fJustCheck, int nHeight, string &errorMessage, bool dontaddtodb) {
	if (tx.IsCoinBase() && !fJustCheck && !dontaddtodb)
	{
		LogPrintf("*Trying to add offer in coinbase transaction, skipping...");
		return true;
	}
	if (fDebug)
		LogPrintf("*** OFFER %d %d %s %s %s %s %s %d\n", nHeight,
			chainActive.Tip()->nHeight, tx.GetHash().ToString().c_str(),
			op==OP_OFFER_ACCEPT ? "OFFERACCEPT: ": "",
			op==OP_OFFER_ACCEPT && vvchArgs.size() > 1? stringFromVch(vvchArgs[1]).c_str(): "",
			fJustCheck ? "JUSTCHECK" : "BLOCK", " VVCH SIZE: ", vvchArgs.size());
	bool foundIdentity = false;
	bool foundIdentityLink = false;
	const COutPoint *prevOutput = NULL;
	const CCoins *prevCoins;
	int prevIdentityOp = 0;
	int prevIdentityOpLink = 0;
	vector<vector<unsigned char> > vvchPrevIdentityArgs, vvchPrevIdentityArgsLink;
	// unserialize msg from txn, check for valid
	COffer theOffer;
	vector<unsigned char> vchData;
	vector<unsigned char> vchHash;
	CTxDestination payDest, commissionDest, dest, identityDest, linkDest;
	int nDataOut;
	if(!GetDynamicData(tx, vchData, vchHash, nDataOut) || !theOffer.UnserializeFromData(vchData, vchHash))
	{
		errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR ERRCODE: 1000 - " + _("Cannot unserialize data inside of this transaction relating to an offer");
		return true;
	}
	// Make sure offer outputs are not spent by a regular transaction, or the offer would be lost
	if (tx.nVersion != DYNAMIC_TX_VERSION)
	{
		errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1001 - " + _("Non-Dynamic transaction found");
		return true;
	}
	if(fJustCheck)
	{
		if(op != OP_OFFER_ACCEPT && vvchArgs.size() != 2)
		{
			errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1002 - " + _("Offer arguments incorrect size");
			return error(errorMessage.c_str());
		}
		else if(op == OP_OFFER_ACCEPT && vvchArgs.size() != 4)
		{
			errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1003 - " + _("OfferAccept arguments incorrect size");
			return error(errorMessage.c_str());
		}
		
		if(op == OP_OFFER_ACCEPT)
		{
			if(vvchArgs.size() <= 3 || vchHash != vvchArgs[3])
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1004 - " + _("Hash provided doesn't match the calculated hash of the data");
				return true;
			}
		}
		else
		{
			if(vvchArgs.size() <= 1 || vchHash != vvchArgs[1])
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1005 - " + _("Hash provided doesn't match the calculated hash of the data");
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
			if(foundIdentity && foundIdentityLink)
				break;
			if (!foundIdentity && IsIdentityOp(pop) && ((theOffer.accept.IsNull() && theOffer.vchIdentity == vvch[0]) || (!theOffer.accept.IsNull() && theOffer.accept.vchBuyerIdentity == vvch[0])))
			{
				foundIdentity = true;
				prevIdentityOp = pop;
				vvchPrevIdentityArgs = vvch;
			}
			if (!foundIdentityLink && IsIdentityOp(pop) && theOffer.vchLinkIdentity == vvch[0])
			{
				foundIdentityLink = true;
				prevIdentityOpLink = pop;
				vvchPrevIdentityArgsLink = vvch;
			}
		}

	}


	// unserialize offer from txn, check for valid
	COfferAccept theOfferAccept;
	vector<CIdentityIndex> vtxIdentityPos;
	COffer linkOffer;
	COffer myPriceOffer;
	COffer myOffer;
	CTransaction linkedTx;
	COfferLinkWhitelistEntry entry;
	CCert theCert;
	CIdentityIndex theIdentity, identity, linkIdentity;
	CTransaction identityTx, identityLinkTx;
	vector<COffer> vtxPos;
	vector<string> categories;
	vector<COffer> offerVtxPos;
	string category;
	string retError = "";
	// just check is for the memory pool inclusion, here we can stop bad transactions from entering before we get to include them in a block
	if(fJustCheck)
	{
		if (vvchArgs.empty() || vvchArgs[0].size() > MAX_GUID_LENGTH)
		{
			errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1006 - " + _("Offer guid too long");
			return error(errorMessage.c_str());
		}

		if(theOffer.sDescription.size() > MAX_VALUE_LENGTH)
		{
			errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1007 - " + _("Offer description too long");
			return error(errorMessage.c_str());
		}
		if(theOffer.sTitle.size() > MAX_NAME_LENGTH)
		{
			errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1008 - " + _("Offer title too long");
			return error(errorMessage.c_str());
		}
		if(theOffer.sCategory.size() > MAX_NAME_LENGTH)
		{
			errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1009 - " + _("Offer category too long");
			return error(errorMessage.c_str());
		}
		if(theOffer.vchLinkOffer.size() > MAX_GUID_LENGTH)
		{
			errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1010 - " + _("Offer link guid hash too long");
			return error(errorMessage.c_str());
		}
		if(theOffer.sCurrencyCode.size() > MAX_GUID_LENGTH)
		{
			errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1011 - " + _("Offer curreny too long");
			return error(errorMessage.c_str());
		}
		if(theOffer.vchGeoLocation.size() > MAX_NAME_LENGTH)
		{
			errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1012 - " + _("Offer geolocation too long");
			return error(errorMessage.c_str());
		}
		if(theOffer.linkWhitelist.entries.size() > 1)
		{
			errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1013 - " + _("Offer has too many affiliate entries, only one allowed per transaction");
			return error(errorMessage.c_str());
		}
		if(!theOffer.vchOffer.empty() && theOffer.vchOffer != vvchArgs[0])
		{
			errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1014 - " + _("Offer guid in the data output does not match the guid in the transaction");
			return error(errorMessage.c_str());
		}
		switch (op) {
		case OP_OFFER_ACTIVATE:
			if(!IsIdentityOp(prevIdentityOp) || vvchPrevIdentityArgs.empty() || theOffer.vchIdentity != vvchPrevIdentityArgs[0])
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1015 - " + _("Identity input mismatch");
				return error(errorMessage.c_str());
			}
			if(!ValidatePaymentOptionsMask(theOffer.paymentOptions))
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1016 - " + _("Invalid payment option");
				return error(errorMessage.c_str());
			}
			if(!theOffer.accept.IsNull())
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1017 - " + _("Cannot have accept information on offer activation");
				return error(errorMessage.c_str());
			}
			if ( theOffer.vchOffer != vvchArgs[0])
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1018 - " + _("Offer input and offer guid mismatch");
				return error(errorMessage.c_str());
			}
			if(!theOffer.vchLinkOffer.empty())
			{
				if(theOffer.nCommission > 100 || theOffer.nCommission < -90)
				{
					errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1019 - " + _("Commission must between -90 and 100");
					return error(errorMessage.c_str());
				}
			}
			else
			{
				if(theOffer.sCategory.size() < 1)
				{
					errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1020 - " + _("Offer category cannot be empty");
					return error(errorMessage.c_str());
				}
				if(theOffer.sTitle.size() < 1)
				{
					errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1021 - " + _("Offer title cannot be empty");
					return error(errorMessage.c_str());
				}
				if(theOffer.paymentOptions <= 0)
				{
					errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1022 - " + _("Invalid payment option specified");
					return error(errorMessage.c_str());
				}
			}
			if(theOffer.nQty < -1)
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1023 - " + _("Quantity must be greater than or equal to -1");
				return error(errorMessage.c_str());
			}
			if(!theOffer.vchCert.empty() && theOffer.nQty != 1)
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1024 - " + _("Quantity must be 1 for a digital offer");
				return error(errorMessage.c_str());
			}
			if(theOffer.nPrice <= 0)
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1025 - " + _("Offer price must be greater than 0");
				return error(errorMessage.c_str());
			}


			break;
		case OP_OFFER_UPDATE:
			if(!IsIdentityOp(prevIdentityOp) || vvchPrevIdentityArgs.empty() || theOffer.vchIdentity != vvchPrevIdentityArgs[0])
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1026 - " + _("Identity input mismatch");
				return error(errorMessage.c_str());
			}
			if(!theOffer.vchLinkIdentity.empty() && (!IsIdentityOp(prevIdentityOpLink) || vvchPrevIdentityArgsLink.empty() || theOffer.vchLinkIdentity != vvchPrevIdentityArgsLink[0]))
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1026 - " + _("Identity link input mismatch");
				return error(errorMessage.c_str());
			}			
			if(theOffer.paymentOptions > 0 && !ValidatePaymentOptionsMask(theOffer.paymentOptions))
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1027 - " + _("Invalid payment option");
				return error(errorMessage.c_str());
			}
			if(!theOffer.accept.IsNull())
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1028 - " + _("Cannot have accept information on offer update");
				return error(errorMessage.c_str());
			}
			if ( theOffer.vchOffer != vvchArgs[0])
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1029 - " + _("Offer input and offer guid mismatch");
				return error(errorMessage.c_str());
			}
			if(!theOffer.linkWhitelist.entries.empty() && theOffer.linkWhitelist.entries[0].nDiscountPct > 99 && theOffer.linkWhitelist.entries[0].nDiscountPct != 127)
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1030 - " + _("Discount must be between 0 and 99");
				return error(errorMessage.c_str());
			}

			if(theOffer.nQty < -1)
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1031 - " + _("Quantity must be greater than or equal to -1");
				return error(errorMessage.c_str());
			}
			if(!theOffer.vchCert.empty() && theOffer.nQty != 1)
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1032 - " + _("Quantity must be 1 for a digital offer");
				return error(errorMessage.c_str());
			}
			if(theOffer.nPrice <= 0)
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1033 - " + _("Offer price must be greater than 0");
				return error(errorMessage.c_str());
			}
			if(theOffer.nCommission > 100 || theOffer.nCommission < -90)
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1034 - " + _("Commission must between -90 and 100");
				return error(errorMessage.c_str());
			}
			break;
		case OP_OFFER_ACCEPT:
			theOfferAccept = theOffer.accept;
			if(!IsIdentityOp(prevIdentityOp) || vvchPrevIdentityArgs.empty() || theOfferAccept.vchBuyerIdentity != vvchPrevIdentityArgs[0])
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1035 - " + _("Identity input mismatch");
				return error(errorMessage.c_str());
			}
			if(!theOfferAccept.feedback.empty())
			{
				if(vvchArgs.size() <= 2 || vvchArgs[2] != vchFromString("1"))
				{
					errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1036 - " + _("Invalid feedback transaction");
					return error(errorMessage.c_str());
				}
				if(theOfferAccept.feedback[0].vchFeedback.empty())
				{
					errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1037 - " + _("Cannot leave empty feedback");
					return error(errorMessage.c_str());
				}
				if(theOfferAccept.feedback[0].vchFeedback.size() > MAX_NAME_LENGTH)
				{
					errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1038 - " + _("Feedback too long");
					return error(errorMessage.c_str());
				}
				if(theOfferAccept.feedback.size() > 1)
				{
					errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1039 - " + _("Cannot only leave one feedback per transaction");
					return error(errorMessage.c_str());
				}
				break;
			}
			else
			{
                if(!IsValidPaymentOption(theOfferAccept.nPaymentOption))
                {
                    errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1040 - " + _("Invalid payment option");
                    return error(errorMessage.c_str());
                }
			}

			if (theOfferAccept.IsNull())
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1041 - " + _("Offeraccept object cannot be empty");
				return error(errorMessage.c_str());
			}
			if (!IsValidIdentityName(theOfferAccept.vchBuyerIdentity))
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1042 - " + _("Invalid offer buyer identity");
				return error(errorMessage.c_str());
			}
			if (vvchArgs.size() <= 1 || vvchArgs[1].size() > MAX_GUID_LENGTH)
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1043 - " + _("Offeraccept transaction with guid too big");
				return error(errorMessage.c_str());
			}
			if (theOfferAccept.vchAcceptRand.size() > MAX_GUID_LENGTH)
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1044 - " + _("Offer accept hex guid too long");
				return error(errorMessage.c_str());
			}
			if (theOfferAccept.vchMessage.size() > MAX_ENCRYPTED_NAME_LENGTH)
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1045 - " + _("Payment message too long");
				return error(errorMessage.c_str());
			}
			if (theOffer.vchOffer != vvchArgs[0])
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1046 - " + _("Offer input and offer guid mismatch");
				return error(errorMessage.c_str());
			}

			break;

		default:
			errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1047 - " + _("Offer transaction has unknown op");
			return error(errorMessage.c_str());
		}
	}


	if (!fJustCheck ) {
		COffer serializedOffer;
		if(op != OP_OFFER_ACTIVATE) {
			// save serialized offer for later use
			serializedOffer = theOffer;
			// load the offer data from the DB
			if(!GetVtxOfOffer(vvchArgs[0], theOffer, vtxPos))
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1048 - " + _("Failed to read from offer DB");
				return true;
			}
			if(serializedOffer.vchIdentity != theOffer.vchIdentity)
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1049 - " + _("Offer identity mismatch");
				serializedOffer.vchIdentity = theOffer.vchIdentity;
			}
		}
		// If update, we make the serialized offer the master
		// but first we assign fields from the DB since
		// they are not shipped in an update txn to keep size down
		if(op == OP_OFFER_UPDATE) {
			serializedOffer.vchLinkOffer = theOffer.vchLinkOffer;
			serializedOffer.vchOffer = theOffer.vchOffer;
			serializedOffer.nSold = theOffer.nSold;
			// cannot edit safety level
			serializedOffer.safetyLevel = theOffer.safetyLevel;
			serializedOffer.accept.SetNull();
			theOffer = serializedOffer;
			if(!vtxPos.empty())
			{
				const COffer& dbOffer = vtxPos.back();
				// if updating whitelist, we dont allow updating any offer details
				if(theOffer.linkWhitelist.entries.size() > 0)
					theOffer = dbOffer;
				else
				{
					// whitelist must be preserved in serialOffer and db offer must have the latest in the db for whitelists
					theOffer.linkWhitelist.entries = dbOffer.linkWhitelist.entries;
					// some fields are only updated if they are not empty to limit txn size, rpc sends em as empty if we arent changing them
					if(serializedOffer.sCategory.empty())
						theOffer.sCategory = dbOffer.sCategory;
					if(serializedOffer.sTitle.empty())
						theOffer.sTitle = dbOffer.sTitle;
					if(serializedOffer.sDescription.empty())
						theOffer.sDescription = dbOffer.sDescription;
					if(serializedOffer.vchCert.empty())
						theOffer.vchCert = dbOffer.vchCert;
					if(serializedOffer.vchGeoLocation.empty())
						theOffer.vchGeoLocation = dbOffer.vchGeoLocation;
					if(serializedOffer.sCurrencyCode.empty())
						theOffer.sCurrencyCode = dbOffer.sCurrencyCode;
					if(serializedOffer.paymentOptions <= 0)
						theOffer.paymentOptions = dbOffer.paymentOptions;

					// user can't update safety level after creation
					theOffer.safetyLevel = dbOffer.safetyLevel;

					// non linked offers cant edit commission
					if(theOffer.vchLinkOffer.empty())
						theOffer.nCommission = 0;

					if(!theOffer.vchLinkIdentity.empty())
						theOffer.vchIdentity = theOffer.vchLinkIdentity;
					theOffer.vchLinkIdentity.clear();
				}
			}
		}
		else if(op == OP_OFFER_ACTIVATE)
		{
			if (pofferdb->ExistsOffer(vvchArgs[0]))
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1050 - " + _("Offer already exists");
				return true;
			}
			// if this is a linked offer activate, then add identity to the whitelist
			if(!theOffer.vchLinkOffer.empty())
			{
				if (!GetVtxOfOffer( theOffer.vchLinkOffer, linkOffer, offerVtxPos))
				{
					errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1051 - " + _("Linked offer not found. It may be expired");
				}
				else
				{
					// if creating a linked offer we set some mandatory fields to the parent
					theOffer.nQty = linkOffer.nQty;
					theOffer.sCurrencyCode = linkOffer.sCurrencyCode;
					theOffer.vchCert = linkOffer.vchCert;
					theOffer.SetPrice(linkOffer.nPrice);
					theOffer.sCategory = linkOffer.sCategory;
					theOffer.sTitle = linkOffer.sTitle;
					theOffer.safeSearch = linkOffer.safeSearch;
					theOffer.paymentOptions = linkOffer.paymentOptions;
					linkOffer.PutToOfferList(offerVtxPos);
					// write parent offer

					if (!dontaddtodb && !pofferdb->WriteOffer(theOffer.vchLinkOffer, offerVtxPos))
					{
						errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1052 - " + _("Failed to write to offer link to DB");
						return error(errorMessage.c_str());
					}
				}
			}
			// init sold to 0
			theOffer.nSold = 0;
		}
		else if (op == OP_OFFER_ACCEPT) {
			theOfferAccept = serializedOffer.accept;
			CTransaction acceptTx;
			COfferAccept offerAccept;
			COffer acceptOffer;

			if(theOfferAccept.bPaymentAck)
			{
				if (!GetOfferAccept(vvchArgs[0], vvchArgs[1], acceptOffer, offerAccept))
				{
					errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1053 - " + _("Could not find offer accept from mempool or disk");
					return true;
				}
				if(!acceptOffer.vchLinkOffer.empty())
				{
					if(!GetVtxOfOffer( acceptOffer.vchLinkOffer, linkOffer, offerVtxPos))
					{
						errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1054 - " + _("Could not get linked offer");
						return true;
					}
					if(theOfferAccept.vchBuyerIdentity != linkOffer.vchIdentity)
					{
						errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1055 - " + _("Only root merchant can acknowledge offer payment");
						return true;
					}
				}	
				else
				{
					if(theOfferAccept.vchBuyerIdentity != theOffer.vchIdentity)
					{
						errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1056 - " + _("Only merchant can acknowledge offer payment");
						return true;
					}
				}
				if(offerAccept.bPaymentAck)
				{
					errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1057 - " + _("Offer payment already acknowledged");
				}
				theOffer.txHash = tx.GetHash();
				theOffer.accept = offerAccept;
				theOffer.accept.bPaymentAck = true;
				theOffer.nHeight = nHeight;
				theOffer.PutToOfferList(vtxPos);
				// write offer

				if (!dontaddtodb && !pofferdb->WriteOffer(vvchArgs[0], vtxPos))
				{
					errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1058 - " + _("Failed to write to offer DB");
					return error(errorMessage.c_str());
				}
				if (fDebug)
					LogPrintf( "CONNECTED OFFER ACK: op=%s offer=%s title=%s qty=%u hash=%s height=%d\n",
						offerFromOp(op).c_str(),
						stringFromVch(vvchArgs[0]).c_str(),
						stringFromVch(theOffer.sTitle).c_str(),
						theOffer.nQty,
						tx.GetHash().ToString().c_str(),
						nHeight);
				return true;
			}
			else if(!theOfferAccept.feedback.empty())
			{
				if (!GetOfferAccept(vvchArgs[0], vvchArgs[1], acceptOffer, offerAccept))
				{
					errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1059 - " + _("Could not find offer accept from mempool or disk");
					return true;
				}
				// if feedback is for buyer then we need to ensure attached input identity was from seller
				if(theOfferAccept.feedback[0].nFeedbackUserFrom == FEEDBACKBUYER)
				{
					if(theOfferAccept.vchBuyerIdentity != offerAccept.vchBuyerIdentity)
					{
						errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1060 - " + _("Only buyer can leave the seller feedback");
						return true;
					}
				}
				else if(theOfferAccept.feedback[0].nFeedbackUserFrom == FEEDBACKSELLER)
				{
					if(theOfferAccept.vchBuyerIdentity != acceptOffer.vchIdentity)
					{
						errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1061 - " + _("Only seller can leave the buyer feedback");
						return true;
					}
				}
				else
				{
					errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1062 - " + _("Unknown feedback user type");
					return true;
				}
				int numBuyerRatings, numSellerRatings, feedbackBuyerCount, numArbiterRatings, feedbackSellerCount, feedbackArbiterCount;
				FindFeedback(offerAccept.feedback, numBuyerRatings, numSellerRatings, numArbiterRatings,feedbackBuyerCount, feedbackSellerCount, feedbackArbiterCount);
				// has this user already rated? if so set desired rating to 0
				if(theOfferAccept.feedback[0].nFeedbackUserFrom == FEEDBACKBUYER && numBuyerRatings > 0)
					theOfferAccept.feedback[0].nRating = 0;
				else if(theOfferAccept.feedback[0].nFeedbackUserFrom == FEEDBACKSELLER && numSellerRatings > 0)
					theOfferAccept.feedback[0].nRating = 0;
				if(feedbackBuyerCount >= 10 && theOfferAccept.feedback[0].nFeedbackUserFrom == FEEDBACKBUYER)
				{
					errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1063 - " + _("Cannot exceed 10 buyer feedbacks");
					return true;
				}
				else if(feedbackSellerCount >= 10 && theOfferAccept.feedback[0].nFeedbackUserFrom == FEEDBACKSELLER)
				{
					errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1064 - " + _("Cannot exceed 10 seller feedbacks");
					return true;
				}
				theOfferAccept.feedback[0].txHash = tx.GetHash();
				theOfferAccept.feedback[0].nHeight = nHeight;
				if(!dontaddtodb)
					HandleAcceptFeedback(theOfferAccept.feedback[0], acceptOffer, vtxPos);
				if (fDebug)
					LogPrintf( "CONNECTED OFFER FEEDBACK: op=%s offer=%s title=%s qty=%u hash=%s height=%d\n",
						offerFromOp(op).c_str(),
						stringFromVch(vvchArgs[0]).c_str(),
						stringFromVch(theOffer.sTitle).c_str(),
						theOffer.nQty,
						tx.GetHash().ToString().c_str(),
						nHeight);
				return true;

			}
			if (GetOfferAccept(vvchArgs[0], vvchArgs[1], acceptOffer, offerAccept))
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1065 - " + _("Offer payment already exists");
				return true;
			}

			myPriceOffer.nHeight = theOfferAccept.nAcceptHeight;
			// if linked offer then get offer info from root offer history because the linked offer may not have history of changes (root offer can update linked offer without tx)
			myPriceOffer.GetOfferFromList(vtxPos);

			if(myPriceOffer.bPrivate && !myPriceOffer.linkWhitelist.IsNull())
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1066 - " + _("Cannot purchase this private offer, must purchase through an affiliate");
				return true;
			}
			if(!myPriceOffer.vchLinkOffer.empty())
			{
				if(!GetVtxOfOffer( myPriceOffer.vchLinkOffer, linkOffer, offerVtxPos))
				{
					errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1067 - " + _("Could not get linked offer");
					return true;
				}
				linkOffer.nHeight = theOfferAccept.nAcceptHeight;
				linkOffer.GetOfferFromList(offerVtxPos);
				vector<CIdentityIndex> vtxIdentity;
				bool isExpired = false;
				if(!GetVtxOfIdentity(linkOffer.vchIdentity, linkIdentity, vtxIdentity, isExpired))
				{
					errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1068 - " + _("Cannot find identity for this linked offer. It may be expired");
					return true;
				}
				if(!IsPaymentOptionInMask(linkOffer.paymentOptions, theOfferAccept.nPaymentOption))
				{
					errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1069 - " + _("User selected payment option not found in list of accepted offer payment options");
					return true;
				}
				else if(!theOfferAccept.txExtId.IsNull() && (linkOffer.paymentOptions == PAYMENTOPTION_DYN || theOfferAccept.nPaymentOption == PAYMENTOPTION_DYN))
				{
					errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1070 - " + _("External chain payment cannot be made with this offer");
					return true;
				}
				linkOffer.linkWhitelist.GetLinkEntryByHash(theOffer.vchIdentity, entry);
				if(entry.IsNull())
				{
					errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1071 - " + _("Linked offer identity does not exist on the root offer affiliate list");
					return true;
				}
				if(theOffer.nCommission <= -entry.nDiscountPct)
				{
					errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1072 - " + _("This resold offer must be of higher price than the original offer including any discount");
					return true;
				}
			}
			if(!IsPaymentOptionInMask(myPriceOffer.paymentOptions, theOfferAccept.nPaymentOption))
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1073 - " + _("User selected payment option not found in list of accepted offer payment options");
				return true;
			}
			else if(!theOfferAccept.txExtId.IsNull() && (myPriceOffer.paymentOptions == PAYMENTOPTION_DYN || theOfferAccept.nPaymentOption == PAYMENTOPTION_DYN))
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1074 - " + _("External chain payment cannot be made with this offer");
				return true;
			}		
			if(theOfferAccept.txExtId.IsNull() && theOfferAccept.nPaymentOption != PAYMENTOPTION_DYN)
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1075 - " + _("External chain payment txid missing");
				return true;
			}
			if(myPriceOffer.sCategory.size() > 0 && boost::algorithm::starts_with(stringFromVch(myPriceOffer.sCategory), "wanted"))
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1076 - " + _("Cannot purchase a wanted offer");
				return true;
			}
			vector<CIdentityIndex> vtxIdentity;
			bool isExpired = false;
			if(!GetVtxOfIdentity(myPriceOffer.vchIdentity, identity, vtxIdentity, isExpired))
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1077 - " + _("Cannot find identity for this offer. It may be expired");
				return true;
			}
			// check that user pays enough in dynamic if the currency of the offer is not external purchase
			if(theOfferAccept.txExtId.IsNull())
			{
				CAmount nPrice;
				CAmount nCommission;
				// try to get the whitelist entry here from the sellers whitelist, apply the discount with GetPrice()
				if(myPriceOffer.vchLinkOffer.empty())
				{
					myPriceOffer.linkWhitelist.GetLinkEntryByHash(theOfferAccept.vchBuyerIdentity, entry);
					nPrice = myPriceOffer.GetPrice(entry);
					nCommission = 0;
				}
				else
				{
					linkOffer.linkWhitelist.GetLinkEntryByHash(myPriceOffer.vchIdentity, entry);
					nPrice = linkOffer.GetPrice(entry);
					nCommission = myPriceOffer.GetPrice() - nPrice;
				}
				if(nPrice != theOfferAccept.nPrice)
				{
					errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1078 - " + _("Offer payment does not specify the correct payment amount");
					return true;
				}
				CAmount nTotalValue = ( nPrice * theOfferAccept.nQty );
				CAmount nTotalCommission = ( nCommission * theOfferAccept.nQty );
				int nOutPayment, nOutCommission;
				nOutPayment = FindOfferAcceptPayment(tx, nTotalValue);
				if(nOutPayment < 0)
				{
					errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1079 - " + _("Offer payment does not pay enough according to the offer price");
					return true;
				}
				if(!myPriceOffer.vchLinkOffer.empty())
				{
					nOutCommission = FindOfferAcceptPayment(tx, nTotalCommission);
					if(nOutCommission < 0)
					{
						errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1080 - " + _("Offer payment does not include enough commission to affiliate");
						return true;
					}
					CDynamicAddress destaddy;
					if (!ExtractDestination(tx.vout[nOutPayment].scriptPubKey, payDest))
					{
						errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1081 - " + _("Could not extract payment destination from scriptPubKey");
						return true;
					}
					destaddy = CDynamicAddress(payDest);
					CDynamicAddress commissionaddy;
					if (!ExtractDestination(tx.vout[nOutCommission].scriptPubKey, commissionDest))
					{
						errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1082 - " + _("Could not extract commission destination from scriptPubKey");
						return true;
					}
					commissionaddy = CDynamicAddress(commissionDest);
					CDynamicAddress identitylinkaddy;
					GetAddress(linkIdentity, &identitylinkaddy);
					if(identitylinkaddy.ToString() != destaddy.ToString())
					{
						errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1083 - " + _("Payment destination does not match merchant address");
						return true;
					}
					CDynamicAddress identityaddy;
					GetAddress(identity, &identityaddy);
					if(identityaddy.ToString() != commissionaddy.ToString())
					{
						errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1084 - " + _("Commission destination does not match affiliate address");
						return true;
					}
				}
				else
				{
					
					if (!ExtractDestination(tx.vout[nOutPayment].scriptPubKey, payDest))
					{
						errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1085 - " + _("Could not extract payment destination from scriptPubKey");
						return true;
					}
					CDynamicAddress destaddy(payDest);
					CDynamicAddress identityaddy;
					GetAddress(identity, &identityaddy);
					if(identityaddy.ToString() != destaddy.ToString())
					{
						errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1086 - " + _("Payment destination does not match merchant address");
						return true;
					}
				}
			}
			// check that the script for the offer update is sent to the correct destination
			if (!ExtractDestination(tx.vout[nOut].scriptPubKey, dest))
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1087 - " + _("Cannot extract destination from output script");
				return true;
			}
			CDynamicAddress destaddy(dest);
			CDynamicAddress identityaddy;
			GetAddress(identity, &identityaddy);
			if(identityaddy.ToString() != destaddy.ToString())
			{
				errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1088 - " + _("Payment address does not match merchant address");
				return true;
			}
			theOfferAccept.vchAcceptRand = vvchArgs[1];
			// decrease qty + increase # sold
			if(theOfferAccept.nQty <= 0)
 				theOfferAccept.nQty = 1;
			int nQty = theOffer.nQty;
			// if this is a linked offer we must update the linked offer qty
			if (!linkOffer.IsNull())
			{
				linkOffer = offerVtxPos.back();
				nQty = linkOffer.nQty;
			}
			if(nQty != -1)
			{
				if(theOfferAccept.nQty > nQty)
				{
					errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1089 - " + _("Not enough quantity left in this offer for this purchase");
					return true;
				}
				nQty -= theOfferAccept.nQty;
			}
 			theOffer.nSold++;
			theOffer.nQty = nQty;
			theOffer.accept = theOfferAccept;
			if (!linkOffer.IsNull())
			{
				linkOffer.nHeight = nHeight;
				linkOffer.nQty = nQty;
				linkOffer.nSold++;
				linkOffer.txHash = tx.GetHash();
				linkOffer.accept = theOfferAccept;
				linkOffer.PutToOfferList(offerVtxPos);
				if (!dontaddtodb && !pofferdb->WriteOffer(myPriceOffer.vchLinkOffer, offerVtxPos))
				{
					errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1090 - " + _("Failed to write to offer link to DB");
					return error(errorMessage.c_str());
				}
			}
			if(!theOfferAccept.txExtId.IsNull())
			{
				if(pofferdb->ExistsOfferTx(theOfferAccept.txExtId) || pescrowdb->ExistsEscrowTx(theOfferAccept.txExtId))
				{
					errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1091 - " + _("BTC Transaction ID specified was already used to pay for an offer");
					return true;
				}
				if(!dontaddtodb && !pofferdb->WriteOfferTx(theOffer.vchOffer, theOfferAccept.txExtId))
				{
					errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1092 - " + _("Failed to BTC Transaction ID to DB");
					return error(errorMessage.c_str());
				}
			}

		}


		if(op == OP_OFFER_UPDATE)
		{
			// ensure the accept is null as this should just have the offer information and no accept information
			theOffer.accept.SetNull();
			// if the txn whitelist entry exists (meaning we want to remove or add)
			if(serializedOffer.linkWhitelist.entries.size() == 1)
			{
				// special case we use to remove all entries
				if(serializedOffer.linkWhitelist.entries[0].nDiscountPct == 127)
				{
					if(theOffer.linkWhitelist.entries.empty())
					{
						errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1093 - " + _("Whitelist is already empty");
					}
					else
						theOffer.linkWhitelist.SetNull();
				}
				// the stored offer has this entry meaning we want to remove this entry
				else if(theOffer.linkWhitelist.GetLinkEntryByHash(serializedOffer.linkWhitelist.entries[0].identityLinkVchRand, entry))
				{
					theOffer.linkWhitelist.RemoveWhitelistEntry(serializedOffer.linkWhitelist.entries[0].identityLinkVchRand);
				}
				// we want to add it to the whitelist
				else
				{
					if(theOffer.linkWhitelist.entries.size() > 20)
					{
						errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1094 -" + _("Too many affiliates for this offer");
					}
					else if(!serializedOffer.linkWhitelist.entries[0].identityLinkVchRand.empty())
					{
						if (GetTxOfIdentity(serializedOffer.linkWhitelist.entries[0].identityLinkVchRand, theIdentity, identityTx))
						{
							theOffer.linkWhitelist.PutWhitelistEntry(serializedOffer.linkWhitelist.entries[0]);
						}
						else
						{
							errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1095 - " + _("Cannot find the identity you are trying to offer affiliate list. It may be expired");
						}
					}
				}

			}
			// if this offer is linked to a parent update it with parent information
			if(!theOffer.vchLinkOffer.empty())
			{
				theOffer.nQty = linkOffer.nQty;
				theOffer.vchCert = linkOffer.vchCert;
				theOffer.paymentOptions = linkOffer.paymentOptions;
				theOffer.SetPrice(linkOffer.nPrice);
			}
		}
		theOffer.nHeight = nHeight;
		theOffer.txHash = tx.GetHash();
		theOffer.PutToOfferList(vtxPos);
		// write offer

		if (!dontaddtodb && !pofferdb->WriteOffer(vvchArgs[0], vtxPos))
		{
			errorMessage = "DYNAMIC_OFFER_CONSENSUS_ERROR: ERRCODE: 1096 - " + _("Failed to write to offer DB");
			return error(errorMessage.c_str());
		}

		// debug
		if (fDebug)
			LogPrintf( "CONNECTED OFFER: op=%s offer=%s title=%s qty=%u hash=%s height=%d\n",
				offerFromOp(op).c_str(),
				stringFromVch(vvchArgs[0]).c_str(),
				stringFromVch(theOffer.sTitle).c_str(),
				theOffer.nQty,
				tx.GetHash().ToString().c_str(),
				nHeight);
	}
	return true;
}

UniValue offernew(const UniValue& params, bool fHelp) {
	if (fHelp || params.size() < 7 || params.size() > 12)
		throw runtime_error(
		"offernew <identity> <category> <title> <quantity> <price> <description> <currency> [cert. guid] [payment options=DYN] [geolocation=''] [safe search=Yes] [private='0']\n"
						"<identity> An identity you own.\n"
						"<category> category, 255 chars max.\n"
						"<title> title, 255 chars max.\n"
						"<quantity> quantity, > 0 or -1 for infinite\n"
						"<price> price in <currency>, > 0\n"
						"<description> description, 1 KB max.\n"
						"<currency> The currency code that you want your offer to be in ie: USD.\n"
						"<cert. guid> Set this to the guid of a certificate you wish to sell\n"
						"<paymentOptions> 'DYN' to accept Dynamic only, 'BTC' for Bitcoin only, 'SEQ' for Sequence only, or a |-delimited string to accept multiple currencies (e.g. 'BTC|DYN' to accept BTC or DYN). Leave empty for default. Defaults to 'DYN'.\n"
						"<geolocation> set to your geolocation. Defaults to empty. \n"
						"<safe search> set to No if this offer should only show in the search when safe search is not selected. Defaults to Yes (offer shows with or without safe search selected in search lists).\n"
						"<private> set to 1 if this offer should be private not be searchable. Defaults to 0.\n"
						+ HelpRequiringPassphrase());
	// gather inputs
	float fPrice;
	vector<unsigned char> vchIdentity = vchFromValue(params[0]);

	CTransaction identitytx;
	CIdentityIndex identity;
	const CWalletTx *wtxIdentityIn = NULL;
	if (!GetTxOfIdentity(vchIdentity, identity, identitytx))
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1500 - " + _("Could not find an identity with this name"));
    if(!IsMyIdentity(identity)) {
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1501 - " + _("This identity is not yours"));
    }
	COutPoint outPoint;
	int numResults  = identityunspent(vchIdentity, outPoint);	
	wtxIdentityIn = pwalletMain->GetWalletTx(outPoint.hash);
	if (wtxIdentityIn == NULL)
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1502 - " + _("This identity is not in your wallet"));

	vector<unsigned char> vchCat = vchFromValue(params[1]);
	vector<unsigned char> vchTitle = vchFromValue(params[2]);
	vector<unsigned char> vchCurrency = vchFromValue(params[6]);
	vector<unsigned char> vchDesc;
	vector<unsigned char> vchCert;

	int nQty;

	try {
		nQty =  boost::lexical_cast<int>(params[3].get_str());
	} catch (std::exception &e) {
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1503 - " + _("Invalid quantity value, must be less than 4294967296 and greater than or equal to -1"));
	}
	fPrice = boost::lexical_cast<float>(params[4].get_str());
	vchDesc = vchFromValue(params[5]);
	CScript scriptPubKeyOrig;
	CScript scriptPubKey;
	if(params.size() >= 8)
	{

		vchCert = vchFromValue(params[7]);
		if(vchCert == vchFromString("nocert"))
			vchCert.clear();
	}

	// payment options - get payment options string if specified otherwise default to DYN
	string paymentOptions = "DYN";
	if(params.size() >= 9 && !params[8].get_str().empty() && params[8].get_str() != "NONE")
	{
		paymentOptions = params[8].get_str();
		boost::algorithm::to_upper(paymentOptions);
	}
	// payment options - validate payment options string
	if(!ValidatePaymentOptionsString(paymentOptions))
	{
		// TODO change error number to something unique
		string err = "DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1504 - " + _("Could not validate the payment options value");
		throw runtime_error(err.c_str());
	}
	// payment options - and convert payment options string to a bitmask for the txn
	unsigned char paymentOptionsMask = (unsigned char) GetPaymentOptionsMaskFromString(paymentOptions);

	string strGeoLocation = "";
	if(params.size() >= 10)
	{
		strGeoLocation = params[9].get_str();
	}
	string strSafeSearch = "Yes";
	if(params.size() >= 11)
	{
		strSafeSearch = params[10].get_str();
	}
	bool bPrivate = false;
	if (params.size() >= 12) bPrivate = boost::lexical_cast<int>(params[11].get_str()) == 1? true: false;

	int precision = 2;
	CAmount nPricePerUnit = convertCurrencyCodeToDynamic(identity.vchIdentityPeg, vchCurrency, fPrice, chainActive.Tip()->nHeight, precision);
	if(nPricePerUnit == 0)
	{
		string err = "DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1505 - " + _("Could not find currency in the peg identity");
		throw runtime_error(err.c_str());
	}
	// if we are selling a cert ensure it exists and pubkey's match (to ensure it doesnt get transferred prior to accepting by user)
	if(!vchCert.empty())
	{
		vector<CCert> vtxCert;
		CCert theCert;
		if (!GetVtxOfCert( vchCert, theCert, vtxCert))
		{
			throw runtime_error("DYNAMIC_OFFER_RPC_ERROR: ERRCODE: 1506 - " + _("Creating an offer with a cert that does not exist"));
		}
		else if(!boost::algorithm::starts_with(stringFromVch(vchCat), "certificates"))
		{
			throw runtime_error("DYNAMIC_OFFER_RPC_ERROR: ERRCODE: 1507 - " + _("Offer selling a certificate must use a certificate category"));
		}
		else if(theCert.vchIdentity != vchIdentity)
		{
			throw runtime_error("DYNAMIC_OFFER_RPC_ERROR: ERRCODE: 1508 - " + _("Cannot create this offer because the certificate identity does not match the offer identity"));
		}
	}
	else if(boost::algorithm::starts_with(stringFromVch(vchCat), "certificates"))
	{
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR: ERRCODE: 1509 - " + _("Offer not selling a certificate cannot use a certificate category"));
	}
	// this is a dynamic transaction
	CWalletTx wtx;

	// generate rand identifier
	vector<unsigned char> vchOffer = vchFromString(GenerateDynamicGuid());
	EnsureWalletIsUnlocked();


	// unserialize offer from txn, serialize back
	// build offer
	COffer newOffer;
	newOffer.vchIdentity = identity.vchIdentity;
	newOffer.vchOffer = vchOffer;
	newOffer.sCategory = vchCat;
	newOffer.sTitle = vchTitle;
	newOffer.sDescription = vchDesc;
	newOffer.nQty = nQty;
	newOffer.nHeight = chainActive.Tip()->nHeight;
	newOffer.SetPrice(nPricePerUnit);
	newOffer.vchCert = vchCert;
	newOffer.sCurrencyCode = vchCurrency;
	newOffer.bPrivate = bPrivate;
	newOffer.paymentOptions = paymentOptionsMask;
	newOffer.safetyLevel = 0;
	newOffer.safeSearch = strSafeSearch == "Yes"? true: false;
	newOffer.vchGeoLocation = vchFromString(strGeoLocation);

	vector<unsigned char> data;
	newOffer.Serialize(data);
    uint256 hash = Hash(data.begin(), data.end());

    vector<unsigned char> vchHashOffer = vchFromValue(hash.GetHex());
	CDynamicAddress identityAddress;
	GetAddress(identity, &identityAddress, scriptPubKeyOrig);
	scriptPubKey << CScript::EncodeOP_N(OP_OFFER_ACTIVATE) << vchOffer << vchHashOffer << OP_2DROP << OP_DROP;
	scriptPubKey += scriptPubKeyOrig;
	CScript scriptPubKeyIdentity;
	scriptPubKeyIdentity << CScript::EncodeOP_N(OP_IDENTITY_UPDATE) << identity.vchIdentity << identity.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
	scriptPubKeyIdentity += scriptPubKeyOrig;

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
	CreateFeeRecipient(scriptData, identity.vchIdentityPeg, chainActive.Tip()->nHeight, data, fee);
	vecSend.push_back(fee);



	SendMoneyDynamic(vecSend, recipient.nAmount+fee.nAmount+identityRecipient.nAmount, false, wtx, wtxIdentityIn, outPoint.n, identity.multiSigInfo.vchIdentityes.size() > 0);
	UniValue res(UniValue::VARR);
	if(identity.multiSigInfo.vchIdentityes.size() > 0)
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
			res.push_back(stringFromVch(vchOffer));
		}
		else
		{
			res.push_back(hex_str);
			res.push_back(stringFromVch(vchOffer));
			res.push_back("false");
		}
	}
	else
	{
		res.push_back(wtx.GetHash().GetHex());
		res.push_back(stringFromVch(vchOffer));
	}

	return res;
}

UniValue offerlink(const UniValue& params, bool fHelp) {
	if (fHelp || params.size() < 3 || params.size() > 4)
		throw runtime_error(
		"offerlink <identity> <guid> <commission> [description]\n"
						"<identity> An identity you own.\n"
						"<guid> offer guid that you are linking to\n"
						"<commission> percentage of profit desired over original offer price, > 0, ie: 5 for 5%\n"
						"<description> description, 1 KB max. Defaults to original description. Leave as '' to use default.\n"
						+ HelpRequiringPassphrase());
	// gather inputs
	COfferLinkWhitelistEntry whiteListEntry;
	vector<unsigned char> vchIdentity = vchFromValue(params[0]);


	CTransaction identitytx;
	CIdentityIndex identity;
	const CWalletTx *wtxIdentityIn = NULL;
	if (!GetTxOfIdentity(vchIdentity, identity, identitytx))
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1510 - " + _("Could not find an identity with this name"));
    if(!IsMyIdentity(identity)) {
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1511 - " + _("This identity is not yours"));
    }
	COutPoint outPoint;
	int numResults  = identityunspent(vchIdentity, outPoint);	
	wtxIdentityIn = pwalletMain->GetWalletTx(outPoint.hash);
	if (wtxIdentityIn == NULL)
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1512 - " + _("This identity is not in your wallet"));

	vector<unsigned char> vchLinkOffer = vchFromValue(params[1]);
	vector<unsigned char> vchDesc;
	// look for a transaction with this key
	CTransaction tx;
	COffer linkOffer;
	if (vchLinkOffer.empty() || !GetTxOfOffer( vchLinkOffer, linkOffer, tx))
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1513 - " + _("Could not find an offer with this guid"));

	int commissionInteger = boost::lexical_cast<int>(params[2].get_str());
	if(params.size() >= 4)
	{

		vchDesc = vchFromValue(params[3]);
		if(vchDesc.empty())
		{
			vchDesc = linkOffer.sDescription;
		}
	}
	else
	{
		vchDesc = linkOffer.sDescription;
	}
	COfferLinkWhitelistEntry entry;
	if(linkOffer.linkWhitelist.GetLinkEntryByHash(vchIdentity, entry))
	{
		if(commissionInteger <= -entry.nDiscountPct)
		{
			throw runtime_error("DYNAMIC_OFFER_RPC_ERROR: ERRCODE: 1514 - " + _("This resold offer must be of higher price than the original offer including any discount"));
		}
	}
	// make sure identity exists in the root offer affiliate list
	else
	{
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR: ERRCODE: 1515 - " + _("Cannot find this identity in the parent offer affiliate list"));
	}
	if (!linkOffer.vchLinkOffer.empty())
	{
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR: ERRCODE: 1516 - " + _("Cannot link to an offer that is already linked to another offer"));
	}
	else if(linkOffer.sCategory.size() > 0 && boost::algorithm::starts_with(stringFromVch(linkOffer.sCategory), "wanted"))
	{
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR: ERRCODE: 1517 - " + _("Cannot link to a wanted offer"));
	}
	
	CScript scriptPubKeyOrig;
	CScript scriptPubKey;

	// this is a dynamic transaction
	CWalletTx wtx;


	// generate rand identifier
	vector<unsigned char> vchOffer = vchFromString(GenerateDynamicGuid());
	EnsureWalletIsUnlocked();

	// build offer
	COffer newOffer;
	newOffer.vchOffer = vchOffer;
	newOffer.vchIdentity = identity.vchIdentity;
	newOffer.sDescription = vchDesc;
	newOffer.SetPrice(linkOffer.GetPrice());
	newOffer.paymentOptions = linkOffer.paymentOptions;
	newOffer.nCommission = commissionInteger;
	newOffer.vchLinkOffer = vchLinkOffer;
	newOffer.nHeight = chainActive.Tip()->nHeight;
	//create offeractivate txn keys

	vector<unsigned char> data;
	newOffer.Serialize(data);
    uint256 hash = Hash(data.begin(), data.end());

    vector<unsigned char> vchHashOffer = vchFromValue(hash.GetHex());
	CDynamicAddress identityAddress;
	GetAddress(identity, &identityAddress, scriptPubKeyOrig);
	scriptPubKey << CScript::EncodeOP_N(OP_OFFER_ACTIVATE) << vchOffer << vchHashOffer << OP_2DROP << OP_DROP;
	scriptPubKey += scriptPubKeyOrig;
	CScript scriptPubKeyIdentity;
	scriptPubKeyIdentity << CScript::EncodeOP_N(OP_IDENTITY_UPDATE) << identity.vchIdentity << identity.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
	scriptPubKeyIdentity += scriptPubKeyOrig;


	string strError;

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
	CreateFeeRecipient(scriptData, identity.vchIdentityPeg, chainActive.Tip()->nHeight, data, fee);
	vecSend.push_back(fee);



	SendMoneyDynamic(vecSend, recipient.nAmount+fee.nAmount+identityRecipient.nAmount, false, wtx, wtxIdentityIn, outPoint.n, identity.multiSigInfo.vchIdentityes.size() > 0);

	UniValue res(UniValue::VARR);
	if(identity.multiSigInfo.vchIdentityes.size() > 0)
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
			res.push_back(stringFromVch(vchOffer));
		}
		else
		{
			res.push_back(hex_str);
			res.push_back(stringFromVch(vchOffer));
			res.push_back("false");
		}
	}
	else
	{
		res.push_back(wtx.GetHash().GetHex());
		res.push_back(stringFromVch(vchOffer));
	}
	return res;
}

UniValue offeraddwhitelist(const UniValue& params, bool fHelp) {
	if (fHelp || params.size() < 2 || params.size() > 3)
		throw runtime_error(
		"offeraddwhitelist <offer guid> <identity guid> [discount percentage]\n"
		"Add to the affiliate list of your offer(controls who can resell).\n"
						"<offer guid> offer guid that you are adding to\n"
						"<identity guid> identity guid representing an identity that you want to add to the affiliate list\n"
						"<discount percentage> percentage of discount given to affiliate for this offer. 0 to 99.\n"
						+ HelpRequiringPassphrase());

	// gather & validate inputs
	vector<unsigned char> vchOffer = vchFromValue(params[0]);
	vector<unsigned char> vchIdentity =  vchFromValue(params[1]);
	int nDiscountPctInteger = 0;

	if(params.size() >= 3)
		nDiscountPctInteger = boost::lexical_cast<int>(params[2].get_str());

	CWalletTx wtx;

	// this is a dynamic txn
	CScript scriptPubKeyOrig;
	// create OFFERUPDATE txn key
	CScript scriptPubKey;



	EnsureWalletIsUnlocked();

	// look for a transaction with this key
	CTransaction tx;
	COffer theOffer;
	if (!GetTxOfOffer( vchOffer, theOffer, tx))
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1518 - " + _("Could not find an offer with this guid"));

	CTransaction identitytx;
	CIdentityIndex theIdentity;
	const CWalletTx *wtxIdentityIn = NULL;
	if (!GetTxOfIdentity( theOffer.vchIdentity, theIdentity, identitytx))
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1519 - " + _("Could not find an identity with this name"));

	if(!IsMyIdentity(theIdentity)) {
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1520 - " + _("This identity is not yours"));
	}
	COutPoint outPoint;
	int numResults  = identityunspent(theOffer.vchIdentity, outPoint);	
	wtxIdentityIn = pwalletMain->GetWalletTx(outPoint.hash);
	if (wtxIdentityIn == NULL)
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1521 - " + _("This identity is not in your wallet"));

	CDynamicAddress identityAddress;
	GetAddress(theIdentity, &identityAddress, scriptPubKeyOrig);


	COfferLinkWhitelistEntry foundEntry;
	if(theOffer.linkWhitelist.GetLinkEntryByHash(vchIdentity, foundEntry))
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1522 - " + _("This identity entry already exists on affiliate list"));

	COfferLinkWhitelistEntry entry;
	entry.identityLinkVchRand = vchIdentity;
	entry.nDiscountPct = nDiscountPctInteger;
	theOffer.ClearOffer();
	theOffer.linkWhitelist.PutWhitelistEntry(entry);
	theOffer.nHeight = chainActive.Tip()->nHeight;


	vector<unsigned char> data;
	theOffer.Serialize(data);
    uint256 hash = Hash(data.begin(), data.end());

    vector<unsigned char> vchHashOffer = vchFromValue(hash.GetHex());
	scriptPubKey << CScript::EncodeOP_N(OP_OFFER_UPDATE) << vchOffer << vchHashOffer << OP_2DROP << OP_DROP;
	scriptPubKey += scriptPubKeyOrig;
	CScript scriptPubKeyIdentity;
	scriptPubKeyIdentity << CScript::EncodeOP_N(OP_IDENTITY_UPDATE) << theIdentity.vchIdentity << theIdentity.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
	scriptPubKeyIdentity += scriptPubKeyOrig;

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
		}
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
UniValue offerremovewhitelist(const UniValue& params, bool fHelp) {
	if (fHelp || params.size() != 2)
		throw runtime_error(
		"offerremovewhitelist <offer guid> <identity guid>\n"
		"Remove from the affiliate list of your offer(controls who can resell).\n"
						+ HelpRequiringPassphrase());
	// gather & validate inputs
	vector<unsigned char> vchOffer = vchFromValue(params[0]);
	vector<unsigned char> vchIdentity = vchFromValue(params[1]);

	CTransaction txCert;
	CCert theCert;
	CWalletTx wtx;

	// this is a dynamic txn
	CScript scriptPubKeyOrig;
	// create OFFERUPDATE txn keys
	CScript scriptPubKey;

	EnsureWalletIsUnlocked();

	// look for a transaction with this key
	CTransaction tx;
	COffer theOffer;
	const CWalletTx *wtxIdentityIn = NULL;
	if (!GetTxOfOffer( vchOffer, theOffer, tx))
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1523 - " + _("Could not find an offer with this guid"));
	CTransaction identitytx;
	CIdentityIndex theIdentity;
	if (!GetTxOfIdentity( theOffer.vchIdentity, theIdentity, identitytx))
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1524 - " + _("Could not find an identity with this name"));
	if(!IsMyIdentity(theIdentity)) {
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1525 - " + _("This identity is not yours"));
	}
	COutPoint outPoint;
	int numResults  = identityunspent(theOffer.vchIdentity, outPoint);	
	wtxIdentityIn = pwalletMain->GetWalletTx(outPoint.hash);
	if (wtxIdentityIn == NULL)
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1526 - " + _("This identity is not in your wallet"));

	CDynamicAddress identityAddress;
	GetAddress(theIdentity, &identityAddress, scriptPubKeyOrig);

	// create OFFERUPDATE txn keys
	COfferLinkWhitelistEntry foundEntry;
	if(!theOffer.linkWhitelist.GetLinkEntryByHash(vchIdentity, foundEntry))
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1527 - " + _("This identity entry was not found on affiliate list"));
	theOffer.ClearOffer();
	theOffer.nHeight = chainActive.Tip()->nHeight;
	theOffer.linkWhitelist.PutWhitelistEntry(foundEntry);

	vector<unsigned char> data;
	theOffer.Serialize(data);
    uint256 hash = Hash(data.begin(), data.end());

    vector<unsigned char> vchHashOffer = vchFromValue(hash.GetHex());
	scriptPubKey << CScript::EncodeOP_N(OP_OFFER_UPDATE) << vchOffer << vchHashOffer << OP_2DROP << OP_DROP;
	scriptPubKey += scriptPubKeyOrig;
	CScript scriptPubKeyIdentity;
	scriptPubKeyIdentity << CScript::EncodeOP_N(OP_IDENTITY_UPDATE) << theIdentity.vchIdentity << theIdentity.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
	scriptPubKeyIdentity += scriptPubKeyOrig;

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
		}
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
UniValue offerclearwhitelist(const UniValue& params, bool fHelp) {
	if (fHelp || params.size() != 1)
		throw runtime_error(
		"offerclearwhitelist <offer guid>\n"
		"Clear the affiliate list of your offer(controls who can resell).\n"
						+ HelpRequiringPassphrase());
	// gather & validate inputs
	vector<unsigned char> vchOffer = vchFromValue(params[0]);

	// this is a dynamicd txn
	CWalletTx wtx;
	CScript scriptPubKeyOrig;

	EnsureWalletIsUnlocked();

	// look for a transaction with this key
	CTransaction tx;
	COffer theOffer;
	const CWalletTx *wtxIdentityIn = NULL;
	if (!GetTxOfOffer( vchOffer, theOffer, tx))
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1528 - " + _("Could not find an offer with this guid"));
	CTransaction identitytx;
	CIdentityIndex theIdentity;
	if (!GetTxOfIdentity(theOffer.vchIdentity, theIdentity, identitytx))
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1529 - " + _("Could not find an identity with this name"));

	if(!IsMyIdentity(theIdentity)) {
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1530 - " + _("This identity is not yours"));
	}
	COutPoint outPoint;
	int numResults  = identityunspent(theOffer.vchIdentity, outPoint);	
	wtxIdentityIn = pwalletMain->GetWalletTx(outPoint.hash);
	if (wtxIdentityIn == NULL)
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1531 - " + _("This identity is not in your wallet"));

	CDynamicAddress identityAddress;
	GetAddress(theIdentity, &identityAddress, scriptPubKeyOrig);

	theOffer.ClearOffer();
	theOffer.nHeight = chainActive.Tip()->nHeight;
	// create OFFERUPDATE txn keys
	CScript scriptPubKey;

	COfferLinkWhitelistEntry entry;
	// special case to clear all entries for this offer
	entry.nDiscountPct = 127;
	theOffer.linkWhitelist.PutWhitelistEntry(entry);

	vector<unsigned char> data;
	theOffer.Serialize(data);
    uint256 hash = Hash(data.begin(), data.end());

    vector<unsigned char> vchHashOffer = vchFromValue(hash.GetHex());
	scriptPubKey << CScript::EncodeOP_N(OP_OFFER_UPDATE) << vchOffer << vchHashOffer << OP_2DROP << OP_DROP;
	scriptPubKey += scriptPubKeyOrig;
	CScript scriptPubKeyIdentity;
	scriptPubKeyIdentity << CScript::EncodeOP_N(OP_IDENTITY_UPDATE) << theIdentity.vchIdentity << theIdentity.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
	scriptPubKeyIdentity += scriptPubKeyOrig;

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
		}
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

UniValue offerwhitelist(const UniValue& params, bool fHelp) {
    if (fHelp || 1 != params.size())
        throw runtime_error("offerwhitelist <offer guid>\n"
                "List all affiliates for this offer.\n");
    UniValue oRes(UniValue::VARR);
    vector<unsigned char> vchOffer = vchFromValue(params[0]);
	// look for a transaction with this key
	CTransaction tx;
	COffer theOffer;
	vector<COffer> myVtxPos;
	if (!GetTxAndVtxOfOffer( vchOffer, theOffer, tx, myVtxPos, true))
		throw runtime_error("could not find an offer with this guid");

	for(unsigned int i=0;i<theOffer.linkWhitelist.entries.size();i++) {
		CTransaction txIdentity;
		CIdentityIndex theIdentity;
		COfferLinkWhitelistEntry& entry = theOffer.linkWhitelist.entries[i];
		if (GetTxOfIdentity(entry.identityLinkVchRand, theIdentity, txIdentity))
		{
			UniValue oList(UniValue::VOBJ);
			oList.push_back(Pair("identity", stringFromVch(entry.identityLinkVchRand)));
			uint64_t nHeight = theIdentity.nHeight;
			oList.push_back(Pair("expires_on",theIdentity.nExpireTime));
			oList.push_back(Pair("offer_discount_percentage", strprintf("%d%%", entry.nDiscountPct)));
			oRes.push_back(oList);
		}
    }
    return oRes;
}
UniValue offerupdate(const UniValue& params, bool fHelp) {
	if (fHelp || params.size() < 6 || params.size() > 14)
		throw runtime_error(
		"offerupdate <identity> <guid> <category> <title> <quantity> <price> [description] [currency] [private='0'] [cert. guid=''] [geolocation=''] [safesearch=Yes] [commission=0] [paymentOptions=0]\n"
						"Perform an update on an offer you control.\n"
						+ HelpRequiringPassphrase());
	// gather & validate inputs
	vector<unsigned char> vchIdentity = vchFromValue(params[0]);
	vector<unsigned char> vchOffer = vchFromValue(params[1]);
	vector<unsigned char> vchCat = vchFromValue(params[2]);
	vector<unsigned char> vchTitle = vchFromValue(params[3]);
	vector<unsigned char> vchDesc;
	vector<unsigned char> vchCert;
	vector<unsigned char> vchGeoLocation;
	vector<unsigned char> sCurrencyCode;
	int bPrivate = false;
	int nQty;
	float fPrice;
	int nCommission = 0;
	if (params.size() >= 7) vchDesc = vchFromValue(params[6]);
	if (params.size() >= 8) sCurrencyCode = vchFromValue(params[7]);
	if (params.size() >= 9) bPrivate = boost::lexical_cast<int>(params[8].get_str()) == 1? true: false;
	if (params.size() >= 10) vchCert = vchFromValue(params[9]);
	if(vchCert == vchFromString("nocert"))
		vchCert.clear();
	if (params.size() >= 11) vchGeoLocation = vchFromValue(params[10]);
	string strSafeSearch = "Yes";
	if(params.size() >= 12)
	{
		strSafeSearch = params[11].get_str();
	}
	if(params.size() >= 13 && !params[12].get_str().empty() && params[12].get_str() != "NONE")
	{
		nCommission = boost::lexical_cast<int>(params[12].get_str());
	}

	string paymentOptions = "DYN";
	if(params.size() >= 14 && !params[13].get_str().empty() && params[13].get_str() != "NONE")
	{
		paymentOptions = params[13].get_str();
		boost::algorithm::to_upper(paymentOptions);
	}
	if(!ValidatePaymentOptionsString(paymentOptions))
	{
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1532 - " + _("Could not validate payment options string"));
	}
	unsigned char paymentOptionsMask = (unsigned char) GetPaymentOptionsMaskFromString(paymentOptions);

	try {
		nQty = boost::lexical_cast<int>(params[4].get_str());
		fPrice = boost::lexical_cast<float>(params[5].get_str());

	} catch (std::exception &e) {
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1533 - " + _("Invalid price and/or quantity values. Quantity must be less than 4294967296 and greater than or equal to -1"));
	}

	CIdentityIndex identity, linkIdentity;
	CTransaction identitytx, linkidentitytx;
	const CWalletTx *wtxIdentityIn = NULL;
	const CWalletTx *wtxLinkIdentityIn = NULL;
	

	// this is a dynamicd txn
	CWalletTx wtx;
	CScript scriptPubKeyOrig, scriptPubKeyCertOrig;

	EnsureWalletIsUnlocked();

	// look for a transaction with this key
	CTransaction tx, linktx;
	COffer theOffer, linkOffer;
	if (!GetTxOfOffer( vchOffer, theOffer, tx))
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1534 - " + _("Could not find an offer with this guid"));

	if (!GetTxOfIdentity(theOffer.vchIdentity, identity, identitytx))
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1535 - " + _("Could not find an identity with this name"));
	if (!vchIdentity.empty() &&  !GetTxOfIdentity(vchIdentity, linkIdentity, linkidentitytx))
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1536 - " + _("Could not find an identity with this name"));

	if(!IsMyIdentity(identity)) {
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1537 - " + _("This identity is not yours"));
	}

	if(!vchCert.empty())
	{
		CCert theCert;
		vector<CCert> vtxCert;
		if (!GetVtxOfCert( vchCert, theCert, vtxCert))
		{
			throw runtime_error("DYNAMIC_OFFER_RPC_ERROR: ERRCODE: 1538 - " + _("Updating an offer with a cert that does not exist"));
		}
		else if(theOffer.vchLinkOffer.empty() && theCert.vchIdentity != theOffer.vchIdentity)
		{
			throw runtime_error("DYNAMIC_OFFER_RPC_ERROR: ERRCODE: 1539 - " + _("Cannot update this offer because the certificate identity does not match the offer identity"));
		}
		if(!boost::algorithm::starts_with(stringFromVch(vchCat), "certificates"))
		{
			throw runtime_error("DYNAMIC_OFFER_RPC_ERROR: ERRCODE: 1540 - " + _("Offer selling a certificate must use a certificate category"));
		}
	}
	else if(boost::algorithm::starts_with(stringFromVch(vchCat), "certificates"))
	{
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR: ERRCODE: 1541 - " + _("Offer not selling a certificate cannot use a certificate category"));
	}
	if(!theOffer.vchLinkOffer.empty())
	{
		COffer linkOffer;
		vector<COffer> offerVtxPos;
		COfferLinkWhitelistEntry entry;
		if (!GetVtxOfOffer( theOffer.vchLinkOffer, linkOffer, offerVtxPos))
		{
			throw runtime_error("DYNAMIC_OFFER_RPC_ERROR: ERRCODE: 1542 - " + _("Linked offer not found. It may be expired"));
		}
		else if(!linkOffer.linkWhitelist.GetLinkEntryByHash(vchIdentity, entry))
		{
			throw runtime_error("DYNAMIC_OFFER_RPC_ERROR: ERRCODE: 1543 - " + _("Cannot find this identity in the parent offer affiliate list"));
		}
		if (!linkOffer.vchLinkOffer.empty())
		{
			throw runtime_error("DYNAMIC_OFFER_RPC_ERROR: ERRCODE: 1544 - " + _("Cannot link to an offer that is already linked to another offer"));
		}
		else if(linkOffer.sCategory.size() > 0 && boost::algorithm::starts_with(stringFromVch(linkOffer.sCategory), "wanted"))
		{
			throw runtime_error("DYNAMIC_OFFER_RPC_ERROR: ERRCODE: 1545 - " + _("Cannot link to a wanted offer"));
		}
	}
	if(vchCat.size() > 0 && boost::algorithm::starts_with(stringFromVch(vchCat), "wanted") && !boost::algorithm::starts_with(stringFromVch(theOffer.sCategory), "wanted"))
	{
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR: ERRCODE: 1546 - " + _("Cannot change category to wanted"));
	}
	COutPoint outPoint;
	int numResults  = identityunspent(theOffer.vchIdentity, outPoint);	
	wtxIdentityIn = pwalletMain->GetWalletTx(outPoint.hash);
	if (wtxIdentityIn == NULL)
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1547 - " + _("This identity is not in your wallet"));

	int numResultsLink = 0;
	COutPoint outPointLink;
	if(!vchIdentity.empty() && vchIdentity != theOffer.vchIdentity)
	{
		numResultsLink = identityunspent(vchIdentity, outPointLink);	
		wtxLinkIdentityIn = pwalletMain->GetWalletTx(outPointLink.hash);
		if (wtxLinkIdentityIn == NULL)
			throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1548 - " + _("This identity is not in your wallet"));

	}
	CDynamicAddress identityAddress;
	GetAddress(identity, &identityAddress, scriptPubKeyOrig);

	// create OFFERUPDATE, IDENTITYUPDATE txn keys
	CScript scriptPubKey;

	COffer offerCopy = theOffer;
	theOffer.ClearOffer();
	theOffer.nHeight = chainActive.Tip()->nHeight;
	if(offerCopy.sCategory != vchCat)
		theOffer.sCategory = vchCat;
	if(offerCopy.sTitle != vchTitle)
		theOffer.sTitle = vchTitle;
	if(offerCopy.sDescription != vchDesc)
		theOffer.sDescription = vchDesc;
	if(offerCopy.vchGeoLocation != vchGeoLocation)
		theOffer.vchGeoLocation = vchGeoLocation;
	CAmount nPricePerUnit = offerCopy.GetPrice();
	if(sCurrencyCode.empty() || sCurrencyCode == vchFromString("NONE"))
		sCurrencyCode = offerCopy.sCurrencyCode;
	if(offerCopy.sCurrencyCode != sCurrencyCode)
		theOffer.sCurrencyCode = sCurrencyCode;

	// linked offers can't change these settings, they are overrided by parent info
	if(offerCopy.vchLinkOffer.empty())
	{
		if(offerCopy.vchCert != vchCert)
			theOffer.vchCert = vchCert;
		int precision = 2;
		nPricePerUnit = convertCurrencyCodeToDynamic(identity.vchIdentityPeg, sCurrencyCode, fPrice, chainActive.Tip()->nHeight, precision);
		if(nPricePerUnit == 0)
		{
			string err = "DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1549 - " + _("Could not find currency in the peg identity");
			throw runtime_error(err.c_str());
		}
	}
	if(params.size() >= 13 && !params[12].get_str().empty() && params[12].get_str() != "NONE")
		theOffer.nCommission = nCommission;
	if(params.size() >= 14 && !params[13].get_str().empty() && params[13].get_str() != "NONE")
		theOffer.paymentOptions = paymentOptionsMask;

	if(!vchIdentity.empty() && vchIdentity != identity.vchIdentity)
		theOffer.vchLinkIdentity = vchIdentity;
	theOffer.safeSearch = strSafeSearch == "Yes"? true: false;
	theOffer.nQty = nQty;
	if (params.size() >= 9)
		theOffer.bPrivate = bPrivate;

	theOffer.nHeight = chainActive.Tip()->nHeight;
	theOffer.SetPrice(nPricePerUnit);


	vector<unsigned char> data;
	theOffer.Serialize(data);
    uint256 hash = Hash(data.begin(), data.end());

    vector<unsigned char> vchHashOffer = vchFromValue(hash.GetHex());
	scriptPubKey << CScript::EncodeOP_N(OP_OFFER_UPDATE) << vchOffer << vchHashOffer << OP_2DROP << OP_DROP;
	scriptPubKey += scriptPubKeyOrig;

	vector<CRecipient> vecSend;
	CRecipient recipient;
	CreateRecipient(scriptPubKey, recipient);
	vecSend.push_back(recipient);
	CScript scriptPubKeyIdentity;
	scriptPubKeyIdentity << CScript::EncodeOP_N(OP_IDENTITY_UPDATE) << identity.vchIdentity << identity.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
	scriptPubKeyIdentity += scriptPubKeyOrig;
	CRecipient identityRecipient;
	CreateRecipient(scriptPubKeyIdentity, identityRecipient);
	for(unsigned int i =numResults;i<=MAX_IDENTITY_UPDATES_PER_BLOCK;i++)
		vecSend.push_back(identityRecipient);

	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, identity.vchIdentityPeg, chainActive.Tip()->nHeight, data, fee);
	vecSend.push_back(fee);

	if(!vchIdentity.empty() && vchIdentity != theOffer.vchIdentity)
	{
		CScript scriptPubKeyIdentityLink, scriptPubKeyOrigLink;
		CDynamicAddress linkIdentityAddress;
		GetAddress(linkIdentity, &linkIdentityAddress, scriptPubKeyOrigLink);
		scriptPubKeyIdentityLink << CScript::EncodeOP_N(OP_IDENTITY_UPDATE) << linkIdentity.vchIdentity << linkIdentity.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
		scriptPubKeyIdentityLink += scriptPubKeyOrigLink;
		CRecipient identityRecipientLink;
		CreateRecipient(scriptPubKeyIdentityLink, identityRecipientLink);
		for(unsigned int i =numResultsLink;i<=MAX_IDENTITY_UPDATES_PER_BLOCK;i++)
			vecSend.push_back(identityRecipientLink);
	}

	SendMoneyDynamic(vecSend, recipient.nAmount+identityRecipient.nAmount+fee.nAmount, false, wtx, wtxIdentityIn, outPoint.n, identity.multiSigInfo.vchIdentityes.size() > 0 || linkIdentity.multiSigInfo.vchIdentityes.size() > 0, NULL, wtxLinkIdentityIn, outPointLink.n);
	UniValue res(UniValue::VARR);
	if(identity.multiSigInfo.vchIdentityes.size() > 0 || linkIdentity.multiSigInfo.vchIdentityes.size() > 0)
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
		}
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
UniValue offeraccept(const UniValue& params, bool fHelp) {
	if (fHelp || 1 > params.size() || params.size() > 6)
		throw runtime_error("offeraccept <identity> <guid> [quantity] [message] [Ext TxId] [payment option=DYN]\n"
				"Accept&Pay for a confirmed offer.\n"
				"<identity> An identity of the buyer.\n"
				"<guid> guidkey from offer.\n"
				"<quantity> quantity to buy. Defaults to 1.\n"
				"<message> payment message to seller, 256 characters max.\n"
				"<Ext TxId> If paid in another coin, enter the Transaction ID here. Default is empty.\n"
				"<paymentOption> If Ext TxId is defined, specify a valid payment option used to make payment. Default is DYN.\n"
				+ HelpRequiringPassphrase());
	CDynamicAddress refundAddr;
	vector<unsigned char> vchIdentity = vchFromValue(params[0]);
	vector<unsigned char> vchOffer = vchFromValue(params[1]);
	vector<unsigned char> vchExtTxId = vchFromValue(params.size()>=5?params[4]:"");

	vector<unsigned char> vchMessage = vchFromValue(params.size()>=4?params[3]:"");
	int64_t nHeight = chainActive.Tip()->nHeight;
	unsigned int nQty = 1;
	if (params.size() >= 3) {
		try {
			nQty = boost::lexical_cast<unsigned int>(params[2].get_str());
		} catch (std::exception &e) {
			throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1550 - " + _("Quantity must be less than 4294967296"));
		}
	}
	// payment options - get payment options string if specified otherwise default to DYN
	string paymentOptions = "DYN";
	if(params.size() >= 6 && !params[5].get_str().empty() && params[5].get_str() != "NONE")
	{
		paymentOptions = params[5].get_str();
		boost::algorithm::to_upper(paymentOptions);
	}
	// payment options - validate payment options string
	if(!ValidatePaymentOptionsString(paymentOptions))
	{
		// TODO change error number to something unique
		string err = "DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1551 - " + _("Could not validate the payment options value");
		throw runtime_error(err.c_str());
	}
		// payment options - and convert payment options string to a bitmask for the txn
	unsigned char paymentOptionsMask = (unsigned char) GetPaymentOptionsMaskFromString(paymentOptions);
	// this is a dynamic txn
	CWalletTx wtx;
	CScript scriptPubKeyIdentityOrig;
	vector<unsigned char> vchAccept = vchFromString(GenerateDynamicGuid());

	// create OFFERACCEPT txn keys
	CScript scriptPubKeyAccept, scriptPubKeyPayment;
	CScript scriptPubKeyIdentity;
	EnsureWalletIsUnlocked();
	CTransaction acceptTx;
	COffer theOffer;
	// if this is a linked offer accept, set the height to the first height so dynrates.peg price will match what it was at the time of the original accept
	CTransaction tx;
	vector<COffer> vtxPos;
	if (!GetTxAndVtxOfOffer( vchOffer, theOffer, tx, vtxPos))
	{
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1552 - " + _("Could not find an offer with this identifier"));
	}

	COffer linkOffer;
	CTransaction linkedTx;
	vector<COffer> vtxLinkPos;
	if(!theOffer.vchLinkOffer.empty() && !GetTxAndVtxOfOffer( theOffer.vchLinkOffer, linkOffer, linkedTx, vtxLinkPos))
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR: ERRCODE: 1553 - " + _("Could not get linked offer"));

	CTransaction identitytx,buyeridentitytx;
	CIdentityIndex theIdentity,tmpIdentity;
	bool isExpired = false;
	vector<CIdentityIndex> identityVtxPos;
	if(!GetTxAndVtxOfIdentity(theOffer.vchIdentity, theIdentity, identitytx, identityVtxPos, isExpired))
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1554 - " + _("Could not find the identity associated with this offer"));

	CIdentityIndex buyerIdentity;
	if (!GetTxOfIdentity(vchIdentity, buyerIdentity, buyeridentitytx))
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1555 - " + _("Could not find buyer identity with this name"));

	vector<string> rateList;
	int precision = 2;
	int nFeePerByte;
	double nRate;
	float fEscrowFee;
	if(getCurrencyToDYNFromIdentity(theIdentity.vchIdentityPeg, theOffer.sCurrencyCode, nRate, chainActive.Tip()->nHeight, rateList,precision, nFeePerByte, fEscrowFee) != "")
	{
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR: ERRCODE: 1556 - " + _("Could not find currency in the peg identity"));
	}
	CCert theCert;
	// trying to purchase a cert
	if(!theOffer.vchCert.empty())
	{
		vector<CCert> vtxCert;
		if (!GetVtxOfCert( theOffer.vchCert, theCert, vtxCert))
		{
			throw runtime_error("DYNAMIC_OFFER_RPC_ERROR: ERRCODE: 1557 - " + _("Cannot purchase an expired certificate"));
		}
		else if(theOffer.vchLinkOffer.empty())
		{
			if(theCert.vchIdentity != theOffer.vchIdentity)
			{
				throw runtime_error("DYNAMIC_OFFER_RPC_ERROR: ERRCODE: 1558 - " + _("Cannot purchase this offer because the certificate has been transferred or it is linked to another offer"));
			}
		}
	}
	else if (vchMessage.size() <= 0)
	{
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR: ERRCODE: 1559 - " + _("Offer payment message cannot be empty"));
	}
	if(!theOffer.vchLinkOffer.empty())
	{
		if (!linkOffer.vchLinkOffer.empty())
		{
			 throw runtime_error("DYNAMIC_OFFER_RPC_ERROR: ERRCODE: 1560 - " + _("Cannot purchase offers that are linked more than once"));
		}
		vector<CIdentityIndex> vtxIdentity;
		CIdentityIndex linkIdentity;
		if(!GetVtxOfIdentity(linkOffer.vchIdentity, linkIdentity, vtxIdentity, isExpired))
		{
			throw runtime_error("DYNAMIC_OFFER_RPC_ERROR: ERRCODE: 1561 - " + _("Cannot find identity for this linked offer"));
		}
		else if(!theOffer.vchCert.empty() && theCert.vchIdentity != linkOffer.vchIdentity)
		{
			throw runtime_error("DYNAMIC_OFFER_RPC_ERROR: ERRCODE: 1562 - " + _("Cannot purchase this linked offer because the certificate has been transferred or it is linked to another offer"));
		}
		else if(linkOffer.sCategory.size() > 0 && boost::algorithm::starts_with(stringFromVch(linkOffer.sCategory), "wanted"))
		{
			throw runtime_error("DYNAMIC_OFFER_RPC_ERROR: ERRCODE: 1563 - " + _("Cannot purchase a wanted offer"));
		}
	}
	const CWalletTx *wtxIdentityIn = NULL;
	COfferLinkWhitelistEntry foundEntry;
	CAmount nPrice;
	CAmount nCommission;
	if(theOffer.vchLinkOffer.empty())
	{
		theOffer.linkWhitelist.GetLinkEntryByHash(buyerIdentity.vchIdentity, foundEntry);
		nPrice = theOffer.GetPrice(foundEntry);
		nCommission = 0;
	}
	else
	{
		linkOffer.linkWhitelist.GetLinkEntryByHash(theOffer.vchIdentity, foundEntry);
		nPrice = linkOffer.GetPrice(foundEntry);
		nCommission = theOffer.GetPrice() - nPrice;
		if(nCommission < 0)
			nCommission = 0;
	}
	COutPoint outPoint;
	int numResults  = identityunspent(buyerIdentity.vchIdentity, outPoint);	
	wtxIdentityIn = pwalletMain->GetWalletTx(outPoint.hash);
	CDynamicAddress buyerAddress;
	GetAddress(buyerIdentity, &buyerAddress, scriptPubKeyIdentityOrig);
	scriptPubKeyIdentity << CScript::EncodeOP_N(OP_IDENTITY_UPDATE) << buyerIdentity.vchIdentity  << buyerIdentity.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
	scriptPubKeyIdentity += scriptPubKeyIdentityOrig;

	string strCipherText = "";

	CIdentityIndex theLinkedIdentity;
	if(!theOffer.vchLinkOffer.empty())
	{
		if (!GetTxOfIdentity(linkOffer.vchIdentity, theLinkedIdentity, identitytx))
			throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1564 - " + _("Could not find an identity with this name"));

		// encrypt to root offer owner if this is a linked offer you are accepting
		if(!EncryptMessage(theLinkedIdentity, vchMessage, strCipherText))
			throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1565 - " + _("Could not encrypt message to seller"));
	}
	else
	{
		// encrypt to offer owner
		if(!EncryptMessage(theIdentity, vchMessage, strCipherText))
			throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1566 - " + _("Could not encrypt message to seller"));
	}

	vector<unsigned char> vchPaymentMessage = vchFromString(strCipherText);
	COfferAccept txAccept;
	txAccept.vchAcceptRand = vchAccept;
	txAccept.nQty = nQty;
	txAccept.nPrice = nPrice;
	// We need to do this to make sure we convert price at the time of initial buyer's accept.
	txAccept.nAcceptHeight = nHeight;
	txAccept.vchBuyerIdentity = vchIdentity;
	txAccept.vchMessage = vchPaymentMessage;
	txAccept.nPaymentOption = paymentOptionsMask;
    CAmount nTotalValue = ( nPrice * nQty );
	CAmount nTotalCommission = ( nCommission * nQty );
	if(!vchExtTxId.empty())
	{
		uint256 txExtId(uint256S(stringFromVch(vchExtTxId)));
		txAccept.txExtId = txExtId;
	}
	COffer copyOffer = theOffer;
	theOffer.ClearOffer();
	theOffer.accept = txAccept;
	theOffer.nHeight = chainActive.Tip()->nHeight;

	vector<unsigned char> data;
	theOffer.Serialize(data);
    uint256 hash = Hash(data.begin(), data.end());

    vector<unsigned char> vchHashOffer = vchFromValue(hash.GetHex());

    CScript scriptPayment, scriptPubKeyCommission, scriptPubKeyOrig, scriptPubLinkKeyOrig, scriptPaymentCommission;
	CDynamicAddress currentAddress;
	GetAddress(theIdentity, &currentAddress, scriptPubKeyOrig);

	CDynamicAddress linkAddress;
	GetAddress(theLinkedIdentity, &linkAddress, scriptPubLinkKeyOrig);
	scriptPubKeyAccept << CScript::EncodeOP_N(OP_OFFER_ACCEPT) << vchOffer << vchAccept << vchFromString("0") << vchHashOffer << OP_2DROP << OP_2DROP << OP_DROP;
	if(!copyOffer.vchLinkOffer.empty())
	{
		scriptPayment = scriptPubLinkKeyOrig;
		scriptPaymentCommission = scriptPubKeyOrig;
	}
	else
	{
		scriptPayment = scriptPubKeyOrig;
	}
	scriptPubKeyAccept += scriptPubKeyOrig;
	scriptPubKeyPayment += scriptPayment;
	scriptPubKeyCommission += scriptPaymentCommission;




	vector<CRecipient> vecSend;


	CRecipient acceptRecipient;
	CreateRecipient(scriptPubKeyAccept, acceptRecipient);
	CRecipient paymentRecipient = {scriptPubKeyPayment, nTotalValue, false};
	CRecipient paymentCommissionRecipient = {scriptPubKeyCommission, nTotalCommission, false};
	CRecipient identityRecipient;
	CreateRecipient(scriptPubKeyIdentity, identityRecipient);
	for(unsigned int i =numResults;i<=MAX_IDENTITY_UPDATES_PER_BLOCK;i++)
		vecSend.push_back(identityRecipient);


	if(vchExtTxId.empty())
	{
		vecSend.push_back(paymentRecipient);
		vecSend.push_back(acceptRecipient);
		if(!copyOffer.vchLinkOffer.empty() && nTotalCommission > 0)
			vecSend.push_back(paymentCommissionRecipient);
	}
	else
		vecSend.push_back(acceptRecipient);


	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, buyerIdentity.vchIdentityPeg, chainActive.Tip()->nHeight, data, fee);
	vecSend.push_back(fee);

	SendMoneyDynamic(vecSend, acceptRecipient.nAmount+paymentRecipient.nAmount+fee.nAmount+identityRecipient.nAmount, false, wtx, wtxIdentityIn, outPoint.n, buyerIdentity.multiSigInfo.vchIdentityes.size() > 0);

	UniValue res(UniValue::VARR);
	if(buyerIdentity.multiSigInfo.vchIdentityes.size() > 0)
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
			res.push_back(stringFromVch(vchAccept));
		}
		else
		{
			res.push_back(hex_str);
			res.push_back(stringFromVch(vchAccept));
			res.push_back("false");
		}
	}
	else
	{
		res.push_back(wtx.GetHash().GetHex());
		res.push_back(stringFromVch(vchAccept));
	}

	return res;
}

void HandleAcceptFeedback(const CFeedback& feedback, COffer& offer, vector<COffer> &vtxPos)
{
	if(feedback.nRating > 0)
	{
		string identityStr;
		CPubKey key;
		if(feedback.nFeedbackUserTo == FEEDBACKBUYER)
			identityStr = stringFromVch(offer.accept.vchBuyerIdentity);
		else if(feedback.nFeedbackUserTo == FEEDBACKSELLER)
			identityStr = stringFromVch(offer.vchIdentity);
		CDynamicAddress address = CDynamicAddress(identityStr);
		if(address.IsValid() && address.isIdentity)
		{
			vector<CIdentityIndex> vtxPos;
			const vector<unsigned char> &vchIdentity = vchFromString(address.identityName);
			if (pidentitydb->ReadIdentity(vchIdentity, vtxPos) && !vtxPos.empty())
			{

				CIdentityIndex identity = vtxPos.back();
				if(feedback.nFeedbackUserTo == FEEDBACKBUYER)
				{
					identity.nRatingCountAsBuyer++;
					identity.nRatingAsBuyer += feedback.nRating;
				}
				else if(feedback.nFeedbackUserTo == FEEDBACKSELLER)
				{
					identity.nRatingCountAsSeller++;
					identity.nRatingAsSeller += feedback.nRating;
				}
				else if(feedback.nFeedbackUserTo == FEEDBACKARBITER)
				{
					identity.nRatingCountAsArbiter++;
					identity.nRatingAsArbiter += feedback.nRating;
				}
				PutToIdentityList(vtxPos, identity);
				pidentitydb->WriteIdentity(vchIdentity, vtxPos);
			}
		}
	}
	offer.accept.feedback.push_back(feedback);
	offer.PutToOfferList(vtxPos);
	pofferdb->WriteOffer(offer.vchOffer, vtxPos);
}
void FindFeedback(const vector<CFeedback> &feedback, int &numBuyerRatings, int &numSellerRatings,int &numArbiterRatings, int &feedbackBuyerCount, int &feedbackSellerCount, int &feedbackArbiterCount)
{
	feedbackSellerCount = feedbackBuyerCount = feedbackArbiterCount = numBuyerRatings = numSellerRatings = numArbiterRatings = 0;
	for(unsigned int i =0;i<feedback.size();i++)
	{
		if(!feedback[i].IsNull())
		{
			if(feedback[i].nFeedbackUserFrom == FEEDBACKBUYER)
			{
				feedbackBuyerCount++;
				if(feedback[i].nRating > 0)
					numBuyerRatings++;
			}
			else if(feedback[i].nFeedbackUserFrom == FEEDBACKSELLER)
			{
				feedbackSellerCount++;
				if(feedback[i].nRating > 0)
					numSellerRatings++;
			}
			else if(feedback[i].nFeedbackUserFrom == FEEDBACKARBITER)
			{
				feedbackArbiterCount++;
				if(feedback[i].nRating > 0)
					numArbiterRatings++;
			}
		}
	}
}
void GetFeedback(vector<CFeedback> &feedBackSorted, float &avgRating, const FeedbackUser type, const vector<CFeedback>& feedBack)
{
	float nRating = 0;
	int nRatingCount = 0;
	for(unsigned int i =0;i<feedBack.size();i++)
	{
		if(!feedBack[i].IsNull() && feedBack[i].nFeedbackUserTo == type)
		{
			if(feedBack[i].nRating > 0)
			{
				nRating += feedBack[i].nRating;
				nRatingCount++;
			}
			feedBackSorted.push_back(feedBack[i]);
		}
	}
	if(nRatingCount > 0)
	{
		nRating /= nRatingCount;
	}
	avgRating = floor(nRating * 10) / 10;
	if(feedBackSorted.size() > 0)
		sort(feedBackSorted.begin(), feedBackSorted.end(), feedbacksort());

}

UniValue offeracceptfeedback(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 4)
        throw runtime_error(
		"offeracceptfeedback <offer guid> <offeraccept guid> [feedback] [rating] \n"
                        "Send feedback and rating for offer accept specified. Ratings are numbers from 1 to 5\n"
                        + HelpRequiringPassphrase());
   // gather & validate inputs
	int nRating = 0;
	vector<unsigned char> vchOffer = vchFromValue(params[0]);
	vector<unsigned char> vchAcceptRand = vchFromValue(params[1]);
	vector<unsigned char> vchFeedback = vchFromValue(params[2]);
	try {
		nRating = boost::lexical_cast<int>(params[3].get_str());
		if(nRating < 0 || nRating > 5)
			throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1567 - " + _("Invalid rating value, must be less than or equal to 5 and greater than or equal to 0"));

	} catch (std::exception &e) {
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1568 - " + _("Invalid rating value"));
	}


    // this is a dynamic transaction
    CWalletTx wtx;

	EnsureWalletIsUnlocked();

    // look for a transaction with this key
    CTransaction tx;
	COffer theOffer;
	COfferAccept theOfferAccept;
	const CWalletTx *wtxIdentityIn = NULL;

	COffer tmpOffer;
	if (!GetTxOfOffer( vchOffer, tmpOffer, tx))
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1569 - " + _("Could not find an offer with this guid"));

	
	if (!GetTxOfOfferAccept(tmpOffer.vchOffer, vchAcceptRand, theOffer, theOfferAccept, tx))
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1570 - " + _("Could not find this offer purchase"));

	vector<vector<unsigned char> > vvch;
	int op, nOut;
	if (!DecodeOfferTx(tx, op, nOut, vvch) || op != OP_OFFER_ACCEPT)
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1571 - " + _("Offer purchase transaction of wrong type"));

	if(vvch[0] != theOffer.vchOffer)
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1572 - " + _("Only merchant of this offer can leave feedback for this purchase"));

	CIdentityIndex buyerIdentity, sellerIdentity;
	CTransaction buyeridentitytx, selleridentitytx;

	if(!GetTxOfIdentity(theOfferAccept.vchBuyerIdentity, buyerIdentity, buyeridentitytx))
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1573 - " + _("Could not buyer identity"));
	if(!GetTxOfIdentity(theOffer.vchIdentity, sellerIdentity, selleridentitytx))
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1574 - " + _("Could not merchant identity"));
	CDynamicAddress buyerAddress;
	CScript buyerScript, sellerScript;
	GetAddress(buyerIdentity, &buyerAddress, buyerScript);

	CDynamicAddress sellerAddress;
	GetAddress(sellerIdentity, &sellerAddress, sellerScript);

	CScript scriptPubKeyIdentity;
	CScript scriptPubKey;
	vector<unsigned char> vchLinkIdentity;
	CIdentityIndex theIdentity;
	bool foundBuyerKey = false;
	bool foundSellerKey = false;
	try
	{
		CKeyID keyID;
		if (!buyerAddress.GetKeyID(keyID))
			throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1575 - " + _("Buyer address does not refer to a key"));
		CKey vchSecret;
		if (!pwalletMain->GetKey(keyID, vchSecret))
			throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1576 - " + _("Private key for buyer address is not known"));
		vchLinkIdentity = buyerIdentity.vchIdentity;
		theIdentity = buyerIdentity;
		foundBuyerKey = true;
	}
	catch(...)
	{
		foundBuyerKey = false;
	}

	try
	{
		CKeyID keyID;
		if (!sellerAddress.GetKeyID(keyID))
			throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1577 - " + _("Seller address does not refer to a key"));
		CKey vchSecret;
		if (!pwalletMain->GetKey(keyID, vchSecret))
			throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1578 - " + _("Private key for seller address is not known"));
		vchLinkIdentity = sellerIdentity.vchIdentity;
		theIdentity = sellerIdentity;
		foundSellerKey = true;
		foundBuyerKey = false;
	}
	catch(...)
	{
		foundSellerKey = false;
	}

	theOffer.ClearOffer();
	theOffer.accept = theOfferAccept;
	theOffer.accept.vchBuyerIdentity = vchLinkIdentity;
	theOffer.accept.bPaymentAck = false;
	theOffer.nHeight = chainActive.Tip()->nHeight;
	COutPoint outPoint;
	int numResults;
	// buyer
	if(foundBuyerKey)
	{
		CFeedback sellerFeedback(FEEDBACKBUYER, FEEDBACKSELLER);
		sellerFeedback.vchFeedback = vchFeedback;
		sellerFeedback.nRating = nRating;
		sellerFeedback.nHeight = chainActive.Tip()->nHeight;
		theOffer.accept.feedback.clear();
		theOffer.accept.feedback.push_back(sellerFeedback);
		numResults  = identityunspent(buyerIdentity.vchIdentity, outPoint);	
		wtxIdentityIn = pwalletMain->GetWalletTx(outPoint.hash);
		if (wtxIdentityIn == NULL)
			throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1579 - " + _("Buyer identity is not in your wallet"));
		scriptPubKeyIdentity << CScript::EncodeOP_N(OP_IDENTITY_UPDATE) << buyerIdentity.vchIdentity << buyerIdentity.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
		scriptPubKeyIdentity += buyerScript;
	}
	// seller
	else if(foundSellerKey)
	{
		CFeedback buyerFeedback(FEEDBACKSELLER, FEEDBACKBUYER);
		buyerFeedback.vchFeedback = vchFeedback;
		buyerFeedback.nRating = nRating;
		buyerFeedback.nHeight = chainActive.Tip()->nHeight;
		theOffer.accept.feedback.clear();
		theOffer.accept.feedback.push_back(buyerFeedback);
		numResults  = identityunspent(sellerIdentity.vchIdentity, outPoint);	
		wtxIdentityIn = pwalletMain->GetWalletTx(outPoint.hash);
		if (wtxIdentityIn == NULL)
			throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1580 - " + _("Seller identity is not in your wallet"));
		scriptPubKeyIdentity = CScript() <<  CScript::EncodeOP_N(OP_IDENTITY_UPDATE) << sellerIdentity.vchIdentity << sellerIdentity.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
		scriptPubKeyIdentity += sellerScript;

	}
	else
	{
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1581 - " + _("You must be either the buyer or seller to leave feedback on this offer purchase"));
	}

	vector<unsigned char> data;
	theOffer.Serialize(data);
    uint256 hash = Hash(data.begin(), data.end());

    vector<unsigned char> vchHashOffer = vchFromValue(hash.GetHex());

	vector<CRecipient> vecSend;
	CRecipient recipientIdentity, recipient;


	scriptPubKey << CScript::EncodeOP_N(OP_OFFER_ACCEPT) << theOffer.vchOffer << theOfferAccept.vchAcceptRand << vchFromString("1") << vchHashOffer << OP_2DROP <<  OP_2DROP << OP_DROP;
	scriptPubKey += sellerScript;
	CreateRecipient(scriptPubKey, recipient);
	CreateRecipient(scriptPubKeyIdentity, recipientIdentity);

	vecSend.push_back(recipient);
	for(unsigned int i =numResults;i<=MAX_IDENTITY_UPDATES_PER_BLOCK;i++)
		vecSend.push_back(recipientIdentity);

	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, theIdentity.vchIdentityPeg, chainActive.Tip()->nHeight, data, fee);
	vecSend.push_back(fee);




	SendMoneyDynamic(vecSend, recipient.nAmount+recipientIdentity.nAmount+fee.nAmount, false, wtx, wtxIdentityIn, outPoint.n, theIdentity.multiSigInfo.vchIdentityes.size() > 0);
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
		}
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
UniValue offeracceptacknowledge(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 2)
        throw runtime_error(
		"offeracceptacknowledge <offer guid> <offeraccept guid> \n"
                        "Acknowledge offer payment as seller of offer. Deducts qty of offer and increases number of sold inventory.\n"
                        + HelpRequiringPassphrase());
   // gather & validate inputs
	vector<unsigned char> vchOffer = vchFromValue(params[0]);
	vector<unsigned char> vchAcceptRand = vchFromValue(params[1]);

    // this is a dynamic transaction
    CWalletTx wtx;

	EnsureWalletIsUnlocked();

    // look for a transaction with this key
    CTransaction tx, linkTx;
	COffer theOffer, linkOffer;
	COfferAccept theOfferAccept;
	const CWalletTx *wtxIdentityIn = NULL;

	if (!GetTxOfOffer( vchOffer, theOffer, tx))
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1582 - " + _("Could not find an offer with this guid"));

	
	CIdentityIndex buyerIdentity, sellerIdentity;
	CTransaction buyeridentitytx, selleridentitytx;

	if(!theOffer.vchLinkOffer.empty())
	{
		if (!GetTxOfOffer( theOffer.vchLinkOffer, theOffer, linkTx))
			throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1583 - " + _("Could not find a linked offer with this guid"));
		if(!GetTxOfIdentity(theOffer.vchIdentity, sellerIdentity, selleridentitytx))
			throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1584 - " + _("Could not find merchant identity"));
	}
	else
	{
		if(!GetTxOfIdentity(theOffer.vchIdentity, sellerIdentity, selleridentitytx))
			throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1585 - " + _("Could not find merchant identity"));
	}

	CScript buyerScript, sellerScript;
	CDynamicAddress sellerAddress;
	GetAddress(sellerIdentity, &sellerAddress, sellerScript);

	COffer tmpOffer;
	if (!GetTxOfOfferAccept(theOffer.vchOffer, vchAcceptRand, tmpOffer, theOfferAccept, tx, true))
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1586 - " + _("Could not find this offer purchase"));



	

	if(!GetTxOfIdentity(theOfferAccept.vchBuyerIdentity, buyerIdentity, buyeridentitytx))
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1587 - " + _("Could not buyer identity"));
	CDynamicAddress buyerAddress;
	GetAddress(buyerIdentity, &buyerAddress, buyerScript);

	CScript scriptPubKeyIdentity;
	CScript scriptPubKeyBuyer;

	CKeyID keyID;
	if (!sellerAddress.GetKeyID(keyID))
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1588 - " + _("Seller address does not refer to a key"));
	CKey vchSecret;
	if (!pwalletMain->GetKey(keyID, vchSecret))
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1589 - " + _("Private key for seller address is not known"));



	theOffer.ClearOffer();
	theOffer.accept.bPaymentAck = true;
	theOffer.accept.vchBuyerIdentity = sellerIdentity.vchIdentity;
	theOffer.accept.nPaymentOption = theOfferAccept.nPaymentOption;
	theOffer.nHeight = chainActive.Tip()->nHeight;

	COutPoint outPoint;
	int numResults  = identityunspent(sellerIdentity.vchIdentity, outPoint);	
	wtxIdentityIn = pwalletMain->GetWalletTx(outPoint.hash);
	if (wtxIdentityIn == NULL)
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1590 - " + _("Seller identity is not in your wallet"));

	scriptPubKeyIdentity = CScript() <<  CScript::EncodeOP_N(OP_IDENTITY_UPDATE) << sellerIdentity.vchIdentity << sellerIdentity.vchGUID << vchFromString("") << OP_2DROP << OP_2DROP;
	scriptPubKeyIdentity += sellerScript;


	vector<unsigned char> data;
	theOffer.Serialize(data);
    uint256 hash = Hash(data.begin(), data.end());

    vector<unsigned char> vchHashOffer = vchFromValue(hash.GetHex());

	vector<CRecipient> vecSend;
	CRecipient recipientIdentity, recipient, recipientBuyer;


	scriptPubKeyBuyer << CScript::EncodeOP_N(OP_OFFER_ACCEPT) << theOffer.vchOffer << theOfferAccept.vchAcceptRand << vchFromString("0") << vchHashOffer << OP_2DROP <<  OP_2DROP << OP_DROP;
	scriptPubKeyBuyer += buyerScript;
	CreateRecipient(scriptPubKeyBuyer, recipientBuyer);
	CreateRecipient(scriptPubKeyIdentity, recipientIdentity);

	vecSend.push_back(recipientBuyer);
	for(unsigned int i =numResults;i<=MAX_IDENTITY_UPDATES_PER_BLOCK;i++)
		vecSend.push_back(recipientIdentity);

	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, sellerIdentity.vchIdentityPeg, chainActive.Tip()->nHeight, data, fee);
	vecSend.push_back(fee);




	SendMoneyDynamic(vecSend, recipientBuyer.nAmount+recipientIdentity.nAmount+fee.nAmount, false, wtx, wtxIdentityIn, outPoint.n, sellerIdentity.multiSigInfo.vchIdentityes.size() > 0);
	UniValue res(UniValue::VARR);
	if(sellerIdentity.multiSigInfo.vchIdentityes.size() > 0)
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
		}
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
UniValue offerinfo(const UniValue& params, bool fHelp) {
	if (fHelp || 1 != params.size())
		throw runtime_error("offerinfo <guid>\n"
				"Show offer details\n");

	UniValue oOffer(UniValue::VOBJ);
	vector<unsigned char> vchOffer = vchFromValue(params[0]);
	vector<COffer> vtxPos;
	if (!pofferdb->ReadOffer(vchOffer, vtxPos) || vtxPos.empty())
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR: ERRCODE: 1591 - " + _("Failed to read from offer DB"));

	// check that the seller isn't banned level 2
	CTransaction identitytx;
	CIdentityIndex identity;
	if(!GetTxOfIdentity(vtxPos.back().vchIdentity, identity, identitytx, true))
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1592 - " + _("Could not find the identity associated with this offer"));

	if(!BuildOfferJson(vtxPos.back(), identity, oOffer))
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1593 - " + _("Could not find this offer"));

	return oOffer;

}
bool BuildOfferJson(const COffer& theOffer, const CIdentityIndex &identity, UniValue& oOffer, const string &strPrivKey)
{
	if(theOffer.safetyLevel >= SAFETY_LEVEL2)
		return false;
	if(identity.safetyLevel >= SAFETY_LEVEL2)
		return false;
	CTransaction linkTx;
	COffer linkOffer;
	vector<COffer> myLinkedVtxPos;
	CTransaction linkidentitytx;
	CIdentityIndex linkIdentity;
	if( !theOffer.vchLinkOffer.empty())
	{
		if(!GetTxAndVtxOfOffer( theOffer.vchLinkOffer, linkOffer, linkTx, myLinkedVtxPos, true))
			return false;
		if(!GetTxOfIdentity(linkOffer.vchIdentity, linkIdentity, linkidentitytx, true))
			return false;
		if(linkOffer.safetyLevel >= SAFETY_LEVEL2)
			return false;
		if(linkIdentity.safetyLevel >= SAFETY_LEVEL2)
			return false;
	}

	uint64_t nHeight;
	int expired;
	int64_t expires_in;
	int64_t expired_time;

	expired = 0;
	expires_in = 0;
	expired_time = 0;
    nHeight = theOffer.nHeight;
	vector<unsigned char> vchCert;
	if(!theOffer.vchCert.empty())
		vchCert = theOffer.vchCert;
	oOffer.push_back(Pair("offer", stringFromVch(theOffer.vchOffer)));
	oOffer.push_back(Pair("cert", stringFromVch(vchCert)));
	oOffer.push_back(Pair("txid", theOffer.txHash.GetHex()));
	expired_time =  GetOfferExpiration(theOffer);
    if(expired_time <= chainActive.Tip()->nTime)
	{
		expired = 1;
	}
	expires_in = expired_time - chainActive.Tip()->nTime;
	if(expires_in < -1)
		expires_in = -1;
	oOffer.push_back(Pair("expires_in", expires_in));
	oOffer.push_back(Pair("expires_on", expired_time));
	oOffer.push_back(Pair("expired", expired));
	oOffer.push_back(Pair("height", strprintf("%llu", nHeight)));
	string sTime;
	CBlockIndex *pindex = chainActive[nHeight];
	if (pindex) {
		sTime = strprintf("%llu", pindex->nTime);
	}
	oOffer.push_back(Pair("time", sTime));
	oOffer.push_back(Pair("category", stringFromVch(theOffer.sCategory)));
	oOffer.push_back(Pair("title", stringFromVch(theOffer.sTitle)));
	int nQty = theOffer.nQty;
	if(!theOffer.vchLinkOffer.empty())
		nQty = linkOffer.nQty;
	if(nQty == -1)
		oOffer.push_back(Pair("quantity", "unlimited"));
	else
		oOffer.push_back(Pair("quantity", strprintf("%d", nQty)));
	oOffer.push_back(Pair("currency", stringFromVch(theOffer.sCurrencyCode)));


	int precision = 2;
	CAmount nPricePerUnit = convertDynamicToCurrencyCode(identity.vchIdentityPeg, theOffer.sCurrencyCode, theOffer.GetPrice(), nHeight, precision);
	oOffer.push_back(Pair("dynprice", theOffer.GetPrice()));
	if(nPricePerUnit == 0)
		oOffer.push_back(Pair("price", "0"));
	else
		oOffer.push_back(Pair("price", strprintf("%.*f", precision, ValueFromAmount(nPricePerUnit).get_real())));

	oOffer.push_back(Pair("ismine", IsMyIdentity(identity)  ? "true" : "false"));
	if(!theOffer.vchLinkOffer.empty()) {
		oOffer.push_back(Pair("commission", strprintf("%d", theOffer.nCommission)));
		oOffer.push_back(Pair("offerlink", "true"));
		oOffer.push_back(Pair("offerlink_guid", stringFromVch(theOffer.vchLinkOffer)));
		oOffer.push_back(Pair("offerlink_seller", stringFromVch(linkOffer.vchIdentity)));

	}
	else
	{
		oOffer.push_back(Pair("commission", "0"));
		oOffer.push_back(Pair("offerlink", "false"));
		oOffer.push_back(Pair("offerlink_guid", ""));
		oOffer.push_back(Pair("offerlink_seller", ""));
	}
	oOffer.push_back(Pair("private", theOffer.bPrivate ? "Yes" : "No"));
	oOffer.push_back(Pair("safesearch", theOffer.safeSearch? "Yes" : "No"));
	unsigned char safetyLevel = max(theOffer.safetyLevel, identity.safetyLevel );
	safetyLevel = max(safetyLevel, linkOffer.safetyLevel );
	safetyLevel = max(safetyLevel, linkIdentity.safetyLevel );
	oOffer.push_back(Pair("safetylevel", safetyLevel));
	int paymentOptions = theOffer.paymentOptions;
	if(!theOffer.vchLinkOffer.empty())
		paymentOptions = linkOffer.paymentOptions;
	oOffer.push_back(Pair("paymentoptions", paymentOptions));
	oOffer.push_back(Pair("paymentoptions_display", GetPaymentOptionsString(paymentOptions)));
	oOffer.push_back(Pair("identity_peg", stringFromVch(identity.vchIdentityPeg)));
	oOffer.push_back(Pair("description", stringFromVch(theOffer.sDescription)));
	oOffer.push_back(Pair("identity", stringFromVch(theOffer.vchIdentity)));
	CDynamicAddress address;
	GetAddress(identity, &address);
	if(!address.IsValid())
		return false;
	oOffer.push_back(Pair("address", address.ToString()));

	float rating = 0;
	if(identity.nRatingCountAsSeller > 0)
	{
		rating = identity.nRatingAsSeller/(float)identity.nRatingCountAsSeller;
		rating = floor(rating * 10) / 10;
	}
	oOffer.push_back(Pair("identity_rating",rating));
	oOffer.push_back(Pair("identity_rating_count",(int)identity.nRatingCountAsSeller));
	oOffer.push_back(Pair("identity_rating_display", strprintf("%.1f/5 (%d %s)", rating, identity.nRatingCountAsSeller, _("Votes"))));
	oOffer.push_back(Pair("geolocation", stringFromVch(theOffer.vchGeoLocation)));
	int sold = theOffer.nSold;
	if(!theOffer.vchLinkOffer.empty())
		sold = linkOffer.nSold;
	oOffer.push_back(Pair("offers_sold", sold));
	return true;
}
UniValue offeracceptlist(const UniValue& params, bool fHelp) {
    if (fHelp || 3 < params.size())
        throw runtime_error("offeracceptlist [\"identity\",...] [<acceptguid>] [<privatekey>]\n"
                "list offer purchases that an array of identities own. Set of identities to look up based on identity, and private key to decrypt any data found in offer purchase.");
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

	UniValue aoOfferAccepts(UniValue::VARR);
	map< vector<unsigned char>, int > vNamesI;
	map< vector<unsigned char>, int > vNamesA;
	vector<COffer> offerScan;
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
			
			CTransaction tx, offerTx, acceptTx, identityTx, linkTx, linkIdentityTx, offerTxTmp;
			COffer theOffer, offerTmp, linkOffer;
			CIdentityIndex linkIdentity;
			vector<COffer> vtxOfferPos, vtxAcceptPos, vtxLinkPos, vtxIdentityLinkPos;
			vector<unsigned char> vchOffer;
			uint256 blockHash;
			uint256 hash;

			
			for(std::vector<CIdentityIndex>::reverse_iterator it = vtxPos.rbegin(); it != vtxPos.rend(); ++it) {
				CIdentityIndex theIdentity = *it;
				if(!GetDynamicTransaction(theIdentity.nHeight, theIdentity.txHash, tx, Params().GetConsensus()))
					continue;
				vector<vector<unsigned char> > vvch;
				int op, nOut;
				if (!DecodeOfferTx(tx, op, nOut, vvch))
					continue;
				if(!GetTxAndVtxOfOffer( vvch[0], offerTmp, offerTx, vtxOfferPos, true))
					continue;

				// get unique offers
				if (vNamesI.find(vvch[0]) != vNamesI.end())
					continue;

				vNamesI[vvch[0]] = offerTmp.nHeight;
				// this is needed because offer accepts dont use seller identity as input (they use buyers obviously) and we dont them in our identity history but they exist in our offer history
				for(int i=vtxOfferPos.size()-1;i>=0;i--) {

					const COffer &theOffer = vtxOfferPos[i];
					if(theOffer.accept.IsNull())
						continue;
					// get unique accepts
					if (vNamesA.find(theOffer.accept.vchAcceptRand) != vNamesA.end())
						continue;
					if (vchNameUniq.size() > 0 && vchNameUniq != theOffer.accept.vchAcceptRand)
						continue;
					if(theOffer.vchIdentity != theIdentity.vchIdentity && theOffer.accept.vchBuyerIdentity != theIdentity.vchIdentity)
						continue;
					UniValue oAccept(UniValue::VOBJ);
					vNamesA[theOffer.accept.vchAcceptRand] = theOffer.accept.nAcceptHeight;
					if(BuildOfferAcceptJson(theOffer, theIdentity, tx, oAccept, strPrivateKey))
					{
						aoOfferAccepts.push_back(oAccept);
					}
					

				}
			}
		}
	}
    return aoOfferAccepts;
}
bool BuildOfferAcceptJson(const COffer& theOffer, const CIdentityIndex& theIdentity, const CTransaction &identitytx, UniValue& oOfferAccept, const string &strPrivKey)
{
	CTransaction offerTx;
	COffer linkOffer;
	CTransaction linkTx;
	vector<vector<unsigned char> > vvch;
	int op, nOut;
	if(!GetDynamicTransaction(theOffer.nHeight, theOffer.txHash, offerTx, Params().GetConsensus()))
		return false;

	if (!DecodeOfferTx(offerTx, op, nOut, vvch)
		|| (op != OP_OFFER_ACCEPT))
		return false;

	
	int nHeight = theOffer.accept.nAcceptHeight;

	bool commissionPaid = false;
	bool discountApplied = false;
	// need to show 3 different possible prices:
	// LINKED OFFERS:
	// for buyer (full price) #1
	// for affiliate (commission + discount) #2
	// for merchant (discounted) #3
	// NON-LINKED OFFERS;
	// for merchant (discounted) #3
	// for buyer (full price) #1


	CAmount priceAtTimeOfAccept = theOffer.GetPrice();
	if(theOffer.vchLinkOffer.empty())
	{
		// NON-LINKED merchant
		if(theIdentity.vchIdentity == theOffer.vchIdentity)
		{
			priceAtTimeOfAccept = theOffer.accept.nPrice;
			if(theOffer.GetPrice() != priceAtTimeOfAccept)
				discountApplied = true;
		}
		// NON-LINKED buyer
		else if(theIdentity.vchIdentity == theOffer.accept.vchBuyerIdentity)
		{
			priceAtTimeOfAccept = theOffer.GetPrice();
			commissionPaid = false;
			discountApplied = false;
		}
	}
	// linked offer
	else
	{
		vector<COffer> vtxLinkPos;
		GetTxAndVtxOfOffer( theOffer.vchLinkOffer, linkOffer, linkTx, vtxLinkPos, true);
		linkOffer.nHeight = nHeight;
		linkOffer.GetOfferFromList(vtxLinkPos);
		// You are the merchant
		if(theIdentity.vchIdentity == linkOffer.vchIdentity)
		{
			commissionPaid = false;
			priceAtTimeOfAccept = theOffer.accept.nPrice;
			if(linkOffer.GetPrice() != priceAtTimeOfAccept)
				discountApplied = true;
		}
		// You are the affiliate
		else if(theIdentity.vchIdentity == theOffer.vchIdentity)
		{
			// full price with commission - discounted merchant price = commission + discount
			priceAtTimeOfAccept = theOffer.GetPrice() -  theOffer.accept.nPrice;
			commissionPaid = true;
			discountApplied = false;
		}
	}
	
	string sHeight = strprintf("%llu", theOffer.nHeight);
	oOfferAccept.push_back(Pair("offer", stringFromVch(theOffer.vchOffer)));
	string sTime;
	CBlockIndex *pindex = chainActive[theOffer.nHeight];
	if (pindex) {
		sTime = strprintf("%llu", pindex->nTime);
	}
	float avgBuyerRating, avgSellerRating;
	vector<CFeedback> buyerFeedBacks, sellerFeedBacks;

	GetFeedback(buyerFeedBacks, avgBuyerRating, FEEDBACKBUYER, theOffer.accept.feedback);
	GetFeedback(sellerFeedBacks, avgSellerRating, FEEDBACKSELLER, theOffer.accept.feedback);


	oOfferAccept.push_back(Pair("id", stringFromVch(theOffer.accept.vchAcceptRand)));
	oOfferAccept.push_back(Pair("txid", theOffer.txHash.GetHex()));
	oOfferAccept.push_back(Pair("title", stringFromVch(theOffer.sTitle)));
	string strExtId = "";
	if(!theOffer.accept.txExtId.IsNull())
		strExtId = theOffer.accept.txExtId.GetHex();
	oOfferAccept.push_back(Pair("exttxid", strExtId));
	oOfferAccept.push_back(Pair("paymentoption", (int)theOffer.accept.nPaymentOption));
	oOfferAccept.push_back(Pair("paymentoption_display", GetPaymentOptionsString(theOffer.accept.nPaymentOption)));
	oOfferAccept.push_back(Pair("height", sHeight));
	oOfferAccept.push_back(Pair("time", sTime));
	oOfferAccept.push_back(Pair("quantity", strprintf("%d", theOffer.accept.nQty)));
	oOfferAccept.push_back(Pair("currency", stringFromVch(theOffer.sCurrencyCode)));
	if(theOffer.GetPrice() > 0)
		oOfferAccept.push_back(Pair("offer_discount_percentage", strprintf("%.2f%%", 100.0f - 100.0f*((float)theOffer.accept.nPrice/(float)theOffer.nPrice))));
	else
		oOfferAccept.push_back(Pair("offer_discount_percentage", "0%"));

	int precision = 2;
	int extprecision = 2;

	CAmount nPricePerUnit = convertDynamicToCurrencyCode(theIdentity.vchIdentityPeg, theOffer.sCurrencyCode, priceAtTimeOfAccept, theOffer.accept.nAcceptHeight, precision);
	CAmount nPricePerUnitExt = 0;
	if(theOffer.accept.nPaymentOption != PAYMENTOPTION_DYN)
		nPricePerUnitExt = convertDynamicToCurrencyCode(theIdentity.vchIdentityPeg, vchFromString(GetPaymentOptionsString(theOffer.accept.nPaymentOption)), priceAtTimeOfAccept, theOffer.accept.nAcceptHeight, extprecision);
	CAmount dynTotal = priceAtTimeOfAccept * theOffer.accept.nQty;
	oOfferAccept.push_back(Pair("dyntotal", dynTotal));
	oOfferAccept.push_back(Pair("dynprice", priceAtTimeOfAccept));
	if(nPricePerUnit == 0)
	{
		oOfferAccept.push_back(Pair("price", "0"));
		oOfferAccept.push_back(Pair("total", "0"));
	}
	else
	{
		oOfferAccept.push_back(Pair("price", strprintf("%.*f", precision, ValueFromAmount(nPricePerUnit).get_real())));
		if(nPricePerUnitExt > 0)
			oOfferAccept.push_back(Pair("total", strprintf("%.*f", extprecision, ValueFromAmount(nPricePerUnitExt).get_real() * theOffer.accept.nQty )));
		else
			oOfferAccept.push_back(Pair("total", strprintf("%.*f", precision, ValueFromAmount(nPricePerUnit).get_real() * theOffer.accept.nQty )));
	}
	oOfferAccept.push_back(Pair("buyer", stringFromVch(theOffer.accept.vchBuyerIdentity)));
	oOfferAccept.push_back(Pair("seller", stringFromVch(theOffer.vchIdentity)));
	oOfferAccept.push_back(Pair("ismine", IsDynamicTxMine(identitytx, "identity")? "true" : "false"));
	string statusStr = "Paid";
	if(!theOffer.accept.txExtId.IsNull())
		statusStr = "Paid with external coin";
	else if(commissionPaid)
		statusStr = "Paid commission";
	else if(discountApplied)
		statusStr = "Paid with discount applied";
	if(theOffer.accept.bPaymentAck)
		statusStr += " (acknowledged)";
	oOfferAccept.push_back(Pair("status",statusStr));
	UniValue oBuyerFeedBack(UniValue::VARR);
	for(unsigned int j =0;j<buyerFeedBacks.size();j++)
	{
		UniValue oFeedback(UniValue::VOBJ);
		string sFeedbackTime;
		CBlockIndex *pindex = chainActive[buyerFeedBacks[j].nHeight];
		if (pindex) {
			sFeedbackTime = strprintf("%llu", pindex->nTime);
		}

		oFeedback.push_back(Pair("txid", buyerFeedBacks[j].txHash.GetHex()));
		oFeedback.push_back(Pair("time", sFeedbackTime));
		oFeedback.push_back(Pair("rating", buyerFeedBacks[j].nRating));
		oFeedback.push_back(Pair("feedbackuser", buyerFeedBacks[j].nFeedbackUserFrom));
		oFeedback.push_back(Pair("feedback", stringFromVch(buyerFeedBacks[j].vchFeedback)));
		oBuyerFeedBack.push_back(oFeedback);
	}
	oOfferAccept.push_back(Pair("buyer_feedback", oBuyerFeedBack));
	UniValue oSellerFeedBack(UniValue::VARR);
	for(unsigned int j =0;j<sellerFeedBacks.size();j++)
	{
		UniValue oFeedback(UniValue::VOBJ);
		string sFeedbackTime;
		CBlockIndex *pindex = chainActive[sellerFeedBacks[j].nHeight];
		if (pindex) {
			sFeedbackTime = strprintf("%llu", pindex->nTime);
		}
		oFeedback.push_back(Pair("txid", sellerFeedBacks[j].txHash.GetHex()));
		oFeedback.push_back(Pair("time", sFeedbackTime));
		oFeedback.push_back(Pair("rating", sellerFeedBacks[j].nRating));
		oFeedback.push_back(Pair("feedbackuser", sellerFeedBacks[j].nFeedbackUserFrom));
		oFeedback.push_back(Pair("feedback", stringFromVch(sellerFeedBacks[j].vchFeedback)));
		oSellerFeedBack.push_back(oFeedback);
	}
	oOfferAccept.push_back(Pair("seller_feedback", oSellerFeedBack));
	unsigned int ratingCount = 0;
	if(avgSellerRating > 0)
		ratingCount++;
	if(avgBuyerRating > 0)
		ratingCount++;
	float totalAvgRating = 0;
	if(ratingCount > 0)
		 totalAvgRating = (avgSellerRating+avgBuyerRating)/(float)ratingCount;
	totalAvgRating = floor(totalAvgRating * 10) / 10;
	oOfferAccept.push_back(Pair("avg_rating", totalAvgRating));
	oOfferAccept.push_back(Pair("avg_rating_display", strprintf("%.1f/5 (%d %s)", totalAvgRating, ratingCount, _("Votes"))));
	string strMessage = string("");
	if(!DecryptMessage(theIdentity, theOffer.accept.vchMessage, strMessage, strPrivKey))
		strMessage = _("Encrypted for owner of offer");
	oOfferAccept.push_back(Pair("pay_message", strMessage));
	return true;
}
UniValue offerlist(const UniValue& params, bool fHelp) {
    if (fHelp || 3 < params.size())
        throw runtime_error("offerlist [\"identity\",...] [<offer>] [<privatekey>]\n"
                "list offers that an array of identities own. Set of identities to look up based on identity, and private key to decrypt any data found in offer.");
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
	vector<COffer> offerScan;
	map< vector<unsigned char>, int > vNamesI;
	map< vector<unsigned char>, UniValue > vNamesO;
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
			for(std::vector<CIdentityIndex>::reverse_iterator it = vtxPos.rbegin(); it != vtxPos.rend(); ++it) {
				const CIdentityIndex& theIdentity = *it;
				if(!GetDynamicTransaction(theIdentity.nHeight, theIdentity.txHash, tx, Params().GetConsensus()))
					continue;
				COffer offer(tx);
				if(!offer.IsNull() && offer.accept.IsNull())
				{
					if (vNamesI.find(offer.vchOffer) != vNamesI.end())
						continue;
					if (vchNameUniq.size() > 0 && vchNameUniq != offer.vchOffer)
						continue;
					vector<COffer> vtxOfferPos;
					if (!pofferdb->ReadOffer(offer.vchOffer, vtxOfferPos) || vtxOfferPos.empty())
						continue;
					const COffer &theOffer = vtxOfferPos.back();
					if(theOffer.vchIdentity != theIdentity.vchIdentity)
						continue;
					offerScan.push_back(theOffer);
					
					UniValue oOffer(UniValue::VOBJ);
					vNamesI[offer.vchOffer] = theOffer.nHeight;
					if(BuildOfferJson(theOffer, theIdentity, oOffer, strPrivateKey))
					{
						oRes.push_back(oOffer);
					}
				}
					
			}
		}
	}
    return oRes;
}
UniValue offerhistory(const UniValue& params, bool fHelp) {
	if (fHelp || 1 != params.size())
		throw runtime_error("offerhistory <offer>\n"
				"List all stored values of an offer.\n");

	UniValue oRes(UniValue::VARR);
	vector<unsigned char> vchOffer = vchFromValue(params[0]);

	vector<COffer> vtxPos;
	if (!pofferdb->ReadOffer(vchOffer, vtxPos) || vtxPos.empty())
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1594 - " + _("Failed to read from offer DB"));

	vector<CIdentityIndex> vtxIdentityPos;
	if (!pidentitydb->ReadIdentity(vtxPos.back().vchIdentity, vtxIdentityPos) || vtxIdentityPos.empty())
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1595 - " + _("Failed to read from identity DB"));
	

	COffer txPos2;
	CIdentityIndex theIdentity;
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
		if (!DecodeOfferTx(tx, op, nOut, vvch) )
			continue;
		theIdentity.nHeight = txPos2.nHeight;
		theIdentity.GetIdentityFromList(vtxIdentityPos);

		UniValue oOffer(UniValue::VOBJ);
		string opName = offerFromOp(op);
		COffer offerOp(tx);
		if(offerOp.accept.bPaymentAck)
			opName += "("+_("acknowledged")+")";
		else if(!offerOp.accept.feedback.empty())
			opName += "("+_("feedback")+")";

		
		oOffer.push_back(Pair("offertype", opName));
		if(BuildOfferJson(txPos2, theIdentity, oOffer))
			oRes.push_back(oOffer);
	}
	
	return oRes;
}
UniValue offerfilter(const UniValue& params, bool fHelp) {
	if (fHelp || params.size() > 4)
		throw runtime_error(
				"offerfilter [[[[[regexp]] from=0]] safesearch='Yes' category]\n"
						"scan and filter offers\n"
						"[regexp] : apply [regexp] on offers, empty means all offers\n"
						"[from] : show results from this GUID [from], 0 means first.\n"
						"[safesearch] : shows all offers that are safe to display (not on the ban list)\n"
						"[category] : category you want to search in, empty for all\n"
						"offerfilter \"\" 5 # list offers updated in last 5 blocks\n"
						"offerfilter \"^offer\" # list all offers starting with \"offer\"\n"
						"offerfilter 36000 0 0 stat # display stats (number of offers) on active offers\n");

	string strRegexp;
	vector<unsigned char> vchOffer;
	string strCategory;
	bool safeSearch = true;

	if (params.size() > 0)
		strRegexp = params[0].get_str();

	if (params.size() > 1)
		vchOffer = vchFromValue(params[1]);

	if (params.size() > 2)
		safeSearch = params[2].get_str()=="On"? true: false;

	if (params.size() > 3)
		strCategory = params[3].get_str();

	UniValue oRes(UniValue::VARR);


	vector<COffer> offerScan;
	if (!pofferdb->ScanOffers(vchOffer, strRegexp, safeSearch, strCategory, 25, offerScan))
		throw runtime_error("DYNAMIC_OFFER_RPC_ERROR ERRCODE: 1596 - " + _("Scan failed"));
	CTransaction identitytx;
	BOOST_FOREACH(const COffer &txOffer, offerScan) {
		vector<CIdentityIndex> vtxIdentityPos;
		if(!pidentitydb->ReadIdentity(txOffer.vchIdentity, vtxIdentityPos) || vtxIdentityPos.empty())
			continue;
		const CIdentityIndex& identity = vtxIdentityPos.back();

		UniValue oOffer(UniValue::VOBJ);
		if(BuildOfferJson(txOffer, identity, oOffer))
			oRes.push_back(oOffer);
	}


	return oRes;
}
bool GetAcceptByHash(std::vector<COffer> &offerList, COfferAccept &ca, COffer &offer) {
	if(offerList.empty())
		return false;
	for(std::vector<COffer>::reverse_iterator it = offerList.rbegin(); it != offerList.rend(); ++it) {
		const COffer& myoffer = *it;
		// skip null states
		if(myoffer.accept.IsNull())
			continue;
        if(myoffer.accept.vchAcceptRand == ca.vchAcceptRand) {
            ca = myoffer.accept;
			offer = myoffer;
			return true;
        }
    }
	return false;
}
std::string GetPaymentOptionsString(const uint32_t paymentOptions)
{
	vector<std::string> currencies;
	if(IsPaymentOptionInMask(paymentOptions, PAYMENTOPTION_DYN)) {
		currencies.push_back(std::string("DYN"));
	}
	if(IsPaymentOptionInMask(paymentOptions, PAYMENTOPTION_BTC)) {
		currencies.push_back(std::string("BTC"));
	}
	if(IsPaymentOptionInMask(paymentOptions, PAYMENTOPTION_SEQ)) {
		currencies.push_back(std::string("SEQ"));
	}
	return boost::algorithm::join(currencies, "+");
}
CChainParams::AddressType PaymentOptionToAddressType(const uint32_t paymentOption)
{
	CChainParams::AddressType myAddressType = CChainParams::ADDRESS_DYN;
	if(paymentOption == PAYMENTOPTION_SEQ)
		myAddressType = CChainParams::ADDRESS_SEQ;
	return myAddressType;
}

void OfferTxToJSON(const int op, const std::vector<unsigned char> &vchData, const std::vector<unsigned char> &vchHash, UniValue &entry)
{
	string opName = offerFromOp(op);
	COffer offer;
	if(!offer.UnserializeFromData(vchData, vchHash))
		return;


	bool isExpired = false;
	vector<CIdentityIndex> identityVtxPos;
	vector<COffer> offerVtxPos;
	CTransaction offertx, identitytx;
	COffer dbOffer;
	if(GetTxAndVtxOfOffer(offer.vchOffer, dbOffer, offertx, offerVtxPos, true))
	{
		dbOffer.nHeight = offer.nHeight;
		dbOffer.GetOfferFromList(offerVtxPos);
	}
	CIdentityIndex dbIdentity;
	if(GetTxAndVtxOfIdentity(offer.vchIdentity, dbIdentity, identitytx, identityVtxPos, isExpired, true))
	{
		dbIdentity.nHeight = offer.nHeight;
		dbIdentity.GetIdentityFromList(identityVtxPos);
	}
	string noDifferentStr = _("<No Difference Detected>");
	COffer offerop(offertx);
	if(offerop.accept.bPaymentAck)
		opName += "("+_("acknowledged")+")";
	else if(!offerop.accept.feedback.empty())
		opName += "("+_("feedback")+")";
	entry.push_back(Pair("txtype", opName));
	entry.push_back(Pair("offer", stringFromVch(offer.vchOffer)));

	if(!offer.linkWhitelist.IsNull())
	{
		string whitelistValue = noDifferentStr;
		if(offer.linkWhitelist.entries[0].nDiscountPct == 127)
			whitelistValue = _("Whitelist was cleared");
		else
			whitelistValue = _("Whitelist entries were added or removed");

		entry.push_back(Pair("whitelist", whitelistValue));
		return;
	}

	string titleValue = noDifferentStr;
	if(!offer.sTitle.empty() && offer.sTitle != dbOffer.sTitle)
		titleValue = stringFromVch(offer.sTitle);
	entry.push_back(Pair("title", titleValue));

	string certValue = noDifferentStr;
	if(!offer.vchCert.empty() && offer.vchCert != dbOffer.vchCert)
		certValue = stringFromVch(offer.vchCert);
	entry.push_back(Pair("cert", certValue));

	string identityValue = noDifferentStr;
	if(!offer.vchIdentity.empty() && offer.vchIdentity != dbOffer.vchIdentity)
		identityValue = stringFromVch(offer.vchIdentity);

	entry.push_back(Pair("identity", identityValue));

	string linkOfferValue = noDifferentStr;
	if(!offer.vchLinkOffer.empty() && offer.vchLinkOffer != dbOffer.vchLinkOffer)
		linkOfferValue = stringFromVch(offer.vchLinkOffer);

	entry.push_back(Pair("offerlink", linkOfferValue));

	string commissionValue = noDifferentStr;
	if(offer.nCommission  != 0 && offer.nCommission != dbOffer.nCommission)
		commissionValue =  boost::lexical_cast<string>(offer.nCommission);
	entry.push_back(Pair("commission", commissionValue));

	string paymentOptionsValue = noDifferentStr;
	if(offer.paymentOptions > 0 && offer.paymentOptions != dbOffer.paymentOptions)
		paymentOptionsValue = GetPaymentOptionsString( offer.paymentOptions);

	entry.push_back(Pair("paymentoptions", paymentOptionsValue));

	string ackValue = noDifferentStr;
	if(offer.accept.bPaymentAck && offer.accept.bPaymentAck != dbOffer.accept.bPaymentAck)
		ackValue = offer.accept.bPaymentAck? "true": "false";

	entry.push_back(Pair("paymentacknowledge", ackValue));

	string categoryValue = noDifferentStr;
	if(!offer.sCategory.empty() && offer.sCategory != dbOffer.sCategory)
		categoryValue = stringFromVch(offer.sCategory);

	entry.push_back(Pair("category", categoryValue ));

	string geolocationValue = noDifferentStr;
	if(!offer.vchGeoLocation.empty() && offer.vchGeoLocation != dbOffer.vchGeoLocation)
		geolocationValue = stringFromVch(offer.vchGeoLocation);

	entry.push_back(Pair("geolocation", geolocationValue ));


	string descriptionValue = noDifferentStr;
	if(!offer.sDescription.empty() && offer.sDescription != dbOffer.sDescription)
		descriptionValue = stringFromVch(offer.sDescription);
	entry.push_back(Pair("description", descriptionValue));


	string qtyValue = noDifferentStr;
	if(offer.nQty != dbOffer.nQty)
		qtyValue =  boost::lexical_cast<string>(offer.nQty);
	entry.push_back(Pair("quantity", qtyValue));

	string currencyValue = noDifferentStr;
	if(!offer.sCurrencyCode.empty()  && offer.sCurrencyCode != dbOffer.sCurrencyCode)
		currencyValue = stringFromVch(offer.sCurrencyCode);
	entry.push_back(Pair("currency", currencyValue));


	string priceValue = noDifferentStr;
	if(offer.GetPrice() != dbOffer.GetPrice())
		priceValue = boost::lexical_cast<string>(offer.GetPrice());
	entry.push_back(Pair("price", priceValue));


	string safeSearchValue = noDifferentStr;
	if(offer.safeSearch != dbOffer.safeSearch)
		safeSearchValue = offer.safeSearch? "Yes": "No";

	entry.push_back(Pair("safesearch", safeSearchValue));

	string safetyLevelValue = noDifferentStr;
	if(offer.safetyLevel != dbOffer.safetyLevel)
		safetyLevelValue = offer.safetyLevel;

	entry.push_back(Pair("safetylevel", safetyLevelValue));

	string privateValue = noDifferentStr;
	if(offer.bPrivate != dbOffer.bPrivate)
		privateValue = offer.bPrivate? "Yes": "No";

	entry.push_back(Pair("private", privateValue ));

}
