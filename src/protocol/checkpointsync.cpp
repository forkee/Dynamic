/**
 * Copyright (c) 2017 Everybody and Nobody (Empinel/Plaxton)
 * Copyright (c) 2012-2013 The Peercoin developers
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

#include <boost/foreach.hpp>

#include "checkpoints.h"
#include "checkpointsync.h"

#include "base58.h"
#include "bitcoinrpc.h"
#include "main.h"
#include "txdb.h"
#include "uint256.h"

using namespace json_spirit;
using namespace std;

// sync-checkpoint master key
const std::string CSyncCheckpoint::strMainPubKey = "04bcba2b149fe9d54f218208dd02aecd7b2245ef21c937207966f0814365b4d1c5d521d001f2df294bafb0fbe5ee4c3290b0c25bff8fdd886b6e3e9317758a7d75";
const std::string CSyncCheckpoint::strTestPubKey = "04ba2e1494f05a1fccbef6b0cf6124ce05c20bc7868726770dda7a41ba8c9e905b67bb594ebbb282b1159ba8fa176121cb81b8a1c184f0c73e631a8a4999647d30";
std::string CSyncCheckpoint::strMasterPrivKey = "";


// synchronized checkpoint (centrally broadcasted)
uint256 hashSyncCheckpoint = 0;
uint256 hashPendingCheckpoint = 0;
CSyncCheckpoint checkpointMessage;
CSyncCheckpoint checkpointMessagePending;
uint256 hashInvalidCheckpoint = 0;
CCriticalSection cs_hashSyncCheckpoint;
std::string strCheckpointWarning;

// get last synchronized checkpoint
CBlockIndex* GetLastSyncCheckpoint()
{
    LOCK(cs_hashSyncCheckpoint);
    if (!mapBlockIndex.count(hashSyncCheckpoint))
        error("GetSyncCheckpoint: block index missing for current sync-checkpoint %s", hashSyncCheckpoint.ToString().c_str());
    else
        return mapBlockIndex[hashSyncCheckpoint];
    return NULL;
}

// only descendant of current sync-checkpoint is allowed
bool ValidateSyncCheckpoint(uint256 hashCheckpoint)
{
    if (!mapBlockIndex.count(hashSyncCheckpoint))
        return error("ValidateSyncCheckpoint: block index missing for current sync-checkpoint %s", hashSyncCheckpoint.ToString().c_str());
    if (!mapBlockIndex.count(hashCheckpoint))
        return error("ValidateSyncCheckpoint: block index missing for received sync-checkpoint %s", hashCheckpoint.ToString().c_str());

    CBlockIndex* pindexSyncCheckpoint = mapBlockIndex[hashSyncCheckpoint];
    CBlockIndex* pindexCheckpointRecv = mapBlockIndex[hashCheckpoint];

    if (pindexCheckpointRecv->nHeight <= pindexSyncCheckpoint->nHeight)
    {
        // Received an older checkpoint, trace back from current checkpoint
        // to the same height of the received checkpoint to verify
        // that current checkpoint should be a descendant block
        CBlockIndex* pindex = pindexSyncCheckpoint;
        while (pindex->nHeight > pindexCheckpointRecv->nHeight)
            if (!(pindex = pindex->pprev))
                return error("ValidateSyncCheckpoint: pprev1 null - block index structure failure");
        if (pindex->GetBlockHash() != hashCheckpoint)
        {
            hashInvalidCheckpoint = hashCheckpoint;
            return error("ValidateSyncCheckpoint: new sync-checkpoint %s is conflicting with current sync-checkpoint %s", hashCheckpoint.ToString().c_str(), hashSyncCheckpoint.ToString().c_str());
        }
        return false; // ignore older checkpoint
    }

    // Received checkpoint should be a descendant block of the current
    // checkpoint. Trace back to the same height of current checkpoint
    // to verify.
    CBlockIndex* pindex = pindexCheckpointRecv;
    while (pindex->nHeight > pindexSyncCheckpoint->nHeight)
        if (!(pindex = pindex->pprev))
            return error("ValidateSyncCheckpoint: pprev2 null - block index structure failure");
    if (pindex->GetBlockHash() != hashSyncCheckpoint)
    {
        hashInvalidCheckpoint = hashCheckpoint;
        return error("ValidateSyncCheckpoint: new sync-checkpoint %s is not a descendant of current sync-checkpoint %s", hashCheckpoint.ToString().c_str(), hashSyncCheckpoint.ToString().c_str());
    }
    return true;
}

bool WriteSyncCheckpoint(const uint256& hashCheckpoint)
{
    if (!pblocktree->WriteSyncCheckpoint(hashCheckpoint))
    {
        return error("WriteSyncCheckpoint(): failed to write to txdb sync checkpoint %s", hashCheckpoint.ToString().c_str());
    }
    if (!pblocktree->Sync())
        return error("WriteSyncCheckpoint(): failed to commit to txdb sync checkpoint %s", hashCheckpoint.ToString().c_str());

    hashSyncCheckpoint = hashCheckpoint;
    return true;
}

bool IsSyncCheckpointEnforced()
{
    return (GetBoolArg("-checkpointenforce", true) || mapArgs.count("-checkpointkey")); // checkpoint master node is always enforced
}

bool AcceptPendingSyncCheckpoint()
{
    LOCK(cs_hashSyncCheckpoint);
    if (hashPendingCheckpoint != 0 && mapBlockIndex.count(hashPendingCheckpoint))
    {
        if (!ValidateSyncCheckpoint(hashPendingCheckpoint))
        {
            hashPendingCheckpoint = 0;
            checkpointMessagePending.SetNull();
            return false;
        }

        CBlockIndex* pindexCheckpoint = mapBlockIndex[hashPendingCheckpoint];
        if (IsSyncCheckpointEnforced() && !pindexCheckpoint->IsInMainChain())
        {
            CValidationState state;
            if (!SetBestChain(state, pindexCheckpoint))
            {
                hashInvalidCheckpoint = hashPendingCheckpoint;
                return error("AcceptPendingSyncCheckpoint: SetBestChain failed for sync checkpoint %s", hashPendingCheckpoint.ToString().c_str());
            }
        }

        if (!WriteSyncCheckpoint(hashPendingCheckpoint))
            return error("AcceptPendingSyncCheckpoint(): failed to write sync checkpoint %s", hashPendingCheckpoint.ToString().c_str());
        hashPendingCheckpoint = 0;
        checkpointMessage = checkpointMessagePending;
        checkpointMessagePending.SetNull();
        printf("AcceptPendingSyncCheckpoint : sync-checkpoint at %s\n", hashSyncCheckpoint.ToString().c_str());
        // relay the checkpoint
        if (!checkpointMessage.IsNull())
        {
            BOOST_FOREACH(CNode* pnode, vNodes)
                checkpointMessage.RelayTo(pnode);
        }
        return true;
    }
    return false;
}

// Automatically select a suitable sync-checkpoint 
uint256 AutoSelectSyncCheckpoint()
{
    // Search backward for a block with specified depth policy
    const CBlockIndex *pindex = pindexBest;
    while (pindex->pprev && pindex->nHeight + (int)GetArg("-checkpointdepth", -1) > pindexBest->nHeight)
        pindex = pindex->pprev;
    return pindex->GetBlockHash();
}

// Check against synchronized checkpoint
bool CheckSyncCheckpoint(const uint256& hashBlock, const CBlockIndex* pindexPrev)
{
    int nHeight = pindexPrev->nHeight + 1;
    LOCK(cs_hashSyncCheckpoint);
    // sync-checkpoint should always be accepted block
    assert(mapBlockIndex.count(hashSyncCheckpoint));
    const CBlockIndex* pindexSync = mapBlockIndex[hashSyncCheckpoint];

    if (nHeight > pindexSync->nHeight)
    {
        // trace back to same height as sync-checkpoint
        const CBlockIndex* pindex = pindexPrev;
        while (pindex->nHeight > pindexSync->nHeight)
            if (!(pindex = pindex->pprev))
                return error("CheckSyncCheckpoint: pprev null - block index structure failure");
        if (pindex->nHeight < pindexSync->nHeight || pindex->GetBlockHash() != hashSyncCheckpoint)
            return false; // only descendant of sync-checkpoint can pass check
    }
    if (nHeight == pindexSync->nHeight && hashBlock != hashSyncCheckpoint)
        return false; // same height with sync-checkpoint
    if (nHeight < pindexSync->nHeight && !mapBlockIndex.count(hashBlock))
        return false; // lower height than sync-checkpoint
    return true;
}

bool WantedByPendingSyncCheckpoint(uint256 hashBlock)
{
    LOCK(cs_hashSyncCheckpoint);
    if (hashPendingCheckpoint == 0)
        return false;
    if (hashBlock == hashPendingCheckpoint)
        return true;
    if (mapOrphanBlocks.count(hashPendingCheckpoint)
        && hashBlock == WantedByOrphan(mapOrphanBlocks[hashPendingCheckpoint]))
        return true;
    return false;
}

// reset synchronized checkpoint to last hardened checkpoint
bool ResetSyncCheckpoint()
{
    LOCK(cs_hashSyncCheckpoint);
    uint256 hash = Checkpoints::GetLatestHardenedCheckpoint();
    if (mapBlockIndex.count(hash) && !mapBlockIndex[hash]->IsInMainChain())
    {
        // checkpoint block accepted but not yet in main chain
        printf("ResetSyncCheckpoint: SetBestChain to hardened checkpoint %s\n", hash.ToString().c_str());
        CValidationState state;
        if (!SetBestChain(state, mapBlockIndex[hash]))
        {
            return error("ResetSyncCheckpoint: SetBestChain failed for hardened checkpoint %s", hash.ToString().c_str());
        }
    } else {
        /* Reset to the last available checkpoint block in the main chain */
        checkpointMessagePending.SetNull();
        hash = Checkpoints::GetLastAvailableCheckpoint();
    }

    if (!WriteSyncCheckpoint(hash))
        return error("ResetSyncCheckpoint: failed to write sync checkpoint %s", hash.ToString().c_str());
    printf("ResetSyncCheckpoint: sync-checkpoint reset to %s\n", hashSyncCheckpoint.ToString().c_str());
    return true;
}

void AskForPendingSyncCheckpoint(CNode* pfrom)
{
    LOCK(cs_hashSyncCheckpoint);
    if (pfrom && hashPendingCheckpoint != 0 && (!mapBlockIndex.count(hashPendingCheckpoint)) && (!mapOrphanBlocks.count(hashPendingCheckpoint)))
        pfrom->AskFor(CInv(MSG_BLOCK, hashPendingCheckpoint));
}

// Verify sync checkpoint master pubkey and reset sync checkpoint if changed
bool CheckCheckpointPubKey()
{
    std::string strPubKey = "";
    std::string strMasterPubKey = fTestNet? CSyncCheckpoint::strTestPubKey : CSyncCheckpoint::strMainPubKey;
    if (!pblocktree->ReadCheckpointPubKey(strPubKey) || strPubKey != strMasterPubKey)
    {
        // write checkpoint master key to db
        if (!pblocktree->WriteCheckpointPubKey(strMasterPubKey))
            return error("CheckCheckpointPubKey() : failed to write new checkpoint master key to db");
        if (!pblocktree->Sync())
            return error("CheckCheckpointPubKey() : failed to commit new checkpoint master key to db");
        if (!ResetSyncCheckpoint())
            return error("CheckCheckpointPubKey() : failed to reset sync-checkpoint");
    }
    return true;
}

bool SetCheckpointPrivKey(std::string strPrivKey)
{
    // Test signing a sync-checkpoint with genesis block
    CSyncCheckpoint checkpoint;
    checkpoint.hashCheckpoint = hashGenesisBlock;

    CDataStream sMsg(SER_NETWORK, PROTOCOL_VERSION);
    sMsg << (CUnsignedSyncCheckpoint)checkpoint;
    checkpoint.vchMsg = std::vector<unsigned char>(sMsg.begin(), sMsg.end());

    CBitcoinSecret vchSecret;
    if (!vchSecret.SetString(strPrivKey))
        return error("SendSyncCheckpoint: Checkpoint master key invalid");
    CKey key = vchSecret.GetKey(); // if key is not correct openssl may crash
    if (!key.Sign(Hash(checkpoint.vchMsg.begin(), checkpoint.vchMsg.end()), checkpoint.vchSig))
        return false;

    // Test signing successful, proceed
    CSyncCheckpoint::strMasterPrivKey = strPrivKey;
    return true;
}

bool SendSyncCheckpoint(uint256 hashCheckpoint)
{
    CSyncCheckpoint checkpoint;
    checkpoint.hashCheckpoint = hashCheckpoint;
    checkpoint.enforcingPaymentsTime = enforceMasternodePaymentsTime;

    CDataStream sMsg(SER_NETWORK, PROTOCOL_VERSION);
    sMsg << (CUnsignedSyncCheckpoint)checkpoint;
    checkpoint.vchMsg = std::vector<unsigned char>(sMsg.begin(), sMsg.end());

    if (CSyncCheckpoint::strMasterPrivKey.empty())
        return error("SendSyncCheckpoint: Checkpoint master key unavailable.");
    CBitcoinSecret vchSecret;
    if (!vchSecret.SetString(CSyncCheckpoint::strMasterPrivKey))
        return error("SendSyncCheckpoint: Checkpoint master key invalid");
    CKey key = vchSecret.GetKey(); // if key is not correct openssl may crash
    if (!key.Sign(Hash(checkpoint.vchMsg.begin(), checkpoint.vchMsg.end()), checkpoint.vchSig))
        return error("SendSyncCheckpoint: Unable to sign checkpoint, check private key?");

    if(!checkpoint.ProcessSyncCheckpoint(NULL))
    {
        printf("WARNING: SendSyncCheckpoint: Failed to process checkpoint.\n");
        return false;
    }

    // Relay checkpoint
    {
        LOCK(cs_vNodes);
        BOOST_FOREACH(CNode* pnode, vNodes)
            checkpoint.RelayTo(pnode);
    }
    return true;
}

// Is the sync-checkpoint outside maturity window?
bool IsMatureSyncCheckpoint()
{
    LOCK(cs_hashSyncCheckpoint);
    // sync-checkpoint should always be accepted block
    assert(mapBlockIndex.count(hashSyncCheckpoint));
    const CBlockIndex* pindexSync = mapBlockIndex[hashSyncCheckpoint];
    return (nBestHeight >= pindexSync->nHeight + COINBASE_MATURITY);
}

// Is the sync-checkpoint too old?
bool IsSyncCheckpointTooOld(unsigned int nSeconds)
{
    LOCK(cs_hashSyncCheckpoint);
    // sync-checkpoint should always be accepted block
    assert(mapBlockIndex.count(hashSyncCheckpoint));
    const CBlockIndex* pindexSync = mapBlockIndex[hashSyncCheckpoint];
    return (pindexSync->GetBlockTime() + nSeconds < GetAdjustedTime());
}

// find block wanted by given orphan block
uint256 WantedByOrphan(const CBlock* pblockOrphan)
{
    // Work back to the first block in the orphan chain
    while (mapOrphanBlocks.count(pblockOrphan->hashPrevBlock))
        pblockOrphan = mapOrphanBlocks[pblockOrphan->hashPrevBlock];
    return pblockOrphan->hashPrevBlock;
}

// verify signature of sync-checkpoint message
bool CSyncCheckpoint::CheckSignature()
{
    std::string strMasterPubKey = fTestNet? CSyncCheckpoint::strTestPubKey : CSyncCheckpoint::strMainPubKey;
    CPubKey key(ParseHex(strMasterPubKey));
    if (!key.Verify(Hash(vchMsg.begin(), vchMsg.end()), vchSig))
        return error("CSyncCheckpoint::CheckSignature() : verify signature failed");

    // Now unserialize the data
    CDataStream sMsg(vchMsg, SER_NETWORK, PROTOCOL_VERSION);
    sMsg >> *(CUnsignedSyncCheckpoint*)this;
    return true;
}

// process synchronized checkpoint
bool CSyncCheckpoint::ProcessSyncCheckpoint(CNode* pfrom)
{
    if (!CheckSignature())
        return false;

    LOCK(cs_hashSyncCheckpoint);
    if (!mapBlockIndex.count(hashCheckpoint))
    {
        // We haven't received the checkpoint chain, keep the checkpoint as pending
        hashPendingCheckpoint = hashCheckpoint;
        checkpointMessagePending = *this;
        printf("ProcessSyncCheckpoint: pending for sync-checkpoint %s\n", hashCheckpoint.ToString().c_str());
        // Ask this guy to fill in what we're missing
        if (pfrom)
        {
            pfrom->PushGetBlocks(pindexBest, hashCheckpoint);
            // ask directly as well in case rejected earlier by duplicate
            // proof-of-stake because getblocks may not get it this time
            pfrom->AskFor(CInv(MSG_BLOCK, mapOrphanBlocks.count(hashCheckpoint)? WantedByOrphan(mapOrphanBlocks[hashCheckpoint]) : hashCheckpoint));
        }
        return false;
    }

    if (!ValidateSyncCheckpoint(hashCheckpoint))
        return false;

    CBlockIndex* pindexCheckpoint = mapBlockIndex[hashCheckpoint];
    if (IsSyncCheckpointEnforced() && !pindexCheckpoint->IsInMainChain())
    {
        // checkpoint chain received but not yet main chain
        CValidationState state;
        if (!SetBestChain(state, pindexCheckpoint))
        {
            hashInvalidCheckpoint = hashCheckpoint;
            return error("ProcessSyncCheckpoint: SetBestChain failed for sync checkpoint %s", hashCheckpoint.ToString().c_str());
        }
    }

    if (!WriteSyncCheckpoint(hashCheckpoint))
        return error("ProcessSyncCheckpoint(): failed to write sync checkpoint %s", hashCheckpoint.ToString().c_str());
    checkpointMessage = *this;
    hashPendingCheckpoint = 0;
    checkpointMessagePending.SetNull();
    printf("ProcessSyncCheckpoint: sync-checkpoint at %s\n", hashCheckpoint.ToString().c_str());
    return true;
}


// RPC commands related to sync checkpoints
// get information of sync-checkpoint (first introduced in ppcoin)
Value getcheckpoint(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getcheckpoint\n"
            "Show info of synchronized checkpoint.\n");

    Object result;
    CBlockIndex* pindexCheckpoint;

    result.push_back(Pair("synccheckpoint", hashSyncCheckpoint.ToString().c_str()));
    if (mapBlockIndex.count(hashSyncCheckpoint))
    {
        pindexCheckpoint = mapBlockIndex[hashSyncCheckpoint];
        result.push_back(Pair("height", pindexCheckpoint->nHeight));
        result.push_back(Pair("timestamp", (boost::int64_t) pindexCheckpoint->GetBlockTime()));
    }
    result.push_back(Pair("subscribemode", IsSyncCheckpointEnforced()? "enforce" : "advisory"));
    if (mapArgs.count("-checkpointkey"))
        result.push_back(Pair("checkpointmaster", true));

    return result;
}

Value sendcheckpoint(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "sendcheckpoint <blockhash>\n"
            "Send a synchronized checkpoint.\n");

    if (!mapArgs.count("-checkpointkey") || CSyncCheckpoint::strMasterPrivKey.empty())
        throw runtime_error("Not a checkpointmaster node, first set checkpointkey in configuration and restart client. ");

    std::string strHash = params[0].get_str();
    uint256 hash(strHash);

    if (!SendSyncCheckpoint(hash))
        throw runtime_error("Failed to send checkpoint, check log. ");

    Object result;
    CBlockIndex* pindexCheckpoint;

    result.push_back(Pair("synccheckpoint", hashSyncCheckpoint.ToString().c_str()));
    if (mapBlockIndex.count(hashSyncCheckpoint))
    {
        pindexCheckpoint = mapBlockIndex[hashSyncCheckpoint];
        result.push_back(Pair("height", pindexCheckpoint->nHeight));
        result.push_back(Pair("timestamp", (boost::int64_t) pindexCheckpoint->GetBlockTime()));
    }
    result.push_back(Pair("subscribemode", IsSyncCheckpointEnforced()? "enforce" : "advisory"));
    if (mapArgs.count("-checkpointkey"))
        result.push_back(Pair("checkpointmaster", true));

    return result;
}

Value enforcecheckpoint(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "enforcecheckpoint <enforce> <enforcemasternodepayments>\n"
            "<enforce> is true or false to enable or disable enforcement of broadcasted checkpoints by developer."
            "<enforcemasternodepayments> change if the network should enforce masternode payment rules for blocks");

    bool fEnforceCheckpoint = params[0].get_bool();
    
    if (mapArgs.count("-checkpointkey") && !fEnforceCheckpoint)
        throw runtime_error(
            "checkpoint master node must enforce synchronized checkpoints.");
    if (fEnforceCheckpoint)
        strCheckpointWarning = "";
    mapArgs["-checkpointenforce"] = (fEnforceCheckpoint ? "1" : "0");
    
    int64 enforceMasternodePaymentsIn = params[1].get_int64();
    enforceMasternodePaymentsTime = enforceMasternodePaymentsIn;

    return Value::null;
}

