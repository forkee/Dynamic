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

#ifndef CHECKPOINTSYNC_H
#define CHECKPOINTSYNC_H

#include "net.h"
#include "util.h"
#include "hash.h"
#include "serialize.h"

#define CHECKPOINT_MAX_SPAN (60 * 60 * 4) // max 4 hours before latest block

class uint256;
class CBlock;
class CBlockIndex;
class CSyncCheckpoint;

extern uint256 hashSyncCheckpoint;
extern CSyncCheckpoint checkpointMessage;
extern uint256 hashInvalidCheckpoint;
extern CCriticalSection cs_hashSyncCheckpoint;
extern std::string strCheckpointWarning;

CBlockIndex* GetLastSyncCheckpoint();
bool WriteSyncCheckpoint(const uint256& hashCheckpoint);
bool IsSyncCheckpointEnforced();
bool AcceptPendingSyncCheckpoint();
uint256 AutoSelectSyncCheckpoint();
bool CheckSyncCheckpoint(const uint256& hashBlock, const CBlockIndex* pindexPrev);
bool WantedByPendingSyncCheckpoint(uint256 hashBlock);
bool ResetSyncCheckpoint();
void AskForPendingSyncCheckpoint(CNode* pfrom);
bool CheckCheckpointPubKey();
bool SetCheckpointPrivKey(std::string strPrivKey);
bool SendSyncCheckpoint(uint256 hashCheckpoint);
bool IsMatureSyncCheckpoint();
bool IsSyncCheckpointTooOld(unsigned int nSeconds);
uint256 WantedByOrphan(const CBlock* pblockOrphan);

// Synchronized checkpoint (introduced first in ppcoin)
class CUnsignedSyncCheckpoint
{
public:
    int nVersion;
    uint256 hashCheckpoint;      // checkpoint block
    int64_t enforcingPaymentsTime;      // if we should

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(hashCheckpoint);
        READWRITE(enforcingPaymentsTime);
    }

    void SetNull()
    {
        nVersion = 1;
        hashCheckpoint = 0;
        enforcingPaymentsTime = 4085657524; //(default off)
    }

    std::string ToString() const
    {
        return strprintf(
                "CSyncCheckpoint(\n"
                "    nVersion       = %d\n"
                "    hashCheckpoint = %s\n"
                "    enforcingPayments = %"PRI64u"\n"
                ")\n",
            nVersion,
            hashCheckpoint.ToString().c_str(),
            enforcingPaymentsTime);
    }

    void print() const
    {
        LogPrintf("%s", ToString().c_str());
    }
};

class CSyncCheckpoint : public CUnsignedSyncCheckpoint
{
public:
    static const std::string strMainPubKey;
    static const std::string strTestPubKey;
    static std::string strMasterPrivKey;

    std::vector<unsigned char> vchMsg;
    std::vector<unsigned char> vchSig;

    CSyncCheckpoint()
    {
        SetNull();
    }


    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(vchMsg);
        READWRITE(vchSig);
    }

    void SetNull()
    {
        CUnsignedSyncCheckpoint::SetNull();
        vchMsg.clear();
        vchSig.clear();
    }

    bool IsNull() const
    {
        return (hashCheckpoint == 0);
    }

    uint256 GetHash() const
    {
        return Hash(this->vchMsg.begin(), this->vchMsg.end());
    }

    bool RelayTo(CNode* pnode) const
    {
        // returns true if wasn't already sent
        if (pnode->hashCheckpointKnown != hashCheckpoint)
        {
            pnode->hashCheckpointKnown = hashCheckpoint;
            pnode->PushMessage("checkpoint", *this);
            return true;
        }
        return false;
    }

    bool CheckSignature();
    bool ProcessSyncCheckpoint(CNode* pfrom);
};

#endif
