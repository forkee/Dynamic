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

#ifndef FEEDBACK_H
#define FEEDBACK_H

#include "script/script.h"
#include "serialize.h"

enum FeedbackUser {
	FEEDBACKNONE=0,
    FEEDBACKBUYER=1,
	FEEDBACKSELLER=2,
	FEEDBACKARBITER=3
};

class CFeedback {
public:
	std::vector<unsigned char> vchFeedback;
	unsigned char nRating;
	unsigned char nFeedbackUserTo;
	unsigned char nFeedbackUserFrom;
	uint64_t nHeight;
	uint256 txHash;
    CFeedback() {
        SetNull();
    }
    CFeedback(unsigned char nAcceptFeedbackUserFrom, unsigned char nAcceptFeedbackUserTo) {
        SetNull();
		nFeedbackUserFrom = nAcceptFeedbackUserFrom;
		nFeedbackUserTo = nAcceptFeedbackUserTo;
    }
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
		READWRITE(vchFeedback);
		READWRITE(VARINT(nRating));
		READWRITE(VARINT(nFeedbackUserFrom));
		READWRITE(VARINT(nFeedbackUserTo));
		READWRITE(VARINT(nHeight));
		READWRITE(txHash);
	}

    friend bool operator==(const CFeedback &a, const CFeedback &b) {
        return (
        a.vchFeedback == b.vchFeedback
		&& a.nRating == b.nRating
		&& a.nFeedbackUserFrom == b.nFeedbackUserFrom
		&& a.nFeedbackUserTo == b.nFeedbackUserTo
		&& a.nHeight == b.nHeight
		&& a.txHash == b.txHash
        );
    }

    CFeedback operator=(const CFeedback &b) {
        vchFeedback = b.vchFeedback;
		nRating = b.nRating;
		nFeedbackUserFrom = b.nFeedbackUserFrom;
		nFeedbackUserTo = b.nFeedbackUserTo;
		nHeight = b.nHeight;
		txHash = b.txHash;
        return *this;
    }

    friend bool operator!=(const CFeedback &a, const CFeedback &b) {
        return !(a == b);
    }

    void SetNull() { txHash.SetNull(); nHeight = 0; nRating = 0; nFeedbackUserFrom = 0; nFeedbackUserTo = 0; vchFeedback.clear();}
    bool IsNull() const { return ( txHash.IsNull() && nHeight == 0 && nRating == 0 && nFeedbackUserFrom == 0 && nFeedbackUserTo == 0 && vchFeedback.empty()); }
};
struct feedbacksort {
    bool operator ()(const CFeedback& a, const CFeedback& b) {
        return a.nHeight < b.nHeight;
    }
};
#endif // FEEDBACK_H
