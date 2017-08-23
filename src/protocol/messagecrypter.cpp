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

#include "messagecrypter.h"

bool CMessageCrypter::Encrypt(const string& vchPubKey, const string& vchPlaintext, string& vchCiphertext)
{
    try
    {
        AutoSeededRandomPool prng;
        StringSource ss(vchPubKey, true);
		ECIES<ECP>::Encryptor encryptor;

        //curve used is secp256k1
        encryptor.AccessKey().AccessGroupParameters().Initialize(ASN1::secp256k1());

        //get point on the used curve
        ECP::Point point;
        encryptor.GetKey().GetGroupParameters().GetCurve().DecodePoint(point, ss, ss.MaxRetrievable());

        //set encryptor's public element
        encryptor.AccessKey().SetPublicElement(point);

        //check whether the encryptor's access key thus formed is valid or not
        encryptor.AccessKey().ThrowIfInvalid(prng, 3);

        // encrypted message
        StringSource ss1(vchPlaintext, true, new PK_EncryptorFilter(prng, encryptor, new StringSink(vchCiphertext) ) );
    }
    catch(const CryptoPP::Exception& ex)
    {
		return false;
    }

	return true;
}

bool CMessageCrypter::Decrypt(const string& vchPrivKey, const string& vchCiphertext, string& vchPlaintext)
{
    try
    {
        AutoSeededRandomPool prng;

        StringSource ss(vchPrivKey, true /*pumpAll*/);

        Integer x;
        x.Decode(ss, ss.MaxRetrievable(), Integer::UNSIGNED);

        ECIES<ECP>::Decryptor decryptor;

		decryptor.AccessKey().AccessGroupParameters().Initialize(ASN1::secp256k1());	
        //make decryptor's access key using decoded private exponent's value
        decryptor.AccessKey().SetPrivateExponent(x);

        //check whether decryptor's access key is valid or not
        bool valid = decryptor.AccessKey().Validate(prng, 3);
        if(!valid)
           decryptor.AccessKey().ThrowIfInvalid(prng, 3);

        //decrypt the message using private key
        StringSource ss2 (vchCiphertext, true, new PK_DecryptorFilter(prng, decryptor, new StringSink(vchPlaintext) ) );

    }
    catch(const CryptoPP::Exception& ex)
    {
		return false;
    }
    return true;
}
