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

#include "auxillary.h"

#include <boost/algorithm/string.hpp>

/**
 * Statements: 
 *  OP_MINT HexOf(123$456$789@SignatureX@SignatureY)
 * Tree
 *  |---------|
 *  | OP_MINT |
 *  |_________|
 *       |
 *       |
 *  |----------------|       |-------------|     |-------------|
 *  | Command   One  | ----- | Digest One  |-----| Digest Two  |
 *  | _______________|       |_____________|     |_____________|
 *       |
 *       |
 *	------------------------
 *  |          |           |
 * 123        456         789
 * 
 **/
 
ProtocolToken SignatureDelimiter = " ";
ProtocolToken PrimaryDelimiter = "@";
ProtocolToken SubDelimiter = "$";

/**
 * Fluid Protocol Commands, usage of only OP_FLUID OPCODE with Sub-Opcodes
 **/
static const int FLUID_OPERATION_MINT_COINS 				= 0xff01;
static const int FLUID_OPERATION_DESTROY_COINS 				= 0xff02; // ONLY COMMAND AVAILABLE FOR ALL USERS
static const int FLUID_OPERATION_CHANGE_REWARD_DYNODE 		= 0xff03;
static const int FLUID_OPERATION_CHANGE_REWARD_MINING 		= 0xff04;
static const int FLUID_OPERATION_STERILIZE_ADDRESS 			= 0xff05;
static const int FLUID_OPERATION_REALLOW_ADDRESS 			= 0xff06;
static const int FLUID_OPERATION_REACTIVATE 				= 0xff07;
static const int FLUID_OPERATION_DEACTIVATE 				= 0xff08;
static const int FLUID_OPERATION_DROPLET 					= 0xff09;
static const int FLUID_OPERATION_RESERVED_ONE				= 0xff10;
static const int FLUID_OPERATION_RESERVED_TWO				= 0xff11;
static const int FLUID_OPERATION_RESERVED_THREE				= 0xff12;
static const int FLUID_OPERATION_RESERVED_FOUR				= 0xff13;
static const int FLUID_OPERATION_RESERVED_FIVE				= 0xff14;

/* String Manipulation */
void ScrubString(std::string &input, bool forInteger) {
	input.erase(std::remove(input.begin(), input.end(), '@'), input.end());
	input.erase(std::remove(input.begin(), input.end(), '$'), input.end());
	if (forInteger)
		input.erase(std::remove(input.begin(), input.end(), ' '), input.end());
}

void SeperateString(std::string input, std::vector<std::string> &output, bool subDelimiter) {
	if(subDelimiter)
		boost::split(output, input, boost::is_any_of(SubDelimiter));
	else
		boost::split(output, input, boost::is_any_of(PrimaryDelimiter));
};

std::string StitchString(std::string stringOne, std::string stringTwo, bool subDelimiter) {
//	ScrubString(stringOne); ScrubString(stringTwo);
	
	if(subDelimiter)
		return stringOne + SubDelimiter + stringTwo;
	else 
		return stringOne + PrimaryDelimiter + stringTwo;
}

std::string StitchString(std::string stringOne, std::string stringTwo, std::string stringThree, bool subDelimiter) {
//	ScrubString(stringOne); ScrubString(stringTwo);
	
	if(subDelimiter)
		return stringOne + SubDelimiter + stringTwo + SubDelimiter + stringThree;
	else 
		return stringOne + PrimaryDelimiter + stringTwo + PrimaryDelimiter + stringThree;
}
#include <stdint.h>

#include <iostream>
#include <sstream>

int64_t stringToInteger(std::string input) {
	int64_t result;
	
	ScrubString(input, true);
	std::stringstream stream(input);
	stream >> result;
	
	return result;
}

std::string getRidOfScriptStatement(std::string input) {
	std::vector<std::string> output;
	boost::split(output, input, boost::is_any_of(" "));
	
	return output.at(1);
}

/*
* Base64 encoding/decoding (RFC1341)
* Copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
*
* This software may be distributed under the terms of the BSD license.
* 2016-12-12 - Gaspard Petit : Slightly modified to return a std::string 
* instead of a buffer allocated with malloc.
*/

#include <string>

std::string Base64Functions::Base64Encode(const unsigned char *src, size_t len)
{
    unsigned char *out, *pos;
    const unsigned char *end, *in;

    size_t olen;

    olen = 4*((len + 2) / 3); /* 3-byte blocks to 4-byte */

    if (olen < len)
        return std::string(); /* integer overflow */

    std::string outStr;
    outStr.resize(olen);
    out = (unsigned char*)&outStr[0];

    end = src + len;
    in = src;
    pos = out;
    while (end - in >= 3) {
        *pos++ = base64_table[in[0] >> 2];
        *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
        *pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
        *pos++ = base64_table[in[2] & 0x3f];
        in += 3;
    }

    if (end - in) {
        *pos++ = base64_table[in[0] >> 2];
        if (end - in == 1) {
            *pos++ = base64_table[(in[0] & 0x03) << 4];
            *pos++ = '=';
        }
        else {
            *pos++ = base64_table[((in[0] & 0x03) << 4) |
                (in[1] >> 4)];
            *pos++ = base64_table[(in[1] & 0x0f) << 2];
        }
        *pos++ = '=';
    }

    return outStr;
}

std::string Base64Functions::Base64Decode(const void* data, const size_t len)
{
    unsigned char* p = (unsigned char*)data;
    int pad = len > 0 && (len % 4 || p[len - 1] == '=');
    const size_t L = ((len + 3) / 4 - pad) * 4;
    std::string str(L / 4 * 3 + pad, '\0');

    for (size_t i = 0, j = 0; i < L; i += 4)
    {
        int n = B64index[p[i]] << 18 | B64index[p[i + 1]] << 12 | B64index[p[i + 2]] << 6 | B64index[p[i + 3]];
        str[j++] = n >> 16;
        str[j++] = n >> 8 & 0xFF;
        str[j++] = n & 0xFF;
    }
    if (pad)
    {
        int n = B64index[p[L]] << 18 | B64index[p[L + 1]] << 12;
        str[str.size() - 1] = n >> 16;

        if (len > L + 2 && p[L + 2] != '=')
        {
            n |= B64index[p[L + 2]] << 6;
            str.push_back(n >> 8 & 0xFF);
        }
    }
    return str;
}
