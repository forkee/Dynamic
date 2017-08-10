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

#ifndef AUXILLARY_PROTOCOL_H
#define AUXILLARY_PROTOCOL_H

#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

typedef std::string ProtocolToken;

extern ProtocolToken PrimaryDelimiter;
extern ProtocolToken SubDelimiter;
extern ProtocolToken SignatureDelimiter;

/* Identification Codes */
static const int IDENTIFIER_NO_TX 					= 0;

static const int IDENTIFIER_MINT_TX 				= 1;
static const int IDENTIFIER_DESTROY_TX 				= 2;

static const int IDENTIFIER_DYNODE_MODFIY_TX 		= 3;
static const int IDENTIFIER_MINING_MODIFY_TX 		= 4;

static const int IDENTIFIER_ACTIVATE_TX 			= 5;
static const int IDENTIFIER_DEACTIVATE_TX 			= 6;

static const int IDENTIFIER_REALLOW_TX 				= 7;
static const int IDENTIFIER_STERILIZE_TX 			= 8;

enum KeyNumber {
	KEY_UNE = 1,
	KEY_DEUX = 2,
	KEY_TROIS = 3,
	
	KEY_MAX = 0
};

enum ProtocolCodes {
	MINT_TX 			= IDENTIFIER_MINT_TX,
	DESTROY_TX 			= IDENTIFIER_DESTROY_TX,
	DYNODE_MODFIY_TX 	= IDENTIFIER_DYNODE_MODFIY_TX,
	MINING_MODIFY_TX 	= IDENTIFIER_MINING_MODIFY_TX,
	ACTIVATE_TX 		= IDENTIFIER_ACTIVATE_TX,
	DEACTIVATE_TX 		= IDENTIFIER_DEACTIVATE_TX,
	REALLOW_TX			= IDENTIFIER_REALLOW_TX,
	STERILIZE_TX		= IDENTIFIER_STERILIZE_TX,
	
	NO_TX = IDENTIFIER_NO_TX
};

static const unsigned char base64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		
static const int B64index[256] = { 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 62, 63, 62, 62, 63, 52, 53, 54, 55,
	56, 57, 58, 59, 60, 61,  0,  0,  0,  0,  0,  0,  0,  0,  1,  2,  3,  4,  5,  6,
	7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,  0,
	0,  0,  0, 63,  0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51 
};
	
class Base64Functions {
private:	
	std::string Base64Decode(const void* data, const size_t len);
	std::string Base64Encode(const unsigned char *src, size_t len);
public:
	static inline bool is_base64(unsigned char c) {
		return (isalnum(c) || (c == '+') || (c == '/'));
	}
};

class HexFunctions {
public:
	// C++98 guarantees that '0', '1', ... '9' are consecutive.
	// It only guarantees that 'a' ... 'f' and 'A' ... 'F' are
	// in increasing order, but the only two alternative encodings
	// of the basic source character set that are still used by
	// anyone today (ASCII and EBCDIC) make them consecutive.
	unsigned char hexval(unsigned char c)
	{
		if ('0' <= c && c <= '9')
			return c - '0';
		else if ('a' <= c && c <= 'f')
			return c - 'a' + 10;
		else if ('A' <= c && c <= 'F')
			return c - 'A' + 10;
		else abort();
	}

	// TODO: Switch to CryptoPP
	std::string StringToHex(std::string input) {
		static const char* const lut = "0123456789ABCDEF";
		size_t len = input.length();
		std::string output;
		output.reserve(2 * len);
		for (size_t i = 0; i < len; ++i)
		{
			const unsigned char c = input[i];
			output.push_back(lut[c >> 4]);
			output.push_back(lut[c & 15]);
		}
		
		return output;
	}
	
	// TODO: Switch to CryptoPP
	std::string HexToString(std::string in) {
		std::string out;
		out.clear();
		out.reserve(in.length() / 2);
		for (std::string::const_iterator p = in.begin(); p != in.end(); p++)
		{
		   unsigned char c = hexval(*p);
		   p++;
		   if (p == in.end()) break; // incomplete last digit - should report error
		   c = (c << 4) + hexval(*p); // + takes precedence over <<
		   out.push_back(c);
		}
		return out;
	}
	
	void ConvertToHex(std::string &input) { std::string output = StringToHex(input); input = output; }
	void ConvertToString(std::string &input) { std::string output = HexToString(input); input = output; }
};

/* String Manipulation Functions */
void ScrubString(std::string &input, bool forInteger = false);
void SeperateString(std::string input, std::vector<std::string> &output, bool subDelimiter = false);
std::string StitchString(std::string stringOne, std::string stringTwo, bool subDelimiter = false);
std::string StitchString(std::string stringOne, std::string stringTwo, std::string stringThree, bool subDelimiter = false);
int64_t stringToInteger(std::string input);
std::string getRidOfScriptStatement(std::string input);

#endif // AUXILLARY_PROTOCOL_H
