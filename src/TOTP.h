// OpenAuthentication Time-based One-time Password Algorithm (RFC 6238)
// Arduino Library
//
// Luca Dentella (http://www.lucadentella.it)

#include "Arduino.h"

#ifndef _TOTP_H
#define _TOTP_H


class TOTP {

	public:
	
		TOTP(uint8_t* hmacKey, int keyLength);
		TOTP(uint8_t* hmacKey, int keyLength, int timeStep);
		char* getCode(long timeStamp);
		char* getCodeFromSteps(long steps);
	
	private:

		uint8_t* _hmacKey;
		int _keyLength;
		int _timeStep;
		uint8_t _byteArray[8];
		uint8_t* _hash;
		int _offset;
		long _truncatedHash;
		char _code[7];
};

#endif