// OpenAuthentication Time-based One-time Password Algorithm (RFC 6238)
// For the complete description of the algorithm see
// http://tools.ietf.org/html/rfc4226#section-5.3
//
// Luca Dentella (http://www.lucadentella.it)

#include "TOTP.h"
#include "Cryptosuite/sha1.h"
#include "Cryptosuite/sha256.h"

// Init the library with the private key, its length, the timeStep duration and the algorithm
TOTP::TOTP(uint8_t* hmacKey, int keyLength, int timeStep, Algorithm algorithm) {

	_hmacKey = hmacKey;
	_keyLength = keyLength;
	_timeStep = timeStep;
	_algorithm = algorithm;
};

// Generate a code, using the timestamp provided
char* TOTP::getCode(long timeStamp) {
	
	long steps = timeStamp / _timeStep;
	return getCodeFromSteps(steps);
}

// Generate a code, using the number of steps provided
char* TOTP::getCodeFromSteps(long steps) {
	
	// Use different digest length for SHA1 and SHA256
	int _digestlength;
	
	// STEP 0, map the number of steps in a 8-bytes array (counter value)
	_byteArray[0] = 0x00;
	_byteArray[1] = 0x00;
	_byteArray[2] = 0x00;
	_byteArray[3] = 0x00;
	_byteArray[4] = (int)((steps >> 24) & 0xFF);
	_byteArray[5] = (int)((steps >> 16) & 0xFF);
	_byteArray[6] = (int)((steps >> 8) & 0XFF);
	_byteArray[7] = (int)((steps & 0XFF));
	
	// STEP 1, get the HMAC-SHA1 hash from counter and key
	switch(_algorithm) {
	
		case SHA1:
			Sha1.initHmac(_hmacKey, _keyLength);
			Sha1.write(_byteArray, 8);
			_hash = Sha1.resultHmac();
			_digestlength = 20;
			break;
		
		case SHA256:
			Sha256.initHmac(_hmacKey, _keyLength);
			Sha256.write(_byteArray, 8);
			_hash = Sha256.resultHmac();
			_digestlength = 32;
			break;		
	}	
	
	// STEP 2, apply dynamic truncation to obtain a 4-bytes string
	_offset = _hash[_digestlength - 1] & 0xF; 
	_truncatedHash = 0;
	for (int j = 0; j < 4; ++j) {
		_truncatedHash <<= 8;
		_truncatedHash  |= _hash[_offset + j];
	}

	// STEP 3, compute the OTP value
	_truncatedHash &= 0x7FFFFFFF;
	_truncatedHash %= 1000000;
	
	// convert the value in string, with heading zeroes
	sprintf(_code, "%06ld", _truncatedHash);
	return _code;
}
