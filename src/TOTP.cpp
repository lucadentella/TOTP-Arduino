// OpenAuthentication Time-based One-time Password Algorithm (RFC 6238)
// For the complete description of the algorithm see
// http://tools.ietf.org/html/rfc4226#section-5.3
//
// Luca Dentella (http://www.lucadentella.it)

#include "TOTP.h"
#include "sha1.h"

const int DEFAULT_CODE_LEN = 6;

// Init the library with the private key, its length and the timeStep duration
TOTP::TOTP(uint8_t* hmacKey, int keyLength, int timeStep) {

	_hmacKey = hmacKey;
	_keyLength = keyLength;
	_timeStep = timeStep;
};

// Init the library with the private key, its length and a time step of 30sec (default for Google Authenticator)
TOTP::TOTP(uint8_t* hmacKey, int keyLength) {

	_hmacKey = hmacKey;
	_keyLength = keyLength;
	_timeStep = 30;
};

long pow10(int n) {
    static long pow10[10] = {
        1, 10, 100, 1000, 10000, 
        100000, 1000000, 10000000, 100000000, 1000000000,
    };

    return pow10[n]; 
} 

char* getFormatString(int codeLen) {
	static char format[10][6] = {
        "%01ld", "%02ld", "%03ld", "%04ld", "%05ld", 
         "%06ld", "%07ld",  "%08ld",  "%09ld",
    };

	return format[codeLen-1];
}

// Generate a code, using the timestamp provided
char* TOTP::getCode(long timeStamp) {
	return getCode(timeStamp, DEFAULT_CODE_LEN);
}

// Generate a code of specified length, using the timestamp provided  
char* TOTP::getCode(long timeStamp, int codeLen) {
	long steps = timeStamp / _timeStep;
	return getCodeFromSteps(steps, codeLen);
}

// Generate a code, using the number of steps provided
char* TOTP::getCodeFromSteps(long steps) {
	return getCodeFromSteps(steps, DEFAULT_CODE_LEN);

}

char *TOTP::getCodeFromSteps(long steps, int codeLen) {
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
	Sha1.initHmac(_hmacKey, _keyLength);
	Sha1.write(_byteArray, 8);
	_hash = Sha1.resultHmac();
	
	// STEP 2, apply dynamic truncation to obtain a 4-bytes string
	_offset = _hash[20 - 1] & 0xF; 
	_truncatedHash = 0;
	for (int j = 0; j < 4; ++j) {
		_truncatedHash <<= 8;
		_truncatedHash  |= _hash[_offset + j];
	}

	// STEP 3, compute the OTP value
	_truncatedHash &= 0x7FFFFFFF;
	_truncatedHash %= pow10(codeLen);
	
	sprintf(_code, getFormatString(codeLen), _truncatedHash);

	return _code;
}

