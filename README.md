Arduino TOTP Library
====================

Library to generate Time-based One-Time Passwords.

Implements the Time-based One-Time Password algorithm specified in [RFC 6238](https://tools.ietf.org/html/rfc6238). Supports different time steps and it's compatible with tokens that uses the same standard (including software ones, like the Google Authenticator app).


Installation & usage:
--------------------
Install the library using the Library Manager or manually in the \libraries folder of your IDE.
This library requires the [Cryptosuite library](https://github.com/maniacbug/Cryptosuite) by maniacbug.

First, store your private key into an array:
```
uint8_t hmacKey[] = {0x4d, 0x79, 0x4c, 0x65, 0x67, 0x6f, 0x44, 0x6f, 0x6f, 0x72};
```
Then create a new instance of the TOTP class using one of the two available constructors:
```
TOTP(uint8_t* hmacKey, int keyLength);
TOTP(uint8_t* hmacKey, int keyLength, int timeStep);
```
The first assumes a timeStep of 30 seconds, value used for example by the Google Authenticator app.

Two methods are available to get a TOTP passcode:
```
char* getCode(long timeStamp);
char* getCodeFromSteps(long steps);
```
The first accept a unix timestamp (number of seconds since Epoch), the second the number of "steps" since Epoch (that is seconds / timeStep) and it's useful to get a pool of values.

A demo project:
---------------

http://www.lucadentella.it/2013/09/14/serratura-otp/


Thanks to:
----------

* Jose Damico, https://github.com/damico/ARDUINO-OATH-TOKEN
* Peter Knight, https://github.com/Cathedrow/Cryptosuite
* Maniacbug, https://github.com/maniacbug/Cryptosuite
