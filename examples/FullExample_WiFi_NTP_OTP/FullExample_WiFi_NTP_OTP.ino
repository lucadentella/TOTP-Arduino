// TOTP DEMO, v1.0
//
// Requires a WiFi-capable board (for example esp32)
// and NTPClient library: https://github.com/arduino-libraries/NTPClient
//
// Change the wifi settings and enter your hmacKey
//
// To generate the hmacKey and initialize the smartphone app
// you can use my tool: http://www.lucadentella.it/OTP
//
// Tested with Arduino 1.8.12, NTPClient 3.2.0 and esp32 1.0.4


#include <WiFi.h>
#include <NTPClient.h>
#include <TOTP.h>

// change the following settings according to your WiFi network
char ssid[] = "mySSID";
char password[] = "myPASSWORD";

// enter your hmacKey (10 digits)
uint8_t hmacKey[] = {0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x6b, 0x65, 0x79, 0x30};

WiFiUDP ntpUDP;
NTPClient timeClient(ntpUDP);
TOTP totp = TOTP(hmacKey, 10);

String totpCode = String("");

void setup() {

  Serial.begin(9600);
  while (!Serial);

  Serial.println("TOTP demo");
  Serial.println();
  
  // connect to the WiFi network
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.println("Establishing connection to WiFi...");
  }
  Serial.print("Connected to WiFi with IP: ");
  Serial.println(WiFi.localIP());
  Serial.println();

  // start the NTP client
  timeClient.begin();
  Serial.println("NTP client started");
  Serial.println();
}

void loop() {

  // update the time 
  timeClient.update();

  // generate the TOTP code and, if different from the previous one, print to screen
  String newCode = String(totp.getCode(timeClient.getEpochTime()));
  if(totpCode!= newCode) {
    totpCode = String(newCode);
    Serial.print("TOTP code: ");
    Serial.println(newCode);
  }
}
