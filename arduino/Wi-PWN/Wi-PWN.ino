/*
  ===========================================
       Copyright (c) 2017 Stefan Kremser
              github.com/spacehuhn
  ===========================================
*/

#include <Arduino.h>

#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <FS.h>

#define resetPin 4 /* <-- comment out or change if you need GPIO 4 for other purposes */
//#define USE_DISPLAY /* <-- uncomment that if you want to use the display */
//#define USE_LED16 /* <-- for the Pocket ESP8266 which has a LED on GPIO 16 to indicate if it's running */

String wifiMode = "";
String attackMode = "";
String scanMode = "SCAN";

bool warning = true;

extern "C" {
  #include "user_interface.h"
}

ESP8266WebServer server(80);

#include <EEPROM.h>
#include "data.h"
#include "NameList.h"
#include "APScan.h"
#include "ClientScan.h"
#include "Attack.h"
#include "Settings.h"
#include "SSIDList.h"

/* ========== DEBUG ========== */
const bool debug = true;
/* ========== DEBUG ========== */

NameList nameList;

APScan apScan;
ClientScan clientScan;
Attack attack;
Settings settings;
SSIDList ssidList;

void sniffer(uint8_t *buf, uint16_t len) {
  clientScan.packetSniffer(buf, len);
}


void startWifi() {
  Serial.println("\nStarting WiFi AP:");
  WiFi.mode(WIFI_STA);
  wifi_set_promiscuous_rx_cb(sniffer);
  WiFi.softAP((const char*)settings.ssid.c_str(), (const char*)settings.password.c_str(), settings.apChannel, settings.ssidHidden); //for an open network without a password change to:  WiFi.softAP(ssid);
  Serial.println("SSID     : '" + settings.ssid+"'");
  Serial.println("Password : '" + settings.password+"'");
  Serial.println("-----------------------------------------------");
  if (settings.password.length() < 8) Serial.println("WARNING: password must have at least 8 characters!");
  if (settings.ssid.length() < 1 || settings.ssid.length() > 32) Serial.println("WARNING: SSID length must be between 1 and 32 characters!");
  wifiMode = "ON";
}

void stopWifi() {
  Serial.println("stopping WiFi AP");
  Serial.println("-----------------------------------------------");
  WiFi.disconnect();
  wifi_set_opmode(STATION_MODE);
  wifiMode = "OFF";
}

void loadIndexHTML() {
  if(warning){
    sendFile(200, "text/html", data_indexHTML, sizeof(data_indexHTML));
  }else{
    sendFile(200, "text/html", data_apscanHTML, sizeof(data_apscanHTML));
  }
}
void loadAPScanHTML() {
  warning = false;
  sendFile(200, "text/html", data_apscanHTML, sizeof(data_apscanHTML));
}
void loadStationsHTML() {
  sendFile(200, "text/html", data_stationHTML, sizeof(data_stationHTML));
}
void loadAttackHTML() {
  sendFile(200, "text/html", data_attackHTML, sizeof(data_attackHTML));
}
void loadSettingsHTML() {
  sendFile(200, "text/html", data_settingsHTML, sizeof(data_settingsHTML));
}
void load404() {
  sendFile(200, "text/html", data_error404, sizeof(data_error404));
}
void loadInfoHTML(){
  sendFile(200, "text/html", data_infoHTML, sizeof(data_infoHTML));
}

void loadFunctionsJS() {
  sendFile(200, "text/javascript", data_functionsJS, sizeof(data_functionsJS));
}
void loadAPScanJS() {
  sendFile(200, "text/javascript", data_apscanJS, sizeof(data_apscanJS));
}
void loadStationsJS() {
  sendFile(200, "text/javascript", data_stationsJS, sizeof(data_stationsJS));
}
void loadAttackJS() {
  attack.ssidChange = true;
  sendFile(200, "text/javascript", data_attackJS, sizeof(data_attackJS));
}
void loadSettingsJS() {
  sendFile(200, "text/javascript", data_settingsJS, sizeof(data_settingsJS));
}

void loadStyle() {
  sendFile(200, "text/css;charset=UTF-8", data_styleCSS, sizeof(data_styleCSS));
}

void loadDarkMode() {
  sendFile(200, "text/css;charset=UTF-8", data_darkModeCSS, sizeof(data_darkModeCSS));
}


void startWiFi(bool start) {
  if (start) startWifi();
  else stopWifi();
  clientScan.clearList();
}

//==========AP-Scan==========
void startAPScan() {
  scanMode = "scanning...";
#ifdef USE_DISPLAY
  drawInterface();
#endif
  if (apScan.start()) {


    server.send ( 200, "text/json", "true");
    attack.stopAll();
    scanMode = "SCAN";
  }
}

void sendAPResults() {
  apScan.sendResults();
}

void selectAP() {
  if (server.hasArg("num")) {
    apScan.select(server.arg("num").toInt());
    server.send( 200, "text/json", "true");
    attack.stopAll();
  }
}

//==========Client-Scan==========
void startClientScan() {
  if (server.hasArg("time") && apScan.getFirstTarget() > -1 && !clientScan.sniffing) {
    server.send(200, "text/json", "true");
    clientScan.start(server.arg("time").toInt());
    attack.stopAll();
  } else server.send( 200, "text/json", "ERROR: No selected Wi-Fi networks!");
}

void sendClientResults() {
  clientScan.send();
}
void sendClientScanTime() {
  server.send( 200, "text/json", (String)settings.clientScanTime );
}

void selectClient() {
  if (server.hasArg("num")) {
    clientScan.select(server.arg("num").toInt());
    attack.stop(0);
    server.send( 200, "text/json", "true");
  }
}

void addClientFromList(){
  if(server.hasArg("num")) {
    int _num = server.arg("num").toInt();
    clientScan.add(nameList.getMac(_num));
    
    server.send( 200, "text/json", "true");
  }else server.send( 200, "text/json", "false");
}

void setClientName() {
  if (server.hasArg("id") && server.hasArg("name")) {
    if(server.arg("name").length()>0){
      nameList.add(clientScan.getClientMac(server.arg("id").toInt()), server.arg("name"));
      server.send( 200, "text/json", "true");
    }
    else server.send( 200, "text/json", "false");
  }
}

void deleteName() {
  if (server.hasArg("num")) {
    int _num = server.arg("num").toInt();
    nameList.remove(_num);
    server.send( 200, "text/json", "true");
  }else server.send( 200, "text/json", "false");
}

void clearNameList() {
  nameList.clear();
  server.send( 200, "text/json", "true" );
}

void editClientName() {
  if (server.hasArg("id") && server.hasArg("name")) {
    nameList.edit(server.arg("id").toInt(), server.arg("name"));
    server.send( 200, "text/json", "true");
  }else server.send( 200, "text/json", "false");
}

void addClient(){
  if(server.hasArg("mac") && server.hasArg("name")){
    String macStr = server.arg("mac");
    macStr.replace(":","");
    Serial.println("add "+macStr+" - "+server.arg("name"));
    if(macStr.length() < 12 || macStr.length() > 12) server.send( 200, "text/json", "false");
    else{
      Mac _newClient;
      for(int i=0;i<6;i++){
        const char* val = macStr.substring(i*2,i*2+2).c_str();
        uint8_t valByte = strtoul(val, NULL, 16);
        Serial.print(valByte,HEX);
        Serial.print(":");
        _newClient.setAt(valByte,i);
      }
      Serial.println();
      nameList.add(_newClient,server.arg("name"));
      server.send( 200, "text/json", "true");
    }
  }
}

//==========Attack==========
void sendAttackInfo() {
  attack.sendResults();
}

void startAttack() {
  if (server.hasArg("num")) {
    int _attackNum = server.arg("num").toInt();
    if (apScan.getFirstTarget() > -1 || _attackNum == 1 || _attackNum == 2) {
      attack.start(server.arg("num").toInt());
      server.send ( 200, "text/json", "true");
    } else server.send( 200, "text/json", "false");
  }
}

void addSSID() {
  if(server.hasArg("ssid") && server.hasArg("num")){
    int num = server.arg("num").toInt();
    if(num > 0){
      ssidList.addClone(server.arg("ssid"),num);
    }else{
      ssidList.add(server.arg("ssid"));
    }
    attack.ssidChange = true;
    server.send( 200, "text/json", "true");
  }else server.send( 200, "text/json", "false");
}

void deleteSSID() {
  ssidList.remove(server.arg("num").toInt());
  attack.ssidChange = true;
  server.send( 200, "text/json", "true");
}

void randomSSID() {
  ssidList._random();
  attack.ssidChange = true;
  server.send( 200, "text/json", "true");
}

void clearSSID() {
  ssidList.clear();
  attack.ssidChange = true;
  server.send( 200, "text/json", "true");
}

void resetSSID() {
  ssidList.load();
  attack.ssidChange = true;
  server.send( 200, "text/json", "true");
}

void saveSSID() {
  ssidList.save();
  server.send( 200, "text/json", "true");
}

void restartESP() {
  server.send( 200, "text/json", "true");
  ESP.reset();
}

void enableRandom(){
  attack.changeRandom(server.arg("interval").toInt());
  server.send( 200, "text/json", "true");
}

//==========Settings==========
void getSettings() {
  settings.send();
}

void saveSettings() {
  if (server.hasArg("ssid")) settings.ssid = server.arg("ssid");
  if (server.hasArg("ssidHidden")) {
    if (server.arg("ssidHidden") == "false") settings.ssidHidden = false;
    else settings.ssidHidden = true;
  }
  if (server.hasArg("password")) settings.password = server.arg("password");
  if (server.hasArg("apChannel")) {
    if (server.arg("apChannel").toInt() >= 1 && server.arg("apChannel").toInt() <= 14) {
      settings.apChannel = server.arg("apChannel").toInt();
    }
  }
  if (server.hasArg("ssidEnc")) {
    if (server.arg("ssidEnc") == "false") settings.attackEncrypted = false;
    else settings.attackEncrypted = true;
  }
  if (server.hasArg("scanTime")) settings.clientScanTime = server.arg("scanTime").toInt();
  if (server.hasArg("timeout")) settings.attackTimeout = server.arg("timeout").toInt();
  if (server.hasArg("deauthReason")) settings.deauthReason = server.arg("deauthReason").toInt();
  if (server.hasArg("packetRate")) settings.attackPacketRate = server.arg("packetRate").toInt();
  if (server.hasArg("apScanHidden")) {
    if (server.arg("apScanHidden") == "false") settings.apScanHidden = false;
    else settings.apScanHidden = true;
  }
  if (server.hasArg("beaconInterval")) {
    if (server.arg("beaconInterval") == "false") settings.beaconInterval = false;
    else settings.beaconInterval = true;
  }
  if (server.hasArg("useLed")) {
    if (server.arg("useLed") == "false") settings.useLed = false;
    else settings.useLed = true;
    attack.refreshLed();
  }
  if (server.hasArg("channelHop")) {
    if (server.arg("channelHop") == "false") settings.channelHop = false;
    else settings.channelHop = true;
  }
  if (server.hasArg("multiAPs")) {
    if (server.arg("multiAPs") == "false") settings.multiAPs = false;
    else settings.multiAPs = true;
  }
  if (server.hasArg("multiAttacks")) {
    if (server.arg("multiAttacks") == "false") settings.multiAttacks = false;
    else settings.multiAttacks = true;
  }
  
  if (server.hasArg("ledPin")) settings.ledPin = server.arg("ledPin").toInt();
  if(server.hasArg("macInterval")) settings.macInterval = server.arg("macInterval").toInt();

  if (server.hasArg("darkMode")) {
    if (server.arg("darkMode") == "false") settings.darkMode = false;
    else settings.darkMode = true;
  }
  
  if (server.hasArg("rebootButton")) {
    if (server.arg("rebootButton") == "false") settings.rebootButton = false;
    else settings.rebootButton = true;
  }
  
  settings.save();
  server.send( 200, "text/json", "true" );
}

void resetSettings() {
  settings.reset();
  server.send( 200, "text/json", "true" );
}

void setup() {
    
  Serial.begin(115200);

  attackMode = "START";

  EEPROM.begin(4096);
  SPIFFS.begin();
  
  settings.load();
  if (debug) settings.info();
  nameList.load();
  ssidList.load();

  startWifi();
  attack.stopAll();
  attack.generate();

  /* ========== Web Server ========== */

  /* HTML */
  server.onNotFound(load404);

  server.on("/", loadIndexHTML);
  server.on("/index.html", loadIndexHTML);
  server.on("/scan.html", loadAPScanHTML);
  server.on("/users.html", loadStationsHTML);
  server.on("/attack.html", loadAttackHTML);
  server.on("/settings.html", loadSettingsHTML);
  server.on("/info.html", loadInfoHTML);

  /* JS */
  server.on("/js/scan.js", loadAPScanJS);
  server.on("/js/users.js", loadStationsJS);
  server.on("/js/attack.js", loadAttackJS);
  server.on("/js/settings.js", loadSettingsJS);
  server.on("/js/functions.js", loadFunctionsJS);

  /* CSS */
  server.on ("/main.css", loadStyle);
  if(settings.darkMode) server.on ("/dark.css", loadDarkMode);

  /* JSON */
  server.on("/APScanResults.json", sendAPResults);
  server.on("/APScan.json", startAPScan);
  server.on("/APSelect.json", selectAP);
  server.on("/ClientScan.json", startClientScan);
  server.on("/ClientScanResults.json", sendClientResults);
  server.on("/ClientScanTime.json", sendClientScanTime);
  server.on("/clientSelect.json", selectClient);
  server.on("/setName.json", setClientName);
  server.on("/addClientFromList.json", addClientFromList);
  server.on("/attackInfo.json", sendAttackInfo);
  server.on("/attackStart.json", startAttack);
  server.on("/settings.json", getSettings);
  server.on("/settingsSave.json", saveSettings);
  server.on("/settingsReset.json", resetSettings);
  server.on("/deleteName.json", deleteName);
  server.on("/clearNameList.json", clearNameList);
  server.on("/editNameList.json", editClientName);
  server.on("/addSSID.json", addSSID);
  server.on("/deleteSSID.json", deleteSSID);
  server.on("/randomSSID.json", randomSSID);
  server.on("/clearSSID.json", clearSSID);
  server.on("/resetSSID.json", resetSSID);
  server.on("/saveSSID.json", saveSSID);
  server.on("/restartESP.json", restartESP);
  server.on("/addClient.json",addClient);
  server.on("/enableRandom.json",enableRandom);

  server.begin();

  pinMode(settings.ledPin, OUTPUT);
  digitalWrite(settings.ledPin, HIGH);

  if(debug){
    Serial.println("\nStarting...\n");
  }
  
}

void loop() {
  
  if (clientScan.sniffing) {
    if (clientScan.stop()) startWifi();
  } else {
    server.handleClient();
    attack.run();
  }

  if(Serial.available()){
    String input = Serial.readString();
    if(input == "reset" || input == "reset\n" || input == "reset\r" || input == "reset\r\n"){
      settings.reset();
    }
  }
}
