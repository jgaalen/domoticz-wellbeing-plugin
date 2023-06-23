#!/usr/bin/env python
"""
Electrolux AEG Wellbeing
"""
"""
<plugin key="wellbeing" name="Electrolux AEG Wellbeing" version="0.1" author="Joerek van Gaalen">
    <params>
        <param field="Username" label="Username" width="200px" required="true"/>
        <param field="Password" label="Password" width="200px" required="true"/>
        <param field="Mode1" label="Reading Interval sec." width="40px" required="true" default="60" />
    </params>
</plugin>
"""

import Domoticz
import requests
from datetime import datetime, timedelta
from enum import Enum
import time
import urllib

TIMEOUT = 10
RETRIES = 3

CLIENT_ID = "ElxOneApp"
CLIENT_SECRET = "8UKrsKD7jH9zvTV7rz5HeCLkit67Mmj68FvRVTlYygwJYy4dW6KF2cVLPKeWzUQUd6KJMtTifFf4NkDnjI7ZLdfnwcPtTSNtYvbP7OzEkmQD9IjhMOf5e1zeAQYtt2yN"
X_API_KEY = "2AMqwEV5MqVhTKrRCyYfVF8gmKrd2rAmp7cUsfky"

BASE_URL = "https://api.ocp.electrolux.one"
AUTHORIZATION_URL = f"{BASE_URL}/one-account-authorization/api/v1"
AUTHENTICATION_URL = f"{BASE_URL}/one-account-authentication/api/v1"
API_URL = f"{BASE_URL}/appliance/api/v2"

HUMIDITY_NORMAL = 0
HUMIDITY_COMFORTABLE = 1
HUMIDITY_DRY = 2
HUMIDITY_WET = 3

def humidity2status_indoor(hlevel, temperature):
    if hlevel is None or temperature is None:
        return None
    if hlevel <= 30:
        return HUMIDITY_DRY
    if 35 <= hlevel <= 65 and 18 <= temperature <= 22:
        return HUMIDITY_COMFORTABLE
    if hlevel >= 70:
        return HUMIDITY_WET
    return HUMIDITY_NORMAL

class Mode(str, Enum):
    OFF = "PowerOff"
    AUTO = "Auto"
    MANUAL = "Manual"
    UNDEFINED = "Undefined"

class BasePlugin:

    def __init__(self):
        self._username = None
        self._password = None
        self._access_token = None
        self._token = None
        self._current_access_token = None
        self._token_expires = datetime.now()
        self.appliances = None

        return

    def _get_token(self) -> dict:
        json={"clientId": CLIENT_ID,
              "clientSecret": CLIENT_SECRET,
              "grantType": "client_credentials"}
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        return self.api_wrapper("post", f'{AUTHORIZATION_URL}/token', json, headers)

    def _login(self, access_token: str) -> dict:
        credentials = {
            "username": self._username,
            "password": self._password
        }
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-api-key": X_API_KEY
        }
        return self.api_wrapper("post", f'{AUTHENTICATION_URL}/authenticate', credentials, headers)

    def _get_token2(self, idToken: str, countryCode: str) -> dict:
        credentials = {
            "clientId": CLIENT_ID,
            "idToken": idToken,
            "grantType": "urn:ietf:params:oauth:grant-type:token-exchange"
        }
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Origin-Country-Code": countryCode
        }
        return self.api_wrapper("post", f'{AUTHORIZATION_URL}/token', credentials, headers)

    def get_login(self) -> bool:
        if self._current_access_token is not None and self._token_expires > datetime.now():
            return True

        Domoticz.Log("Current token is not set or expired")

        self._token = None
        self._current_access_token = None
        access_token = self._get_token()

        if 'accessToken' not in access_token:
            self._access_token = None
            self._current_access_token = None
            Domoticz.Error("AccessToken 1 is missing")
            return False

        userToken = self._login(access_token['accessToken'])

        if 'idToken' not in userToken:
            self._current_access_token = None
            Domoticz.Error("User login failed")
            return False

        token = self._get_token2(userToken['idToken'], userToken['countryCode'])

        if 'accessToken' not in token:
            self._current_access_token = None
            Domoticz.Error("AccessToken 2 is missing")
            return False

        self._token_expires = datetime.now() + timedelta(seconds=token['expiresIn'])
        self._current_access_token = token['accessToken']

        return True

    def _get_appliances(self, access_token: str) -> dict:
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-api-key": X_API_KEY
        }
        return self.api_wrapper("get", f'{API_URL}/appliances', headers=headers)

    def _send_command(self, access_token: str, pnc_id: str, command: dict) -> None:
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        self.api_wrapper("put", f"{APPLIANCE_DATA_URL}/{pnc_id}/Commands", data=command, headers=headers)

    def get_data(self):
        n = 0
        while not self.get_login() and n < RETRIES:
            Domoticz.Log(f"Re-trying login. Attempt {n + 1} / {RETRIES}")
            n += 1
            time.sleep(n)

        if self._current_access_token is None:
            Domoticz.Error("Unable to login")
            return

        access_token = self._current_access_token
        appliances = self._get_appliances(access_token)
        Domoticz.Debug(f"Fetched data: {appliances}")

        for appliance in (appliance for appliance in appliances if 'applianceId' in appliance):
            modelName = appliance['applianceData']['modelName']
            applianceId = appliance['applianceId']
            applianceName = appliance['applianceData']['applianceName']
            Domoticz.Debug(f'Found appliance {applianceName}')

            if 'PM10' not in appliance['properties']['reported']:
                continue

            maxLevel = 5
            co2Type = "ECO2"
            if modelName == "PUREA9":
                maxLevel = 9
                co2Type = "CO2"

            data = appliance.get('properties', {}).get('reported', {})
            data['connectionState'] = appliance.get('connectionState')
            data['status'] = appliance.get('connectionState')

            updateDevice(applianceId, "State", str(data['connectionState']))
            updateDevice(applianceId, "Workmode", data['Workmode'])
            updateDevice(applianceId, "Fanspeed", data['Fanspeed'], maxLevel)
            updateDevice(applianceId, "Ionizer", str(data['Ionizer']))
            updateDevice(applianceId, "PM1", str(data['PM1']))
            updateDevice(applianceId, "PM2_5", str(data['PM2_5']))
            updateDevice(applianceId, "PM10", str(data['PM10']))
            updateDevice(applianceId, "Temp", str(data['Temp']))
            updateDevice(applianceId, "Humidity", data['Humidity'], round(data['Temp']))
            updateDevice(applianceId, co2Type, str(data[co2Type]))
            updateDevice(applianceId, "TVOC", str(data['TVOC']))


    def api_wrapper(self, method: str, url: str, data: dict = {}, headers: dict = {}) -> dict:
        """Get information from the API."""
        try:
            if method == "get":
                response = requests.get(url, headers=headers, timeout=TIMEOUT)
                return response.json()

            elif method == "put":
                response = requests.put(url, headers=headers, json=data, timeout=TIMEOUT)
                return response.json()

            elif method == "patch":
                requests.patch(url, headers=headers, json=data, timeout=TIMEOUT)

            elif method == "post":
                response = requests.post(url, headers=headers, json=data, timeout=TIMEOUT)
                return response.json()

        except requests.exceptions.Timeout as exception:
            Domoticz.Error(
                "Timeout error fetching information from %s - %s",
                url,
                exception,
            )

        except requests.exceptions.RequestException as exception:
            Domoticz.Error(
                "Error fetching information from %s - %s",
                url,
                exception,
            )
        except Exception as exception:  # pylint: disable=broad-except
            Domoticz.Error("Something really wrong happened! - %s", exception)

    def onStart(self):
        Domoticz.Log("Wellbeing plugin start")
        self._username = Parameters["Username"]
        self._password = Parameters["Password"]

        self.get_data()
        if Parameters["Mode1"]:
            Domoticz.Heartbeat(int(Parameters["Mode1"]))
        else:
            Domoticz.Heartbeat(60)

    def onHeartbeat(self):
        self.get_data()

    def onCommand(self, Unit, Command, Level, Color):

        access_token = self._current_access_token

        if Devices[Unit].Options.get('type'):
            if Devices[Unit].Options['type'] == 'Ionizer':
                if Command == "Off":
                    cmd = {"Ionizer": False}
                else:
                    cmd = {"Ionizer": True}
                self._send_command(access_token, Devices[Unit].Options['pncId'], cmd)
                self.get_data()

            if Devices[Unit].Options['type'] == 'Workmode':
                if Command == "Set Level":
                    if Level == 10:
                        cmd = {"WorkMode": "Auto"}
                    elif Level == 20:
                        cmd = {"WorkMode": "Manual"}
                else:
                    cmd = {"WorkMode": "PowerOff"}
                self._send_command(access_token, Devices[Unit].Options['pncId'], cmd)
                self.get_data()

            if Devices[Unit].Options['type'] == 'Fanspeed':
                workmodeId = Devices[Unit].Options['pncId'] + "_Workmode"
                workmodeUnit = GetDomoDeviceInfo(workmodeId)
                if str(Devices[workmodeUnit].sValue) == '20': # Check if workmode = manual
                    fanspeed = round(Level / 10)
                    cmd = {"Fanspeed": fanspeed}
                    self._send_command(access_token, Devices[Unit].Options['pncId'], cmd)
                    self.get_data()
                else:
                    Domoticz.Log("Cannot update fanspeed because workmode is not set to manual")

global _plugin
_plugin = BasePlugin()

def onStart():
    global _plugin
    _plugin.onStart()

def onHeartbeat():
    global _plugin
    _plugin.onHeartbeat()

def onCommand(Unit, Command, Level, Color):
    global _plugin
    _plugin.onCommand(Unit, Command, Level, Color)

def FreeUnit() :
    FreeUnit = ""
    for x in range(1,256):
        if x not in Devices :
            FreeUnit=x
            return FreeUnit
    if FreeUnit == "" :
        FreeUnit=len(Devices)+1
    return FreeUnit

def GetDomoDeviceInfo(DID):
    for x in Devices:
        if Devices[x].DeviceID == str(DID):
            return x
    return False

def updateDevice(pncId, name, value, value2='5'):
    id = pncId + "_" + name
    unit = GetDomoDeviceInfo(id)
    if (unit == False):
        unit = FreeUnit()
        Domoticz.Log("Found new device: " + name + "(" + str(unit) + ") value: " + str(value))
        if (name == 'State'):
            Domoticz.Device(Name=name, Unit=unit, TypeName="Switch", Used=0, DeviceID=id).Create()
        if (name == 'Workmode'):
            lOption = {"Scenes": "|||", "LevelNames": "PowerOff|Auto|Manual" , "LevelOffHidden": "false", "SelectorStyle": "0", "pncId": pncId, "type": name}
            Domoticz.Device(Name=name, Unit=unit, Type=244, Subtype=62, Switchtype=18, Options=lOption, Used=0, DeviceID=id).Create()
        if (name == 'Fanspeed'):
            if (value2 == '9'):
                lOption = {"Scenes": "|||||||||", "LevelNames": "0|1|2|3|4|5|6|7|8|9" , "LevelOffHidden": "true", "SelectorStyle": "0", "pncId": pncId, "type": name}
            else:
                lOption = {"Scenes": "|||||", "LevelNames": "0|1|2|3|4|5" , "LevelOffHidden": "true", "SelectorStyle": "0", "pncId": pncId, "type": name}
            Domoticz.Device(Name=name, Unit=unit, Type=244, Subtype=62, Switchtype=18, Options=lOption, Image=7, Used=0, DeviceID=id).Create()
        if (name == 'Ionizer'):
            Domoticz.Device(Name=name, Unit=unit, TypeName="Switch", Used=0, Options={"pncId": pncId, "type": name},DeviceID=id).Create()
        if (name == 'PM1' or name == 'PM2_5' or name == 'PM10'):
            Domoticz.Device(Name=name, Unit=unit, TypeName="Custom", Subtype=31, Options={'Custom': '1;ug/m3'}, Used=0, DeviceID=id).Create()
        if (name == 'Temp'):
            Domoticz.Device(Name=name, Unit=unit, TypeName="Temperature", Used=0, DeviceID=id).Create()
        if (name == 'Humidity'):
            Domoticz.Device(Name=name, Unit=unit, TypeName="Humidity", Used=0, DeviceID=id).Create()
        if (name == 'CO2' or name == 'ECO2'):
            Domoticz.Device(Name=name, Unit=unit, TypeName="Custom", Subtype=31, Options={'Custom': '1;ppm'}, Used=0, DeviceID=id).Create()
        if (name == 'TVOC'):
            Domoticz.Device(Name=name, Unit=unit, TypeName="Custom", Subtype=31, Options={'Custom': '1;ppb'}, Used=0, DeviceID=id).Create()

    nv = 0
    if (name == 'State'):
        if (value == 'Connected'):
            nv = 1
            value = "On"
        else:
            value = "Off"
    if (name == 'Workmode'):
        if(value == 'PowerOff'):
            value = 0
        elif(value == 'Auto'):
            nv = 1
            value = '10'
        elif(value == 'Manual'):
            nv = 1
            value = '20'
    if (name == 'Fanspeed'):
        nv = 2
        value = value * 10
    if (name == 'Ionizer'):
        if (value == 'True'):
            nv = 1
            value = "On"
        else:
            value = "Off"
    if (name == 'Humidity'):
        nv = value
        value = str(humidity2status_indoor(value, value2))
    if (str(Devices[unit].sValue) != str(value) or Devices[unit].nValue != nv):
        Domoticz.Debug("Update - " + name + " to " + str(value) + " was " + str(Devices[unit].sValue))
        Devices[unit].Update(nValue=nv, sValue=str(value))