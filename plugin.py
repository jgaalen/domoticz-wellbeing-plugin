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

TIMEOUT = 10
RETRIES = 3
BASE_URL = "https://api.delta.electrolux.com/api"
TOKEN_URL = "https://electrolux-wellbeing-client.vercel.app/api/mu52m5PR9X"
LOGIN_URL = f"{BASE_URL}/Users/Login"
APPLIANCES_URL = f"{BASE_URL}/Domains/Appliances"
APPLIANCE_INFO_URL = f"{BASE_URL}/AppliancesInfo"
APPLIANCE_DATA_URL = f"{BASE_URL}/Appliances"

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
        return self.api_wrapper("get", TOKEN_URL)

    def _login(self, access_token: str) -> dict:
        credentials = {
            "Username": self._username,
            "Password": self._password
        }
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        return self.api_wrapper("post", LOGIN_URL, credentials, headers)

    def get_login(self) -> bool:
        if self._current_access_token is not None and self._token_expires > datetime.now():
            return True

        Domoticz.Debug("Current token is not set or expired")

        self._token = None
        self._current_access_token = None
        access_token = self._get_token()

        if 'accessToken' not in access_token:
            self._access_token = None
            self._current_access_token = None
            Domoticz.Debug("AccessToken 1 is missing")
            return False

        token = self._login(access_token['accessToken'])

        if 'accessToken' not in token:
            self._current_access_token = None
            Domoticz.Debug("AccessToken 2 is missing")
            return False

        self._token_expires = datetime.now() + timedelta(seconds=token['expiresIn'])
        self._current_access_token = token['accessToken']

        return True

    def _get_appliance_info(self, access_token: str, pnc_id: str) -> dict:
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        url = f"{APPLIANCE_INFO_URL}/{pnc_id}"
        return self.api_wrapper("get", url, headers=headers)

    def _get_appliance_data(self, access_token: str, pnc_id: str) -> dict:
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        return self.api_wrapper("get", f"{APPLIANCE_DATA_URL}/{pnc_id}", headers=headers)

    def _get_appliances(self, access_token: str) -> dict:
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        return self.api_wrapper("get", APPLIANCES_URL, headers=headers)

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

        if self._current_access_token is None:
            raise Exception("Unable to login")

        access_token = self._current_access_token
        appliances = self._get_appliances(access_token)
        Domoticz.Debug(f"Fetched data: {appliances}")

        for appliance in (appliance for appliance in appliances if 'pncId' in appliance):
            modelName = appliance['modelName']
            pncId = appliance['pncId']
            applianceName = appliance['applianceName']
            appliance_info = self._get_appliance_info(access_token, pncId)
            Domoticz.Debug(f"Fetched data: {appliance_info}")

            if appliance_info['device'] != 'AIR_PURIFIER':
                continue

            maxLevel = 5
            co2Type = "ECO2"
            if modelName == "PUREA9":
                maxLevel = 9
                co2Type = "CO2"

            appliance_data = self._get_appliance_data(access_token, pncId)
            Domoticz.Debug(f"{appliance_data.get('applianceData', {}).get('applianceName', 'N/A')}: {appliance_data}")

            data = appliance_data.get('twin', {}).get('properties', {}).get('reported', {})
            data['connectionState'] = appliance_data.get('twin', {}).get('connectionState')
            data['status'] = appliance_data.get('twin', {}).get('connectionState')

            updateDevice(pncId, "State", str(data['connectionState']))
            updateDevice(pncId, "Workmode", data['Workmode'])
            updateDevice(pncId, "Fanspeed", data['Fanspeed'], maxLevel)
            updateDevice(pncId, "Ionizer", str(data['Ionizer']))
            updateDevice(pncId, "PM1", str(data['PM1']))
            updateDevice(pncId, "PM2_5", str(data['PM2_5']))
            updateDevice(pncId, "PM10", str(data['PM10']))
            updateDevice(pncId, "Temp", str(data['Temp']))
            updateDevice(pncId, "Humidity", data['Humidity'], round(data['Temp']))
            updateDevice(pncId, co2Type, str(data[co2Type]))
            updateDevice(pncId, "TVOC", str(data['TVOC']))


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
        Domoticz.Heartbeat(int(Parameters["Mode1"]))

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