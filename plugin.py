"""
Electrolux AEG Wellbeing
Author: Joerek van Gaalen
"""
"""
<plugin key="wellbeing" name="Electrolux AEG Wellbeing" version="0.5" author="Joerek van Gaalen">
    <description>
        <h2>Electrolux AEG Wellbeing Plugin</h2><br/>
        <h3>Features</h3>
        <ul style="list-style-type:square">
            <li>Control your Electrolux AEG Wellbeing devices</li>
            <li>Monitor air quality, temperature, and humidity</li>
        </ul>
        <h3>Devices</h3>
        <ul style="list-style-type:square">
            <li>Air Purifiers</li>
        </ul>
        <h3>Configuration</h3>
        <ul style="list-style-type:square">
            <li>Enter your Electrolux AEG account credentials</li>
            <li>Set the desired update interval (minimum recommended: 18 seconds)</li>
        </ul>
    </description>
    <params>
        <param field="Username" label="Username" width="200px" required="true"/>
        <param field="Password" label="Password" width="200px" required="true" password="true"/>
        <param field="Mode1" label="Reading Interval (sec)" width="40px" required="true" default="60">
            <description>How often to fetch data from the API (in seconds). Warning: Setting this below 18 seconds may result in rate limit errors!</description>
        </param>
    </params>
</plugin>
"""

import Domoticz
import requests
import re
from datetime import datetime, timedelta
from enum import Enum
import time

TIMEOUT = 10
RETRIES = 3

HUMIDITY_NORMAL = 0
HUMIDITY_COMFORTABLE = 1
HUMIDITY_DRY = 2
HUMIDITY_WET = 3

class Mode(str, Enum):
    OFF = "PowerOff"
    AUTO = "Auto"
    MANUAL = "Manual"
    UNDEFINED = "Undefined"

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

class ElectroluxAuth:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.access_token = None
        self.refresh_token = None
        self.api_key = None
        self.token_expires = None

    def authenticate(self):
        try:

            # Step 1: Get CSRF token
            Domoticz.Debug("Step 1: Getting CSRF token...")
            login_url = "https://account.electrolux.one/ui/edp/login?client_id=HeiOpenApi&redirect_uri=https://developer.electrolux.one/loggedin"
            response = self.session.get(login_url)
            csrf_token = re.search('<meta name="x-csrf-token" content="(.*?)"/>', response.text).group(1)

            # Step 2: First authorization
            Domoticz.Debug("Step 2: Performing first authorization...")
            auth_url = "https://api.account.electrolux.one/api/v1/authorize"
            auth_data = {
                "email": self.username,
                "password": self.password,
                "redirectUri": "https://developer.electrolux.one/loggedin",
                "clientId": "HeiOpenApi",
                "state": None
            }
            headers = {"x-csrf-token": csrf_token}
            response = self.session.post(auth_url, json=auth_data, headers=headers)
            code = re.search(r'\?code=(.*?)&', response.text).group(1)
            Domoticz.Debug(f"Authorization code obtained: {code[:10]}...")  # Log only first 10 characters for security

            # Step 3: Get first token
            Domoticz.Debug("Step 3: Getting first token...")
            token_url = "https://api.developer.electrolux.one/api/v1/token"
            token_data = {
                "code": code,
                "redirectUri": "https://developer.electrolux.one/loggedin"
            }
            response = self.session.post(token_url, json=token_data)
            Domoticz.Debug("First token obtained successfully.")

            # Step 4: Second authorization
            Domoticz.Debug("Step 4: Performing second authorization...")
            auth_data["redirectUri"] = "https://developer.electrolux.one/generateToken"
            response = self.session.post(auth_url, json=auth_data, headers=headers)
            code = re.search(r'\?code=(.*?)&', response.text).group(1)
            Domoticz.Debug(f"Second authorization code obtained: {code[:10]}...")  # Log only first 10 characters for security

            # Step 5: Generate final tokens
            Domoticz.Debug("Step 5: Generating final tokens...")
            gen_token_url = "https://api.developer.electrolux.one/api/v1/generate-token"
            gen_token_data = {
                "code": code,
                "redirectUri": "https://developer.electrolux.one/generateToken"
            }
            response = self.session.post(gen_token_url, json=gen_token_data)
            tokens = response.json()
            self.access_token = tokens['accessToken']
            self.refresh_token = tokens['refreshToken']

            # Set token expiration time
            expires_in = tokens.get('expiresIn', 3600)  # Default to 1 hour if not provided
            self.token_expires = datetime.now() + timedelta(seconds=expires_in)
            Domoticz.Debug(f"Token will expire at {self.token_expires}")

            Domoticz.Debug("Final tokens generated successfully.")

            # Step 6: Get or create API key
            Domoticz.Debug("Step 6: Getting or creating API key...")
            new_key_created = self.get_or_create_api_key()

            if new_key_created:
                Domoticz.Log("New API key created. Reauthenticating...")
                return self.authenticate()

            Domoticz.Log("Authentication process completed successfully.")
            return True
        except Exception as e:
            Domoticz.Error(f"Authentication failed: {str(e)}")
            return False

    def get_or_create_api_key(self):
        api_keys_url = "https://api.developer.electrolux.one/api/v1/api-keys"
        headers = {"Authorization": f"Bearer {self.access_token}"}

        Domoticz.Debug("Fetching existing API keys...")
        response = self.session.get(api_keys_url, headers=headers)
        api_keys = response.json()

        enabled_key = next((key for key in api_keys if key['status'] == 'ENABLED'), None)

        if enabled_key:
            self.api_key = enabled_key['apiKey']
            Domoticz.Debug(f"Using existing API key: {self.api_key[:10]}...")  # Log only first 10 characters for security
        else:
            Domoticz.Log("No enabled API key found. Creating a new one...")
            create_key_data = {"name": "domoticz"}
            response = self.session.post(api_keys_url, json=create_key_data, headers=headers)
            new_key = response.json()
            self.api_key = new_key['apiKey']
            Domoticz.Debug(f"New API key created: {self.api_key[:10]}...")  # Log only first 10 characters for security

    def refresh_access_token(self):
        Domoticz.Debug("Refreshing access token...")
        refresh_url = "https://api.developer.electrolux.one/api/v1/token/refresh"
        refresh_data = {
            "refreshToken": self.refresh_token
        }
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        try:
            response = requests.post(refresh_url, json=refresh_data, headers=headers)
            tokens = response.json()
            self.access_token = tokens['accessToken']
            self.refresh_token = tokens['refreshToken']

            # Update token expiration time
            expires_in = tokens.get('expiresIn', 3600)  # Default to 1 hour if not provided
            self.token_expires = datetime.now() + timedelta(seconds=expires_in)
            Domoticz.Debug(f"Token refreshed. New expiration time: {self.token_expires}")

            return True
        except Exception as e:
            Domoticz.Error(f"Failed to refresh token: {str(e)}")
            return False

class BasePlugin:
    def __init__(self):
        self._username = None
        self._password = None
        self.auth = None
        self.token_expires = datetime.now()
        self.appliances = {}  # Store appliance IDs and their capabilities

    def onStart(self):
        Domoticz.Log("Wellbeing plugin starting...")
        self._username = Parameters["Username"]
        self._password = Parameters["Password"]

        Domoticz.Log("Initializing ElectroluxAuth...")
        self.auth = ElectroluxAuth(self._username, self._password)
        if self.auth.authenticate():
            Domoticz.Debug("Authentication successful. Fetching appliance information...")
            self.fetch_appliances()
            self.fetch_appliance_capabilities()
            self.get_data()
        else:
            Domoticz.Error("Authentication failed. Please check your credentials and try again.")

        if Parameters["Mode1"]:
            interval = int(Parameters["Mode1"])
            Domoticz.Log(f"Setting heartbeat interval to {interval} seconds.")
            Domoticz.Heartbeat(interval)
        else:
            Domoticz.Log("No heartbeat interval specified. Using default of 60 seconds.")
            Domoticz.Heartbeat(60)

    def fetch_appliances(self):
        Domoticz.Debug("Fetching appliances...")
        headers = self._get_headers()
        url = "https://api.developer.electrolux.one/api/v1/appliances"
        response = self.api_wrapper("get", url, headers=headers)

        for appliance in response:
            if 'applianceId' in appliance:
                self.appliances[appliance['applianceId']] = {'capabilities': None}
                Domoticz.Debug(f"Found appliance: {appliance['applianceId']}")

    def fetch_appliance_capabilities(self):
        for applianceId in self.appliances:
            Domoticz.Debug(f"Fetching capabilities for appliance {applianceId}...")
            headers = self._get_headers()
            url = f"https://api.developer.electrolux.one/api/v1/appliances/{applianceId}/info"
            response = self.api_wrapper("get", url, headers=headers)

            if response:
                self.appliances[applianceId]['capabilities'] = response.get('capabilities', {})
                self.appliances[applianceId]['info'] = response.get('applianceInfo', {})
                Domoticz.Debug(f"Capabilities fetched for appliance {applianceId}")
            else:
                Domoticz.Error(f"Failed to fetch capabilities for appliance {applianceId}")

    def onHeartbeat(self):
        if datetime.now() >= self.auth.token_expires:
            Domoticz.Debug("Access token expired. Initiating refresh...")
            if self.auth.refresh_access_token():
                Domoticz.Debug("Access token refreshed successfully. Updating data...")
            else:
                Domoticz.Error("Failed to refresh access token. Skipping data update.")
                return

        self.get_data()

    def get_data(self):
        if self.auth.access_token is None:
            Domoticz.Error("No valid access token. Unable to fetch data.")
            return

        for applianceId in self.appliances:
            self.update_appliance_state(applianceId)

    def update_appliance_state(self, applianceId):
        Domoticz.Debug(f"Updating state for appliance {applianceId}...")
        headers = self._get_headers()
        url = f"https://api.developer.electrolux.one/api/v1/appliances/{applianceId}/state"
        response = self.api_wrapper("get", url, headers=headers)

        if not response or 'properties' not in response or 'reported' not in response['properties']:
            Domoticz.Error(f"Invalid data structure for appliance {applianceId}")
            return

        reported_data = response['properties']['reported']
        capabilities = self.appliances[applianceId]['capabilities']
        appliance_info = self.appliances[applianceId]['info']

        # Determine max fan speed level and CO2 type
        max_fanspeed = capabilities.get('Fanspeed', {}).get('max', 5)
        co2_type = "CO2" if appliance_info.get('model') == 'AX9' else "ECO2"

        # Update devices
        updateDevice(applianceId, "State", str(response.get('connectionState', 'Unknown')))
        updateDevice(applianceId, "Workmode", reported_data.get('Workmode', 'Unknown'))
        updateDevice(applianceId, "Fanspeed", reported_data.get('Fanspeed', 0), max_fanspeed)
        updateDevice(applianceId, "Ionizer", str(reported_data.get('Ionizer', False)))
        updateDevice(applianceId, "PM1", str(reported_data.get('PM1', 0)))
        updateDevice(applianceId, "PM2_5", str(reported_data.get('PM2_5', 0)))
        updateDevice(applianceId, "PM10", str(reported_data.get('PM10', 0)))
        updateDevice(applianceId, "Temp", str(reported_data.get('Temp', 0)))
        updateDevice(applianceId, "Humidity", reported_data.get('Humidity', 0), round(reported_data.get('Temp', 0)))
        updateDevice(applianceId, co2_type, str(reported_data.get(co2_type, 0)))
        updateDevice(applianceId, "TVOC", str(reported_data.get('TVOC', 0)))

    def _get_headers(self):
        return {
            "Authorization": f"Bearer {self.auth.access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-api-key": self.auth.api_key
        }

    def api_wrapper(self, method: str, url: str, data: dict = {}, headers: dict = {}) -> dict:
        Domoticz.Debug(f"API request: {method.upper()} {url}")
        try:
            if method == "get":
                response = requests.get(url, headers=headers, timeout=TIMEOUT)
            elif method == "put":
                response = requests.put(url, headers=headers, json=data, timeout=TIMEOUT)
            elif method == "post":
                response = requests.post(url, headers=headers, json=data, timeout=TIMEOUT)

            response.raise_for_status()
            Domoticz.Debug(f"API request successful. Status code: {response.status_code}")
            return response.json() if response.content else {}
        except requests.exceptions.Timeout:
            Domoticz.Error(f"Timeout error fetching information from {url}")
        except requests.exceptions.RequestException as e:
            Domoticz.Error(f"Error fetching information from {url}: {str(e)}")
        except Exception as e:
            Domoticz.Error(f"Unexpected error during API request: {str(e)}")
        return {}

    def onCommand(self, Unit, Command, Level, Color):
        Domoticz.Debug(f"Command received for Unit {Unit}: {Command} (Level: {Level}, Color: {Color})")
        if Devices[Unit].Options.get('type'):
            applianceId = Devices[Unit].DeviceID.split('_')[0]
            if Devices[Unit].Options['type'] == 'Ionizer':
                cmd = {"Ionizer": Command == "On"}
                self._send_command(applianceId, cmd)
            elif Devices[Unit].Options['type'] == 'Workmode':
                if Command == "Set Level":
                    cmd = {"Workmode": "Auto" if Level == 10 else "Manual" if Level == 20 else "PowerOff"}
                else:
                    cmd = {"Workmode": "PowerOff"}
                self._send_command(applianceId, cmd)
            elif Devices[Unit].Options['type'] == 'Fanspeed':
                workmode = self.get_workmode(applianceId)
                if workmode == 'Manual':
                    fanspeed = round(Level / 10)
                    cmd = {"Fanspeed": fanspeed}
                    self._send_command(applianceId, cmd)
                else:
                    Domoticz.Log(f"Cannot update fanspeed because workmode is not set to manual: {workmode}")

            # Update the appliance state after sending a command
            self.update_appliance_state(applianceId)

    def _send_command(self, applianceId: str, command: dict) -> bool:
        Domoticz.Debug(f"Sending command to appliance {applianceId}: {command}")
        headers = self._get_headers()
        url = f"https://api.developer.electrolux.one/api/v1/appliances/{applianceId}/command"

        try:
            response = requests.put(url, json=command, headers=headers, timeout=TIMEOUT)

            if 200 <= response.status_code < 300:
                Domoticz.Debug(f"Command sent successfully to appliance {applianceId}. Status code: {response.status_code}")
                return True
            else:
                Domoticz.Error(f"Failed to send command to appliance {applianceId}. Status code: {response.status_code}")
                return False

        except requests.exceptions.RequestException as e:
            Domoticz.Error(f"Error sending command to appliance {applianceId}: {str(e)}")
            return False

    def get_workmode(self, applianceId):
        for unit in Devices:
            if Devices[unit].DeviceID == f"{applianceId}_Workmode":
                # Map the numeric level to the corresponding workmode name
                level = int(Devices[unit].sValue)
                if level == 0:
                    return "PowerOff"
                elif level == 10:
                    return "Auto"
                elif level == 20:
                    return "Manual"
                else:
                    Domoticz.Error(f"Unknown workmode level: {level}")
                    return "Unknown"
        Domoticz.Error(f"Workmode device not found for appliance {applianceId}")
        return None

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