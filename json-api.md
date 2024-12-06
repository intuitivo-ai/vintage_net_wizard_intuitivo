# JSON API

## Endpoints

* [Get Status](#get-status)
* [Get Access Points](#get-access-points)
* [Configure SSID Priority](#configure-ssid-priority)
* [Configure an SSID](#configure-an-ssid)
* [Delete an SSID configuration](#delete-an-ssid-configuration)
* [Get Configurations](#get-configurations)
* [Get Configuration Status](#get-configuration-status)
* [Apply](#apply)
* [Complete the Configuration Process](#complete-the-configuration-process)
* [Get lock type](#get-lock-type)
* [Get Version](#get-version)
* [Get Temperature](#get-temperature)
* [Get Profile State](#get-profile-state)
* [Get NAMA State](#get-nama-state)
* [Get APN Configuration](#get-apn-configuration)
* [Get NTP Configuration](#get-ntp-configuration)
* [Get Imbera State](#get-imbera-state)
* [Get Lock Status](#get-lock-status)
* [Get Door Status](#get-door-status)
* [Change NAMA Mode](#change-nama-mode)
* [Clear Operations](#clear-operations)
* [Change Lock Type](#change-lock-type)
* [Change Internet Sharing](#change-internet-sharing)

### Get status

This request returns a 200.

Path: `/api/v1/status`

Method: `GET`

Response: Array AccessPoint

Response Code: `200`

#### Response

```
```

### Get access points

This request returns a list of known access points and their properties. Hidden
access points are not returned.

Path: `/api/v1/access_points`

Method: `GET`

Response: Array AccessPoint

Response Code: `200`

#### Response

```json
[
  {
    "ssid": "Free WiFi!",
    "frequency": 2437,
    "band": "wifi_2_4_ghz",
    "channel": 6,
    "flags": ["ess"],
    "signal_percent": 100,

  },
  {
    "ssid": "Imperial Star Destroyer",
    "frequency": 5755,
    "band": "wifi_5_ghz",
    "channel": 151,
    "flags": ["wpa2_psk_ccmp", "ess"],
    "signal_percent": 75
  }
]
```

### Configure SSID priority

This endpoint takes a list of SSIDs. Each SSID is tried in order until a
successful connection is made. It is not required to list all configured SSIDs.

Path: `/api/v1/ssids`

Method: `PUT`

Request: `Array String`

Response: Empty

Response Code: `204`

### Example

#### Request

```json
[
  "Millennium Falcon",
  "Death Star",
  "TIE-fighter-01",
  "lukes-lightsaber"
]
```

### Configure an SSID

Set connection parameters for an `SSID`.

Path: `/api/v1/<ssid>/configuration`

Method: `PUT`

Request: `WiFiConfiguration`

Response: Empty

Response Code: `204`

### Example

#### Request

`/api/v1/millennium-falcon/configuration`

```json
{
  "key_mgmt": "wpa_psk",
  "password": "Chewbacca"
}
```

#### Errors

If the configuration is passed is invalid the endpoint will return with a `400`
status with one of the below errors:

```json
{
  "error": "password_required",
  "message": "A password is required for wpa_psk access points."
}
```

If the configuration is provide a `key_mgmt` field and there is no provided
password.

```json
{
 "error": "password_too_short",
 "message": "The minimum length for a password is 8."
}
```

If the password is less than `8` characters long as outlined in the
IEEE Std 802.11i-2004 specification.

```json
{
  "error": "invalid_characters",
  "message": "The password provided has invalid characters."
}
```

If the password contains characters that are not valid ASCII.

```json
{
  "error": "password_too_long",
  "message": "The maximum length for a password is 63."
}
```

If the password is greater than `63` characters long as outlined in the
IEEE Std 802.11i-2004 specification.

### Delete an SSID configuration

Delete the configuration attached to an SSID

Path: `/api/v1/<ssid>/configuration`

Method: `DELETE`

Request: Empty

Response: Empty

Response Code: `200`

### Get configurations

Get the current known configurations.

Path: `/api/v1/configurations`

Method: `GET`

Request: Empty

Response: `Array WiFiConfiguration` - Passwords are filtered

Response Code: 200

#### Request

```json
[
  {
    "ssid": "Millennium Falcon",
    "key_mgmt": "wpa_psk"
  }
]
```

### Get configuration status

Get the current status of the configuration. This is useful after using
the `/api/v1/apply` endpoint to figure out if the configurations that
were provided work or not.

Path: `/api/v1/configuration/status`

Method: `GET`

Request: Empty

Response: `ConfigurationStatus`

Response Code: 200

### Apply

A POST to this endpoint applies the configuration and attempts to connect to the
configured WiFi networks. This will return back to AP mode and you can use the
`/api/v1/configuration/status` endpoint to get whether or not the configuration
worked or not.

Path: `/api/v1/apply`

Method: `POST`

Request: Empty

Response: Empty

Response Code: `202`

### Complete the configuration process

Finalize the configuration process. This will apply the configuration and
not return to AP mode.

Path: `/api/v1/complete`

Method: `GET`

Request: Empty

Response: Empty

Response Code: `202`

### Get lock type

Get the current lock type configuration.

Path: `/api/v1/lock_type`

Method: `GET`

Request: Empty

Response: `LockType`

Response Code: `200`

#### Response Example

```json
{
  "lock_type": "retrofit"
}
```

### Get Version

Get the current firmware version information.

Path: `/api/v1/get_version`

Method: `GET`

Request: Empty

Response: `Version`

Response Code: `200`

#### Response Example

```json
{
  "version": "1.2.3"
}
```

### Get Temperature

Get the current temperature reading from the system.

Path: `/api/v1/get_temp`

Method: `GET`

Request: Empty

Response: `Temperature`

Response Code: `200`

#### Response Example

```json
{
  "temp": 23.5
}
```

### Get Profile State

Get the current profile state of the system. The profile state indicates which operating mode/profile is currently active (e.g. 1 for standard mode, 2 for NAMA mode).

Path: `/api/v1/state_profile`

Method: `GET`

Request: Empty

Response: `ProfileState`

Response Code: `200`

#### Response Example

```json
{
  "state_profile": 1
}
```

### Get NAMA State

Get the current NAMA state of the system. This indicates whether NAMA mode is on, off, or in an unknown state.

Path: `/api/v1/state_nama`

Method: `GET`

Request: Empty

Response: `NAMAState`

Response Code: `200`

#### Response Example

```json
{
  "state_nama": "on"
}
```

### Get APN Configuration

Get the current APN (Access Point Name) configuration used for cellular connectivity.

Path: `/api/v1/get_apn`

Method: `GET`

Request: Empty

Response: `APNConfiguration`

Response Code: `200`

#### Response Example

```json
{
  "apn": "internet.carrier.com"
}
```

### Get NTP Configuration

Get the current NTP (Network Time Protocol) server configuration.

Path: `/api/v1/get_ntp`

Method: `GET`

Request: Empty

Response: `NTPConfiguration`

Response Code: `200`

#### Response Example

```json
{
  "ntp": "pool.ntp.org,time.google.com"
}
```

### Get Imbera State

Get the current state of the Imbera system. This indicates whether the system is in an "ok" or "error" state.

Path: `/api/v1/state_imbera`

Method: `GET`

Request: Empty

Response: `ImberaState`

Response Code: `200`

#### Response Example

```json
{
  "state_imbera": "ok"
}
```

### Get Lock Status

Get the current status of the lock system.

Path: `/api/v1/status_lock`

Method: `GET`

Request: Empty

Response: `LockStatus`

Response Code: `200`

#### Response Example

```json
{
  "lock": "closed"
}
```

### Get Door Status

Get the current status of the door.

Path: `/api/v1/status_door`

Method: `GET`

Request: Empty

Response: `DoorStatus`

Response Code: `200`

#### Response Example

```json
{
  "door": "closed"
}
```

### Change NAMA Mode

Change the NAMA mode activation state.

Path: `/api/v1/nama_change`

Method: `PUT`

Request: `NAMAChangeRequest`

Response: Empty

Response Code: `204`

#### Request Example

```json
{
  "value": true
}
```

### Clear Operations

Initialize transaction operations. This endpoint clears the current operation state.

Path: `/api/v1/clear_nama_operator`

Method: `PUT`

Request: Empty

Response: Empty

Response Code: `204`

#### Response Example

```json
```

### Change Lock Type

Change the type of lock system to use.

Path: `/api/v1/lock/change`

Method: `POST`

Request: `LockChangeRequest`

Response: Empty

Response Code: `200`

#### Request Example

```json
{
  "lock_select": "retrofit"
}
```

#### Errors

If no lock_select is provided, the endpoint will return with a `400` status:

```json
{
  "error": "lock_select_required",
  "message": "A lock_select value is required."
}
```

### Change Internet Sharing

Configure the internet sharing settings.

Path: `/api/v1/sharing/change`

Method: `POST`

Request: `InternetSharingRequest`

Response: Empty

Response Code: `200`

#### Errors

If no internet_select is provided, the endpoint will return with a `400` status:

```json
{
  "error": "interface_select_required",
  "message": "A interface_select value is required."
}
```

#### Request Example

```json
{
  "internet_select": "wifi"
}
```

## Types

### AccessPoint

```s
{
  "ssid": String,
  "signal_percent": 0..100,
  "frequency": Integer,
  "band": Band,
  "channel": Integer,
  "flags": Flags
}
```

### Band

This is the WiFi radio band that the access point is using.

```s
"wifi_2_4_ghz"
"wifi_5_ghz"
"unknown"
```

### Flags

Flags are reported by access points. They can be used to know whether a password
is required to join the network. Example flags are `"wpa2"`, `"psk"`, and
`"eap"`. Flags are documented in the [`vintage_net_wifi`
documentation](https://hexdocs.pm/vintage_net_wifi/VintageNetWiFi.AccessPoint.html)

### KeyManagement

Key management is an interpretation of the `Flags` that determines what
information that the user needs to provide to connect to the access point.  For
hidden access points where the `Flags` are unavailable, the user will need to
pick one of these.

```s
"none" - No security
"wpa_psk" - WPA or WPA2 with a pre-shared key
"wpa_eap" - WPA or WPA2 with a username and password
```

### WiFiConfiguration

This specifies how to connect to one WiFi access point. The `ssid` and
`key_mgmt` fields are required. Depending on the `key_mgmt`, `password` may be
needed.

```s
{
  "ssid": String,
  "key_mgmt": KeyManagement,
  "password": Optional String
}
```

### ConfigurationStatus

```s
not_configured - No configuration attempts have taken place
good - A configuration was applied and is working
bad - A configuration was applied and is not working
```

### LockType

This specifies the type of lock that is currently configured in the system.

```s
{
  "lock_type": String  // The type of lock, e.g. "retrofit", "nama", etc.
}
```

### Version

This specifies the current firmware version of the system.

```s
{
  "version": String  // The version string of the firmware
}
```

### Temperature

This specifies the current temperature reading from the system.

```s
{
  "temp": Number  // The temperature value, can be NaN if no reading is available
}
```

### ProfileState

This specifies the current operating profile of the system.

```s
{
  "state_profile": Number  // The profile number (1 = standard mode, 2 = NAMA mode)
}
```

### NAMAState

This specifies the current state of the NAMA system.

```s
{
  "state_nama": String  // The NAMA state ("on", "off", or "unknown")
}
```

### APNConfiguration

This specifies the APN configuration for cellular connectivity.

```s
{
  "apn": String  // The APN string, empty string if not configured
}
```

### NTPConfiguration

This specifies the NTP server configuration.

```s
{
  "ntp": String  // Comma-separated list of NTP servers, empty string if not configured
}
```

### ImberaState

This specifies the current state of the Imbera system.

```s
{
  "state_imbera": String  // The Imbera state ("ok" or "error")
}
```

### LockStatus

This specifies the current status of the lock.

```s
{
  "lock": String  // The lock status ("open" or "closed")
}
```

### DoorStatus

This specifies the current status of the door.

```s
{
  "door": String  // The door status ("open" or "closed")
}
```

### NAMAChangeRequest

This specifies whether to activate or deactivate NAMA mode.

```s
{
  "value": Boolean  // true to activate NAMA mode, false to deactivate
}
```

### LockChangeRequest

This specifies which type of lock system to use.

```s
{
  "lock_select": String  // The lock type to use (e.g. "retrofit", "nama", etc.)
}
```

### InternetSharingRequest

This specifies the internet sharing configuration.

```s
{
  "internet_select": String  // The internet sharing mode to use
}
```
