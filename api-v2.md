# VintageNetWizard API V2

## Overview
Version 2 of the VintageNetWizard API provides enhanced functionality with consistent response formats and detailed metadata.

## Base URL
All API endpoints are prefixed with `/api/v2`

## Common Response Format
All responses include timestamps and follow a consistent format:

Success Response:
    {
      "status": "success",
      "message": "Operation completed successfully",
      "timestamp": "2024-03-20T15:30:00Z",
      ...additional fields
    }

Error Response:
    {
      "error": "validation_error",
      "code": "ERROR_CODE",
      "message": "Human readable error message",
      "timestamp": "2024-03-20T15:30:00Z",
      "details": ["Optional array of specific error details"]
    }

## Endpoints

### Health Check
`GET /health`

Response:
    {
      "status": "ok",
      "version": "2.0.0",
      "mac_address": "00:11:22:33:44:55",
      "firmware_version": "1.2.3",
      "timestamp": "2024-03-20T15:30:00Z"
    }

### Scan Networks
`GET /networks/scan`

Response:
    {
      "networks": [
        {
          "ssid": "NetworkName",
          "signal_percent": 75,
          "frequency": 2437,
          "band": "wifi_2_4_ghz",
          "channel": 6,
          "flags": ["wpa2", "psk", "ccmp", "ess"]
        }
      ]
    }

### Get Configuration Status
`GET /configuration/status`

Response:
    {
      "status": "good",
      "timestamp": "2024-03-20T15:30:00Z",
      "details": "Network configured and connected"
    }

Status values:
- "good" - Network is configured and connected
- "bad" - Network is configured but not connected
- "not_configured" - No network configuration present

### Get Camera Status
`GET /cameras`

Response:
    {
      "cameras": [
        {
          "id": "cam1",
          "name": "Front Camera",
          "status": "online",
          "streamUrl": "rtsp://device-ip:8554/cam1"
        }
      ]
    }

Status values:
- "online" - Camera is connected and streaming
- "offline" - Camera is disconnected or not responding

### Initialize Cameras
`POST /cameras/initialize`

Response:
    {
      "status": "success",
      "message": "Cameras initialized successfully",
      "timestamp": "2024-03-20T15:30:00Z"
    }

### Get Door Status
`GET /door`

Response:
    {
      "status": "open",
      "lastChanged": "2024-03-20T15:30:00Z"
    }

Status values:
- "open" - Door is currently open
- "closed" - Door is currently closed

### Get Lock Status
`GET /lock`

Response:
    {
      "status": "locked",
      "lastChanged": "2024-03-20T15:30:00Z",
      "type": "retrofit",
      "isWorking": true
    }

Status values:
- "locked" - Lock is engaged
- "unlocked" - Lock is disengaged

### Control Lock
`POST /lock`

Request:
    {
      "desired_state": "locked"
    }

Response:
    {
      "status": "success",
      "message": "Lock state changed successfully",
      "current_state": "locked",
      "timestamp": "2024-03-20T15:30:00Z"
    }

### Update Lock Type
`PUT /lock-type`

Request:
    {
      "lockType": "retrofit"
    }

Response:
    {
      "status": "success",
      "message": "Lock type updated successfully",
      "current_type": "retrofit",
      "timestamp": "2024-03-20T15:30:00Z"
    }

### Get Board Configuration
`GET /config`

Response:
    {
      "lockType": "retrofit",
      "wifi": {
        "networks": [
          {
            "ssid": "MyNetwork",
            "password": "********"
          }
        ],
        "primary_network": "MyNetwork",
        "method": "dhcp",
        "static_config": {
          "address": "192.168.1.100",
          "netmask": "255.255.255.0",
          "gateway": "192.168.1.1",
          "name_servers": "8.8.8.8,8.8.4.4"
        }
      },
      "mobileNetwork": {
        "apn": "internet"
      },
      "hotspotOutput": "wlan0",
      "nama": {
        "enabled": true,
        "profile": 1,
        "temperature": "",
        "version": ""
      },
      "ntp": "pool.ntp.org",
      "status_wifi": {
        "status": "good",
        "timestamp": "2024-03-20T15:30:00Z",
        "details": "Network configured and connected"
      }
    }

### Update Board Configuration
`PUT /config`

Request:
    {
      "lockType": "retrofit",
      "wifi": {
        "networks": [
          {
            "ssid": "MyNetwork",
            "password": "mypassword",
            "key_mgmt": "wpa_psk"
          }
        ],
        "method": "static",
        "static_config": {
          "address": "192.168.1.100",
          "netmask": "255.255.255.0",
          "gateway": "192.168.1.1",
          "name_servers": "8.8.8.8,8.8.4.4"
        }
      },
      "mobileNetwork": {
        "apn": "internet"
      },
      "hotspotOutput": "wlan0",
      "nama": {
        "profile": 1
      },
      "ntp": "pool.ntp.org"
    }

Response:
    {
      "status": "success",
      "message": "Configuration updated successfully",
      "timestamp": "2024-03-20T15:30:00Z"
    }

### Complete Configuration
`PUT /complete`

Response:
    {
      "status": "success",
      "message": "Configuration completed and server stopping",
      "timestamp": "2024-03-20T15:30:00Z"
    }

## Data Types

### Lock Types
- `retrofit`: Retrofit lock mechanism
- `imbera`: Imbera native lock
- `southco`: Southco electronic lock
- `duenorth`: DueNorth lock

### Network Methods
- `dhcp`: Dynamic IP configuration
- `static`: Static IP configuration

### Camera Status
- `online`: Camera is connected and streaming
- `offline`: Camera is disconnected or not responding

### Lock States
- `locked`: Lock is engaged
- `unlocked`: Lock is disengaged

### Door States
- `open`: Door is currently open
- `closed`: Door is currently closed

### Hotspot Output
- `wlan0`: WiFi interface
- `wwan0`: Mobile network interface

## Error Codes

- `PASSWORD_REQUIRED`: A password is required for this network
- `INVALID_IP`: Invalid IP address format
- `INVALID_NAMESERVERS`: Invalid nameserver format
- `INVALID_APN`: Invalid APN format
- `INVALID_STATE`: Invalid lock state provided
- `MISSING_STATE`: Lock state not provided
- `INVALID_CONFIG`: Invalid configuration provided
- `MISSING_CONFIG`: Configuration not provided

### Network Security Types (key_mgmt)
- `none`: No security (open network)
- `wpa_psk`: WPA/WPA2 Personal with pre-shared key
- `wpa_eap`: WPA/WPA2 Enterprise with EAP authentication

For WPA Enterprise networks, additional fields are required:
    {
      "ssid": "EnterpriseNetwork",
      "password": "password",
      "key_mgmt": "wpa_eap",
      "user": "username"
    }