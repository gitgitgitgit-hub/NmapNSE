-- Script Name: radius-version.nse
-- Purpose: Probes the RADIUS server to determine the software version or type.
-- Author: Your Name
-- License: Same as Nmap

-- Import necessary libraries
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

-- Define the description of the script
description = [[
Probes the RADIUS server to determine the software version or type (e.g., FreeRADIUS, Cisco ACS).
This script might involve sending crafted packets with specific attributes to elicit version-specific responses.
Useful for vulnerability assessment based on known version-specific weaknesses.
]]

-- Define categories
categories = {"discovery", "safe"}

-- Define the script's arguments
portrule = shortport.port_or_service({1812, 1813}, "radius")

-- Function to build and send a RADIUS probe to identify version
local function send_radius_version_probe(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000) -- 5-second timeout

  -- Build a RADIUS packet with specific attributes for version probing
  local radius_request = "\x01\x02\x00\x14" .. -- Code (1 for Access-Request), Identifier (2), Length (20 bytes)
                        "\x00\x00\x00\x00" .. -- Authenticator (16 bytes of zeros)
                        "\x01\x04version"    -- Attribute: User-Name (1), Length (4), Value ("version")

  local status, err = socket:sendto(host, port, radius_request)
  if not status then
    stdnse.print_debug(1, "Failed to send RADIUS version probe: %s", err)
    socket:close()
    return nil, err
  end

  local response, err = socket:receive()
  socket:close()

  if not response then
    stdnse.print_debug(1, "No response from RADIUS server for version probe: %s", err)
    return nil, err
  end

  return response
end

-- Function to parse the RADIUS response and extract version information
local function parse_radius_version(response)
  -- Example parsing logic (to be adjusted based on known version response formats)
  if response:find("FreeRADIUS") then
    return "FreeRADIUS detected"
  elseif response:find("Cisco") then
    return "Cisco ACS detected"
  else
    return "Unknown RADIUS server type"
  end
end

-- Main action function
action = function(host, port)
  local response, err = send_radius_version_probe(host.ip, port.number)

  if not response then
    return string.format("No response from RADIUS server on %s:%d for version identification", host.ip, port.number)
  end

  local version_info = parse_radius_version(response)
  return string.format("RADIUS server on %s:%d identified: %s", host.ip, port.number, version_info)
end
