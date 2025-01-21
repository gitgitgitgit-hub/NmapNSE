-- Script Name: radius-service-detect.nse
-- Purpose: Detects if a RADIUS server is running on the target host.
-- Author: Your Name
-- License: Same as Nmap

-- Import necessary libraries
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

-- Define the description of the script
description = [[
Detects if a RADIUS server is running on the target host.
The script checks common RADIUS ports (UDP 1812 for authentication, UDP 1813 for accounting)
and attempts to verify the service by sending a RADIUS Access-Request packet.
]]

-- Define categories
categories = {"discovery", "safe"}

-- Define the script's arguments
portrule = shortport.port_or_service({1812, 1813}, "radius")

-- Function to build and send a RADIUS Access-Request packet
local function send_radius_probe(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000) -- 5-second timeout

  local radius_request = "\x01\x01\x00\x14" .. -- Code (1 for Access-Request), Identifier (1), Length (20 bytes)
                        "\x00\x00\x00\x00" .. -- Authenticator (16 bytes of zeros)
                        "\x01\x04test"       -- Attribute: User-Name (1), Length (4), Value ("test")

  local status, err = socket:sendto(host, port, radius_request)
  if not status then
    stdnse.print_debug(1, "Failed to send RADIUS request: %s", err)
    socket:close()
    return nil, err
  end

  local response, err = socket:receive()
  socket:close()

  if not response then
    stdnse.print_debug(1, "No response from RADIUS server: %s", err)
    return nil, err
  end

  return response
end

-- Main action function
action = function(host, port)
  local response, err = send_radius_probe(host.ip, port.number)

  if not response then
    return string.format("No response from potential RADIUS server on %s:%d", host.ip, port.number)
  end

  return string.format("Potential RADIUS server detected on %s:%d", host.ip, port.number)
end
