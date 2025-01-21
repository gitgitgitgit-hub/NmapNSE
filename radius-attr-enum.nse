-- Script Name: radius-attr-enum.nse
-- Purpose: Enumerates supported RADIUS attributes by the server.
-- Author: Your Name
-- License: Same as Nmap

-- Import necessary libraries
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

-- Define the description of the script
description = [[
Enumerates supported RADIUS attributes by the server through trial-and-error or known responses.
The script checks for the support of common attributes such as NAS-IP-Address, User-Name, and others.
Useful for understanding the server's configuration and capabilities for more targeted attacks or configurations.
]]

-- Define categories
categories = {"discovery", "safe"}

-- Define the script's arguments
portrule = shortport.port_or_service({1812}, "radius")

-- List of common RADIUS attributes for enumeration
local attributes = {
  {type = 1, name = "User-Name", value = "testuser"},
  {type = 4, name = "NAS-IP-Address", value = "192.168.1.1"},
  {type = 6, name = "Service-Type", value = "\x00\x02"}, -- Login
  {type = 31, name = "Calling-Station-Id", value = "00:11:22:33:44:55"},
  {type = 32, name = "NAS-Identifier", value = "TestNAS"},
}

-- Function to send a RADIUS Access-Request with a specific attribute
local function send_radius_request_with_attr(host, port, attr)
  local socket = nmap.new_socket()
  socket:set_timeout(5000) -- 5-second timeout

  -- Build RADIUS Access-Request packet with the given attribute
  local radius_request = "\x01\x04\x00" ..
                         string.char(20 + 2 + #attr.value) .. -- Code, Identifier, Length
                         "\x00\x00\x00\x00" .. -- Authenticator (16 bytes of zeros)
                         string.char(attr.type) ..
                         string.char(2 + #attr.value) ..
                         attr.value

  local status, err = socket:sendto(host, port, radius_request)
  if not status then
    stdnse.print_debug(1, "Failed to send RADIUS request with attribute %s: %s", attr.name, err)
    socket:close()
    return nil, err
  end

  local response, err = socket:receive()
  socket:close()

  if not response then
    stdnse.print_debug(1, "No response for attribute %s: %s", attr.name, err)
    return nil, err
  end

  return response
end

-- Function to parse the RADIUS response for attribute support
local function parse_radius_response(attr, response)
  -- Example logic to determine if the attribute is supported
  if response:find(attr.name) or #response > 0 then
    return true
  end
  return false
end

-- Main action function
action = function(host, port)
  local results = {}

  for _, attr in ipairs(attributes) do
    stdnse.print_debug(1, "Checking support for attribute: %s", attr.name)

    local response, err = send_radius_request_with_attr(host.ip, port.number, attr)
    if response then
      if parse_radius_response(attr, response) then
        table.insert(results, string.format("Attribute %s (Type %d) is supported", attr.name, attr.type))
      else
        table.insert(results, string.format("Attribute %s (Type %d) is not supported", attr.name, attr.type))
      end
    else
      table.insert(results, string.format("Failed to check attribute %s (Type %d): %s", attr.name, attr.type, err or "Unknown error"))
    end
  end

  return table.concat(results, "\n")
end
