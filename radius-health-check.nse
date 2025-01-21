-- Script Name: radius-health-check.nse
-- Purpose: Checks the health and responsiveness of a RADIUS server.
-- Author: Your Name
-- License: Same as Nmap

-- Import necessary libraries
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

-- Define the description of the script
description = [[
Sends periodic authentication or accounting requests to a RADIUS server to assess its health and responsiveness.

This script checks for:
- Server responsiveness to Access-Request or Accounting-Request packets.
- Latency and potential packet loss statistics.

Useful for monitoring or ensuring the operational status of a RADIUS server in a network environment.
]]

-- Define categories
categories = {"discovery", "safe"}

-- Define the portrule for targeting RADIUS servers
portrule = shortport.port_or_service({1812, 1813}, "radius")

-- Function to send RADIUS Access-Request or Accounting-Request packets and measure response time
local function send_radius_probe(host, port, packet_type)
  local socket = nmap.new_socket()
  socket:set_timeout(5000) -- 5-second timeout

  -- Construct a RADIUS packet (Access-Request or Accounting-Request)
  local packet_code = packet_type == "accounting" and "\x04" or "\x01" -- Access-Request: 0x01, Accounting-Request: 0x04
  local packet = packet_code .. "\x0c\x00\x14" .. -- Code, Identifier, Length
                 "\x00\x00\x00\x00" ..          -- Authenticator (16 bytes of zeros)
                 "\x01\x08testuser"              -- User-Name attribute

  local start_time = nmap.clock_ms()
  local status, err = socket:sendto(host, port, packet)
  if not status then
    stdnse.print_debug(1, "Failed to send RADIUS %s request: %s", packet_type, err)
    socket:close()
    return nil, err
  end

  local response, err = socket:receive()
  local latency = nmap.clock_ms() - start_time
  socket:close()

  if not response then
    return nil, string.format("No response from server for %s request: %s", packet_type, err), latency
  end

  return true, nil, latency
end

-- Main action function
action = function(host, port)
  local results = {}
  local packet_types = {"authentication", "accounting"}

  for _, packet_type in ipairs(packet_types) do
    stdnse.print_debug(1, "Sending %s probe to RADIUS server", packet_type)

    local success, err, latency = send_radius_probe(host, port, packet_type)
    if success then
      table.insert(results, string.format("RADIUS %s probe successful. Latency: %d ms", packet_type, latency))
    elseif err then
      table.insert(results, string.format("RADIUS %s probe failed. Error: %s", packet_type, err))
    end
  end

  return table.concat(results, "\n")
end
