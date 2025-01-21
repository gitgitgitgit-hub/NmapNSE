-- Script Name: tacacs-service-detect.nse
-- Purpose: Detects if a TACACS+ server is running on the target host.
-- Author: Your Name
-- License: Same as Nmap

-- Import necessary libraries
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

-- Define the description of the script
description = [[
Detects if a TACACS+ server is running on the target host by checking the common port (TCP 49).
Sends a TACACS+ START packet to verify the service response.

This script is designed to confirm the presence of a TACACS+ service without attempting authentication.
]]

-- Define categories
categories = {"discovery", "safe"}

-- Define portrule to target TACACS+ servers
portrule = shortport.port_or_service(49, "tacacs")

-- Function to construct a TACACS+ START packet
local function create_tacacs_start_packet()
  -- TACACS+ header:
  -- 1 byte: version (major << 4 | minor)
  -- 1 byte: type (0x01 for authentication START)
  -- 1 byte: sequence (should start at 1)
  -- 1 byte: flags (set to 0 for this packet)
  -- 4 bytes: session ID (random value)
  -- 4 bytes: length of the packet body (set to 0 for START packet)

  local version = "\xc0" -- TACACS+ version 1.0
  local packet_type = "\x01" -- Authentication START
  local sequence = "\x01" -- Sequence number 1
  local flags = "\x00" -- No flags
  local session_id = stdnse.generate_random_bytes(4)
  local length = "\x00\x00\x00\x00" -- No body for this START packet

  return version .. packet_type .. sequence .. flags .. session_id .. length
end

-- Function to send the TACACS+ START packet and analyze the response
local function probe_tacacs_service(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000) -- 5-second timeout

  local packet = create_tacacs_start_packet()

  local status, err = socket:connect(host, port)
  if not status then
    return nil, string.format("Failed to connect to TACACS+ server: %s", err)
  end

  local sent, err = socket:send(packet)
  if not sent then
    socket:close()
    return nil, string.format("Failed to send TACACS+ START packet: %s", err)
  end

  local response, err = socket:receive_bytes(12) -- TACACS+ header size
  socket:close()

  if not response then
    return nil, string.format("No response from TACACS+ server: %s", err)
  end

  -- Check if the response has a valid TACACS+ header (e.g., matching session ID)
  local session_id = packet:sub(5, 8)
  if response:sub(5, 8) == session_id then
    return true
  else
    return false, "Unexpected response from TACACS+ server"
  end
end

-- Main action function
action = function(host, port)
  local success, err = probe_tacacs_service(host, port)

  if success then
    return "TACACS+ service detected on the target."
  elseif err then
    return string.format("Failed to detect TACACS+ service: %s", err)
  else
    return "No TACACS+ service detected."
  end
end
