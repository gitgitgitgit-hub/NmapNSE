-- Script Name: tacacs-version.nse
-- Purpose: Identifies the TACACS+ server's version by probing with specific packets and analyzing responses.
-- Author: Your Name
-- License: Same as Nmap

-- Import necessary libraries
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

-- Define the description of the script
description = [[
Attempts to identify the TACACS+ server's version by sending specific TACACS+ packets and analyzing the responses.
The script may look for version strings or behaviors characteristic of known TACACS+ implementations.

This script is useful for vulnerability assessments or understanding the target server's software.
]]

-- Define categories
categories = {"discovery", "version", "safe"}

-- Define portrule to target TACACS+ servers
portrule = shortport.port_or_service(49, "tacacs")

-- Function to construct a TACACS+ packet for probing
local function create_tacacs_probe_packet()
  -- TACACS+ header:
  -- 1 byte: version (major << 4 | minor)
  -- 1 byte: type (0x01 for authentication START)
  -- 1 byte: sequence (should start at 1)
  -- 1 byte: flags (set to 0 for this packet)
  -- 4 bytes: session ID (random value)
  -- 4 bytes: length of the packet body (set to 0 for this probe)

  local version = "\xc0" -- TACACS+ version 1.0 (major 1, minor 0)
  local packet_type = "\x01" -- Authentication START
  local sequence = "\x01" -- Sequence number 1
  local flags = "\x00" -- No flags
  local session_id = stdnse.generate_random_bytes(4)
  local length = "\x00\x00\x00\x00" -- No body for this probe

  return version .. packet_type .. sequence .. flags .. session_id .. length
end

-- Function to send the TACACS+ probe packet and analyze the response for version information
local function probe_tacacs_version(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000) -- 5-second timeout

  local packet = create_tacacs_probe_packet()

  local status, err = socket:connect(host, port)
  if not status then
    return nil, string.format("Failed to connect to TACACS+ server: %s", err)
  end

  local sent, err = socket:send(packet)
  if not sent then
    socket:close()
    return nil, string.format("Failed to send TACACS+ probe packet: %s", err)
  end

  local response, err = socket:receive()
  socket:close()

  if not response then
    return nil, string.format("No response from TACACS+ server: %s", err)
  end

  -- Analyze the response for version-related information
  local version_info = {}

  -- Example: Check the response header for the version field (first byte)
  local version_byte = string.byte(response, 1)
  local major_version = math.floor(version_byte / 16)
  local minor_version = version_byte % 16

  table.insert(version_info, string.format("Detected TACACS+ version: %d.%d", major_version, minor_version))

  return table.concat(version_info, "\n")
end

-- Main action function
action = function(host, port)
  local result, err = probe_tacacs_version(host, port)

  if result then
    return result
  elseif err then
    return string.format("Error detecting TACACS+ version: %s", err)
  else
    return "No TACACS+ version information detected."
  end
end
