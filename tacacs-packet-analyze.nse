-- Script Name: tacacs-packet-analyze.nse
-- Purpose: Analyzes TACACS+ packet structures to provide insights into authentication, authorization, and accounting processes.
-- Author: Your Name
-- License: Same as Nmap

-- Import necessary libraries
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

-- Define the description of the script
description = [[
Analyzes TACACS+ packet structures to provide insights into authentication, authorization, and accounting processes.
This includes interpretation of packet headers, body contents, and encryption status.
Useful for network forensic analysis and understanding TACACS+ communication patterns.
]]

-- Define categories
categories = {"discovery", "safe"}

-- Define portrule to target TACACS+ servers
portrule = shortport.port_or_service(49, "tacacs")

-- Function to parse a TACACS+ packet
local function parse_tacacs_packet(packet)
  if #packet < 12 then
    return "Packet too short to be a valid TACACS+ packet."
  end

  -- Parse header
  local version = string.byte(packet, 1)
  local major_version = bit.rshift(version, 4)
  local minor_version = bit.band(version, 0x0F)
  local packet_type = string.byte(packet, 2)
  local sequence = string.byte(packet, 3)
  local flags = string.byte(packet, 4)
  local session_id = string.unpack("!I4", packet:sub(5, 8))
  local length = string.unpack("!I4", packet:sub(9, 12))

  -- Check if packet length matches the header length
  if #packet ~= length + 12 then
    return "Packet length mismatch."
  end

  -- Extract body
  local body = packet:sub(13)

  -- Interpret packet type
  local packet_type_str = "Unknown"
  if packet_type == 1 then
    packet_type_str = "Authentication"
  elseif packet_type == 2 then
    packet_type_str = "Authorization"
  elseif packet_type == 3 then
    packet_type_str = "Accounting"
  end

  -- Interpret flags
  local flags_str = {}
  if bit.band(flags, 0x01) ~= 0 then
    table.insert(flags_str, "Unencrypted")
  else
    table.insert(flags_str, "Encrypted")
  end
  flags_str = table.concat(flags_str, ", ")

  -- Return parsed information
  return string.format(
    [[
    TACACS+ Packet Analysis:
    - Version: %d.%d
    - Type: %s (%d)
    - Sequence: %d
    - Flags: %s
    - Session ID: 0x%08X
    - Length: %d bytes
    - Body: %s
    ]],
    major_version, minor_version, packet_type_str, packet_type,
    sequence, flags_str, session_id, length, stdnse.tohex(body)
  )
end

-- Function to capture and analyze TACACS+ packets
local function capture_tacacs_packet(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000) -- 5-second timeout

  local status, err = socket:connect(host, port)
  if not status then
    return nil, string.format("Failed to connect to TACACS+ server: %s", err)
  end

  -- Send a basic probe to elicit a response
  local probe_packet = "\xc0\x01\x01\x00" .. stdnse.generate_random_bytes(8) .. "test-body"
  local sent, err = socket:send(probe_packet)
  if not sent then
    socket:close()
    return nil, string.format("Failed to send TACACS+ probe packet: %s", err)
  end

  -- Receive the response
  local response, err = socket:receive()
  socket:close()

  if not response then
    return nil, string.format("No response from TACACS+ server: %s", err)
  end

  -- Parse and analyze the response
  return parse_tacacs_packet(response)
end

-- Main action function
action = function(host, port)
  local result, err = capture_tacacs_packet(host, port)
  if result then
    return result
  else
    return string.format("Failed to analyze TACACS+ packets: %s", err)
  end
end
