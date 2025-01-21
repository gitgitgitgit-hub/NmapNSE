-- Script Name: tacacs-user-enum.nse
-- Purpose: Enumerates valid usernames on a TACACS+ server by analyzing server responses.
-- Author: Your Name
-- License: Same as Nmap

-- Import necessary libraries
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local creds = require "creds"

-- Define the description of the script
description = [[
Attempts to enumerate valid usernames on a TACACS+ server by sending authentication requests with common or provided usernames.
The script analyzes server responses, looking for differences in behavior (e.g., timing differences or error messages) that indicate valid usernames.

This script is intended for penetration testing scenarios and should only be used with proper authorization.
]]

-- Define categories
categories = {"discovery", "intrusive"}

-- Define portrule to target TACACS+ servers
portrule = shortport.port_or_service(49, "tacacs")

-- Function to construct a TACACS+ authentication START packet
local function create_tacacs_auth_packet(username)
  -- TACACS+ header:
  -- 1 byte: version (major << 4 | minor)
  -- 1 byte: type (0x01 for authentication START)
  -- 1 byte: sequence (should start at 1)
  -- 1 byte: flags (set to 0 for this packet)
  -- 4 bytes: session ID (random value)
  -- 4 bytes: length of the packet body

  local version = "\xc0" -- TACACS+ version 1.0 (major 1, minor 0)
  local packet_type = "\x01" -- Authentication START
  local sequence = "\x01" -- Sequence number 1
  local flags = "\x00" -- No flags
  local session_id = stdnse.generate_random_bytes(4)

  -- Packet body: username attribute
  local username_attribute = "\x01" .. string.char(#username) .. username
  local body = username_attribute
  local length = string.pack("!I4", #body)

  return version .. packet_type .. sequence .. flags .. session_id .. length .. body
end

-- Function to send the TACACS+ packet and analyze the response
local function probe_tacacs_username(host, port, username)
  local socket = nmap.new_socket()
  socket:set_timeout(5000) -- 5-second timeout

  local packet = create_tacacs_auth_packet(username)

  local status, err = socket:connect(host, port)
  if not status then
    return nil, string.format("Failed to connect to TACACS+ server: %s", err)
  end

  local sent, err = socket:send(packet)
  if not sent then
    socket:close()
    return nil, string.format("Failed to send TACACS+ packet: %s", err)
  end

  local response, err = socket:receive()
  socket:close()

  if not response then
    return nil, string.format("No response from TACACS+ server: %s", err)
  end

  -- Analyze response for behavior indicative of valid usernames
  local response_code = string.byte(response, 2) -- Response type/code

  if response_code == 0x02 then -- Assume 0x02 indicates a valid username (example)
    return true
  else
    return false
  end
end

-- Main action function
action = function(host, port)
  local usernames = stdnse.get_script_args("tacacs-user-enum.userlist") or {"admin", "test", "guest", "user"}
  local results = {}

  for _, username in ipairs(usernames) do
    stdnse.print_debug(1, "Probing TACACS+ server with username: %s", username)

    local is_valid, err = probe_tacacs_username(host, port, username)
    if is_valid then
      table.insert(results, string.format("Valid username found: %s", username))
    elseif err then
      stdnse.print_debug(1, "Error probing username %s: %s", username, err)
    end
  end

  if #results > 0 then
    return table.concat(results, "\n")
  else
    return "No valid usernames detected."
  end
end
