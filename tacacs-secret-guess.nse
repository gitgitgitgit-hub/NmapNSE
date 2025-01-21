-- Script Name: tacacs-secret-guess.nse
-- Purpose: Attempts to guess or brute-force the TACACS+ shared secret by analyzing server responses.
-- Author: Your Name
-- License: Same as Nmap

-- Import necessary libraries
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local creds = require "creds"

-- Define the description of the script
description = [[
Attempts to guess or brute-force the TACACS+ shared secret by sending authentication requests with different secrets.
This script is intended solely for authorized internal security audits.
]]

-- Define categories
categories = {"intrusive", "auth"}

-- Define portrule to target TACACS+ servers
portrule = shortport.port_or_service(49, "tacacs")

-- Default shared secret list and rate limiting
local DEFAULT_SECRET_LIST = {"secret", "tacacs", "admin", "password"}
local DEFAULT_RATE_LIMIT = 100 -- Milliseconds between attempts

-- Function to construct a TACACS+ packet with a shared secret
local function create_tacacs_packet(secret)
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

  -- Use the shared secret to create a valid packet
  local body = "test-body" -- Example placeholder for packet body (e.g., username, password attributes)
  local length = string.pack("!I4", #body)

  -- Normally, TACACS+ uses the shared secret to compute an MD5 hash or similar mechanism
  -- For simplicity, the secret is included in the payload here (adjust as needed for protocol-specific details)
  local payload = secret .. body

  return version .. packet_type .. sequence .. flags .. session_id .. length .. payload
end

-- Function to send the TACACS+ packet and analyze the response
local function attempt_tacacs_secret(host, port, secret)
  local socket = nmap.new_socket()
  socket:set_timeout(5000) -- 5-second timeout

  local packet = create_tacacs_packet(secret)

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

  -- Analyze response to determine if the secret was correct (e.g., specific success codes or behaviors)
  local response_code = string.byte(response, 2)
  if response_code == 0x03 then -- Assume 0x03 indicates success
    return true
  else
    return false
  end
end

-- Main action function
action = function(host, port)
  local secrets = stdnse.get_script_args("tacacs-secret-guess.secretlist") or DEFAULT_SECRET_LIST
  local rate_limit = tonumber(stdnse.get_script_args("tacacs-secret-guess.rate_limit")) or DEFAULT_RATE_LIMIT

  local results = {}

  for _, secret in ipairs(secrets) do
    stdnse.print_debug(1, "Trying shared secret: %s", secret)

    local success, err = attempt_tacacs_secret(host, port, secret)

    if success then
      table.insert(results, string.format("Valid shared secret found: %s", secret))
      break -- Stop after finding a valid secret
    elseif err then
      stdnse.print_debug(1, "Error attempting shared secret %s: %s", secret, err)
    end

    stdnse.sleep(rate_limit)
  end

  if #results > 0 then
    return table.concat(results, "\n")
  else
    return "No valid shared secret found."
  end
end
