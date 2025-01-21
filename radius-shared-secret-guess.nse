-- Script Name: radius-secret-guess.nse
-- Purpose: Attempts to guess or brute-force the RADIUS shared secret.
-- Author: Your Name
-- License: Same as Nmap

-- Import necessary libraries
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local creds = require "creds"

-- Define the description of the script
description = [[
Attempts to guess or brute-force the RADIUS shared secret by observing responses to authentication requests with different secrets.
This script is intended for internal security audits only and must be used with explicit permission due to ethical and legal concerns.
]]

-- Define categories
categories = {"auth", "intrusive"}

-- Define the script's arguments
local args = stdnse.parse_args({
  {"radius-secret-guess.dictionary", "Path to the shared secret dictionary file (default: nselib/data/radius-secrets.txt)"},
  {"radius-secret-guess.delay", "Delay in milliseconds between attempts (default: 100ms)", "number"},
})

-- Default values
local DEFAULT_DICTIONARY = "nselib/data/radius-secrets.txt"
local DEFAULT_DELAY = 100 -- milliseconds

portrule = shortport.port_or_service({1812}, "radius")

-- Function to send a RADIUS Access-Request with a specific shared secret
local function send_radius_request_with_secret(host, port, secret)
  local socket = nmap.new_socket()
  socket:set_timeout(5000) -- 5-second timeout

  -- Construct a basic RADIUS Access-Request packet
  local packet = "\x01\x0a\x00\x14" .. -- Code (Access-Request), Identifier, Length
                 "\x00\x00\x00\x00" .. -- Authenticator (16 bytes of zeros)
                 "\x01\x08testuser" -- User-Name attribute

  -- Calculate the Message-Authenticator using the secret
  local authenticator = nmap.crypt("md5", secret .. packet)
  packet = packet:sub(1, 4) .. authenticator .. packet:sub(21)

  local status, err = socket:sendto(host, port, packet)
  if not status then
    stdnse.print_debug(1, "Failed to send RADIUS request with secret: %s", err)
    socket:close()
    return nil, err
  end

  local response, err = socket:receive()
  socket:close()

  if not response then
    stdnse.print_debug(1, "No response for secret %s: %s", secret, err)
    return nil, err
  end

  -- Check if the response indicates a valid shared secret
  return response:sub(1, 1) == "\x02" -- Code 2 (Access-Accept)
end

-- Main brute-force function
action = function(host, port)
  local dictionary_file = args["radius-secret-guess.dictionary"] or DEFAULT_DICTIONARY
  local delay = args["radius-secret-guess.delay"] or DEFAULT_DELAY

  local secrets = creds.parse(dictionary_file)
  if not secrets then
    return "Failed to load shared secret dictionary file"
  end

  for _, secret in ipairs(secrets) do
    stdnse.print_debug(1, "Trying shared secret: %s", secret)

    local success, err = send_radius_request_with_secret(host.ip, port.number, secret)
    if success then
      return string.format("Valid shared secret found: %s", secret)
    elseif err then
      stdnse.print_debug(1, "Error during attempt: %s", err)
    end

    stdnse.sleep(delay)
  end

  return "No valid shared secret found"
end
