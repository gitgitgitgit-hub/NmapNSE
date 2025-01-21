-- Script Name: radius-config-scan.nse
-- Purpose: Scans and determines RADIUS server configuration settings.
-- Author: Your Name
-- License: Same as Nmap

-- Import necessary libraries
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

-- Define the description of the script
description = [[
Scans and tries to determine the configuration settings of a RADIUS server, such as:
- Timeout
- Retransmission count
- Supported authentication methods (PAP, CHAP, MS-CHAP).

The script might involve sending malformed or incomplete packets to analyze how the server responds.
Useful for assessing the robustness and security of a RADIUS server's configuration.
]]

-- Define categories
categories = {"discovery", "safe"}

-- Define script arguments
portrule = shortport.port_or_service({1812}, "radius")

-- Function to test server timeout
local function test_timeout(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(10000) -- Set a longer timeout to test server behavior

  -- Send a malformed RADIUS packet to check timeout
  local malformed_request = "\x01\x05\x00\x14" .. -- Code, Identifier, Length
                            "\x00\x00\x00\x00" .. -- Authenticator (16 bytes of zeros)
                            "\x00\x00" -- Malformed/empty attributes

  local start_time = nmap.clock_ms()
  local status, err = socket:sendto(host, port, malformed_request)
  if not status then
    stdnse.print_debug(1, "Failed to send malformed packet: %s", err)
    socket:close()
    return nil, err
  end

  local response = socket:receive()
  local end_time = nmap.clock_ms()
  socket:close()

  if response then
    return end_time - start_time -- Calculate response time in milliseconds
  else
    return "Timeout exceeded or no response"
  end
end

-- Function to test retransmission behavior
local function test_retransmissions(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000) -- Set a timeout for retransmission behavior testing

  -- Send an incomplete packet
  local incomplete_request = "\x01\x06\x00\x10" .. -- Code, Identifier, Length
                              "\x00\x00\x00\x00" -- Incomplete data

  local status, err = socket:sendto(host, port, incomplete_request)
  if not status then
    stdnse.print_debug(1, "Failed to send incomplete packet: %s", err)
    socket:close()
    return nil, err
  end

  local retransmissions = 0
  repeat
    local response = socket:receive()
    if response then retransmissions = retransmissions + 1 end
  until not response

  socket:close()
  return retransmissions
end

-- Function to probe supported authentication methods
local function probe_auth_methods(host, port)
  local methods = {
    {name = "PAP", packet = "\x01\x07\x00\x14" .. "\x00\x00\x00\x00\x02\x04test"},
    {name = "CHAP", packet = "\x01\x08\x00\x14" .. "\x00\x00\x00\x00\x03\x05test"},
    {name = "MS-CHAP", packet = "\x01\x09\x00\x14" .. "\x00\x00\x00\x00\x04\x06test"},
  }

  local supported_methods = {}

  for _, method in ipairs(methods) do
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:sendto(host, port, method.packet)
    if not status then
      stdnse.print_debug(1, "Failed to send %s probe: %s", method.name, err)
    else
      local response = socket:receive()
      if response then
        table.insert(supported_methods, method.name)
      end
    end

    socket:close()
  end

  return supported_methods
end

-- Main action function
action = function(host, port)
  local results = {}

  -- Test timeout behavior
  local timeout_result, timeout_err = test_timeout(host, port)
  if timeout_err then
    table.insert(results, string.format("Timeout test failed: %s", timeout_err))
  else
    table.insert(results, string.format("Timeout test result: %s ms", timeout_result))
  end

  -- Test retransmission behavior
  local retransmission_result, retransmission_err = test_retransmissions(host, port)
  if retransmission_err then
    table.insert(results, string.format("Retransmission test failed: %s", retransmission_err))
  else
    table.insert(results, string.format("Retransmissions detected: %d", retransmission_result))
  end

  -- Probe authentication methods
  local supported_methods = probe_auth_methods(host, port)
  if #supported_methods > 0 then
    table.insert(results, string.format("Supported authentication methods: %s", table.concat(supported_methods, ", ")))
  else
    table.insert(results, "No supported authentication methods detected")
  end

  return table.concat(results, "\n")
end
