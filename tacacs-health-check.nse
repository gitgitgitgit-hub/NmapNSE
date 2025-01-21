-- Script Name: tacacs-health-check.nse
-- Purpose: Monitors the health and responsiveness of a TACACS+ server by periodically sending authentication or authorization requests.
-- Author: Your Name
-- License: Same as Nmap

-- Import necessary libraries
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local math = require "math"

-- Define the description of the script
description = [[
Checks the responsiveness of a TACACS+ server by sending periodic authentication or authorization requests.
Metrics such as response time and server availability are collected to assess the operational status of the server.
Useful for monitoring TACACS+ services in a network infrastructure.
]]

-- Define categories
categories = {"discovery", "safe"}

-- Define portrule to target TACACS+ servers
portrule = shortport.port_or_service(49, "tacacs")

-- Function to construct a basic TACACS+ health check packet
local function create_health_check_packet()
  -- TACACS+ header structure:
  -- 1 byte: version (major << 4 | minor)
  -- 1 byte: type (e.g., 0x01 for authentication START)
  -- 1 byte: sequence (should start at 1)
  -- 1 byte: flags (set to 0 for this packet)
  -- 4 bytes: session ID (random value)
  -- 4 bytes: length of the packet body

  local version = "\xc0" -- TACACS+ version 1.0
  local packet_type = "\x01" -- Authentication START
  local sequence = "\x01" -- Sequence number 1
  local flags = "\x00" -- No flags
  local session_id = stdnse.generate_random_bytes(4)

  -- Example payload: Basic health check request
  local body = "health-check-body" -- Placeholder payload
  local length = string.pack("!I4", #body)

  return version .. packet_type .. sequence .. flags .. session_id .. length .. body
end

-- Function to send the health check packet and measure response time
local function send_health_check(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000) -- 5-second timeout

  local packet = create_health_check_packet()

  local status, err = socket:connect(host, port)
  if not status then
    return nil, string.format("Failed to connect to TACACS+ server: %s", err)
  end

  local start_time = nmap.clock_ms()
  local sent, err = socket:send(packet)
  if not sent then
    socket:close()
    return nil, string.format("Failed to send health check packet: %s", err)
  end

  local response, err = socket:receive()
  local end_time = nmap.clock_ms()
  socket:close()

  if not response then
    return nil, string.format("No response from TACACS+ server: %s", err)
  end

  -- Calculate response time
  local response_time = end_time - start_time

  -- Return response details and response time
  return {
    response_time = response_time,
    response = response
  }
end

-- Main action function
action = function(host, port)
  local results = {}

  -- Perform multiple health checks (e.g., 3 checks)
  for i = 1, 3 do
    local result, err = send_health_check(host, port)

    if result then
      table.insert(results, string.format("Health Check %d: Response time: %d ms", i, result.response_time))
    elseif err then
      table.insert(results, string.format("Health Check %d: Failed (%s)", i, err))
    end

    -- Wait 1 second between checks to avoid overwhelming the server
    nmap.sleep(1000)
  end

  return table.concat(results, "\n")
end
