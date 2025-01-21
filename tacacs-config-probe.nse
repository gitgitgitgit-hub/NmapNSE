-- Script Name: tacacs-config-probe.nse
-- Purpose: Probes TACACS+ servers to extract configuration details like authentication types, encryption methods, and error handling behaviors.
-- Author: Your Name
-- License: Same as Nmap

-- Import necessary libraries
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

-- Define the description of the script
description = [[
Probes TACACS+ servers to extract configuration details such as supported authentication types,
encryption methods, and error handling behaviors. This is achieved by sending crafted or malformed
packets and analyzing server responses. Designed for authorized security assessments.
]]

-- Define categories
categories = {"discovery", "safe"}

-- Define portrule to target TACACS+ servers
portrule = shortport.port_or_service(49, "tacacs")

-- Function to construct a TACACS+ probing packet
local function create_tacacs_probe_packet(probe_type)
  -- TACACS+ header:
  -- 1 byte: version (major << 4 | minor)
  -- 1 byte: type (e.g., 0x01 for authentication START)
  -- 1 byte: sequence (should start at 1)
  -- 1 byte: flags (set to 0 for this packet)
  -- 4 bytes: session ID (random value)
  -- 4 bytes: length of the packet body

  local version = "\xc0" -- TACACS+ version 1.0
  local packet_type = probe_type or "\x01" -- Default to authentication START
  local sequence = "\x01" -- Sequence number 1
  local flags = "\x00" -- No flags
  local session_id = stdnse.generate_random_bytes(4)

  -- Example payload: crafted attributes or invalid data for probing
  local body = "invalid-body" -- Placeholder for payload
  local length = string.pack("!I4", #body)

  return version .. packet_type .. sequence .. flags .. session_id .. length .. body
end

-- Function to send the probing packet and analyze the response
local function probe_tacacs_server(host, port, probe_type)
  local socket = nmap.new_socket()
  socket:set_timeout(5000) -- 5-second timeout

  local packet = create_tacacs_probe_packet(probe_type)

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

  -- Analyze response to infer server configuration details
  -- For example, check for specific error codes or unexpected behaviors
  local response_code = string.byte(response, 2)
  return string.format("Probe type %s: Response code %02x", probe_type, response_code)
end

-- Main action function
action = function(host, port)
  local probe_types = {"\x01", "\x02", "\x03"} -- Example probe types: auth START, auth CONTINUE, etc.
  local results = {}

  for _, probe_type in ipairs(probe_types) do
    stdnse.print_debug(1, "Sending probe type: %s", probe_type)

    local result, err = probe_tacacs_server(host, port, probe_type)

    if result then
      table.insert(results, result)
    elseif err then
      stdnse.print_debug(1, "Error probing with type %s: %s", probe_type, err)
    end
  end

  if #results > 0 then
    return table.concat(results, "\n")
  else
    return "No configuration details could be inferred."
  end
end
