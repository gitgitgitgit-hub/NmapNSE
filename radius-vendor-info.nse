-- Script Name: radius-vendor-info.nse
-- Purpose: Enumerates RADIUS vendor-specific attributes and behaviors.
-- Author: Your Name
-- License: Same as Nmap

-- Import necessary libraries
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

-- Define the description of the script
description = [[
Probes for vendor-specific attributes (VSAs) in RADIUS servers to identify hardware or software specifics.

This script checks for known vendor-specific attributes associated with major network equipment providers and helps
in hardware fingerprinting or identifying potential misconfigurations.
]]

-- Define categories
categories = {"discovery", "safe"}

-- Define portrule to target RADIUS servers
portrule = shortport.port_or_service({1812}, "radius")

-- Define known vendor-specific attributes
local vendor_attributes = {
  [9] = "Cisco",               -- Cisco Systems
  [11] = "HP",                 -- Hewlett-Packard
  [45] = "Juniper",            -- Juniper Networks
  [311] = "Microsoft",         -- Microsoft
  [674] = "Alcatel-Lucent",    -- Alcatel-Lucent
  [2352] = "Aruba Networks",   -- Aruba Networks
}

-- Function to send a RADIUS Access-Request and check for vendor-specific responses
local function probe_vendor_attributes(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000) -- 5-second timeout

  -- Construct a basic RADIUS Access-Request packet with a generic VSA
  local packet = "\x01\x0b\x00\x18" .. -- Code (Access-Request), Identifier, Length
                 "\x00\x00\x00\x00" .. -- Authenticator (16 bytes of zeros)
                 "\x1a\x10" ..          -- Vendor-Specific Attribute header (Vendor ID placeholder)
                 "\x00\x00\x00\x09" .. -- Cisco Vendor ID (example)
                 "\x01\x04test"        -- Attribute value (dummy)

  local status, err = socket:sendto(host, port, packet)
  if not status then
    stdnse.print_debug(1, "Failed to send RADIUS request: %s", err)
    socket:close()
    return nil, err
  end

  local response, err = socket:receive()
  socket:close()

  if not response then
    return nil, string.format("No response from server: %s", err)
  end

  -- Analyze response for vendor-specific attributes
  local detected_vendors = {}
  for vendor_id, vendor_name in pairs(vendor_attributes) do
    if response:find(string.pack("!I4", vendor_id)) then
      table.insert(detected_vendors, vendor_name)
    end
  end

  return detected_vendors
end

-- Main action function
action = function(host, port)
  local results = {}

  local vendors, err = probe_vendor_attributes(host, port)
  if err then
    table.insert(results, string.format("Error probing vendor attributes: %s", err))
  elseif #vendors > 0 then
    table.insert(results, "Detected vendor-specific attributes:")
    for _, vendor in ipairs(vendors) do
      table.insert(results, string.format("- %s", vendor))
    end
  else
    table.insert(results, "No vendor-specific attributes detected.")
  end

  return table.concat(results, "\n")
end
RADIUS Server Health Check
Script Name: radius-health-check.nse
Functionality: 
Checks if the RADIUS server is responsive and healthy by sending periodic authentication or accounting requests.
Could include latency checks or packet loss statistics.
Usage: For monitoring or ensuring the RADIUS server is operational in a network environment.
