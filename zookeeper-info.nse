-- Script Name: zookeeper-info.nse
-- Purpose: Scans for Apache ZooKeeper services, gathers version information,
-- server state, and attempts to list znodes if accessible.
-- Author: thepacketbender
-- License: Same as Nmap -- See https://nmap.org/book/man-legal.html

-- Import necessary libraries
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

-- Define the description of the script
description = [[
Detects Apache ZooKeeper services, retrieves version and server state,
and attempts to enumerate znodes if access permissions allow.
]]

-- Define categories
categories = {"safe", "discovery", "version"}

-- Define portrule to target ZooKeeper services
portrule = function(host, port)
  return (port.number == 2181 or port.number == 2182) and port.protocol == "tcp"
end

-- Main action function
action = function(host, port)
  local socket = nmap.new_socket()
  local status, err = socket:connect(host, port)
  
  if not status then
    stdnse.print_debug(1, "Failed to connect to ZooKeeper: %s", err)
    return nil
  end
  
  -- Send commands to ZooKeeper server
  local commands = {
    "ruok", -- Checks if server is running
    "stat", -- Gets server stats
    "envi", -- Gets server environment
    "srvr", -- Gets detailed server information
    "cons", -- Gets connection information
    "wchs", -- Gets watch summary
    "wchc", -- Lists detailed watch information by session
    "wchp", -- Lists detailed watch information by path
    "mntr", -- Gets monitoring information
    "ls /", -- List root znode children
    "get /" -- Fetch data from the root znode
  }
  
  local results = {}
  
  for _, cmd in ipairs(commands) do
    socket:send(cmd .. "\n")
    local response
    status, response = socket:receive_lines(1)
    if status then
      table.insert(results, cmd .. ": " .. response)
    end
  end

  socket:close()

  if #results > 0 then
    return stdnse.format_output(true, results)
  end
end
