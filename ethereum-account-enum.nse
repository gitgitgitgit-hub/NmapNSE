-- Script Name: ethereum-account-enum.nse
-- Purpose: Enumerates Ethereum accounts exposed via the Geth RPC interface on port 8545.
-- Author: Your Name
-- License: Same as Nmap

-- Import necessary libraries
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"

-- Define the description of the script
description = [[
Checks for misconfigurations in Ethereum Geth RPC interfaces by attempting to enumerate accounts using the eth_accounts and personal_listAccounts methods.
These methods should ideally be protected by authentication, but misconfigured nodes might expose sensitive information.
]]

-- Define categories
categories = {"discovery", "safe"}

-- Define portrule to target Geth RPC interfaces
portrule = shortport.port_or_service(8545, "geth")

-- Function to send JSON-RPC requests
local function send_rpc_request(host, port, method)
  local url = string.format("http://%s:%d", host, port)
  local payload = stdnse.format([[{
    "jsonrpc": "2.0",
    "method": "%s",
    "params": [],
    "id": 1
  }]], method)

  local response = http.post(url, nil, payload, {header = {"Content-Type: application/json"}})

  if not response or response.status ~= 200 then
    return nil, string.format("HTTP error: %s", response and response.status or "no response")
  end

  local body = response.body
  local result = stdnse.parse_json(body)

  if result and result.result then
    return result.result
  elseif result and result.error then
    return nil, string.format("RPC error: %s", result.error.message)
  else
    return nil, "Unknown error or invalid response format."
  end
end

-- Main action function
action = function(host, port)
  local results = {}

  -- Attempt to enumerate accounts using eth_accounts
  local eth_accounts, err = send_rpc_request(host, port, "eth_accounts")
  if eth_accounts then
    table.insert(results, string.format("eth_accounts: %s", table.concat(eth_accounts, ", ")))
  elseif err then
    table.insert(results, string.format("eth_accounts failed: %s", err))
  end

  -- Attempt to enumerate accounts using personal_listAccounts
  local personal_accounts, err = send_rpc_request(host, port, "personal_listAccounts")
  if personal_accounts then
    table.insert(results, string.format("personal_listAccounts: %s", table.concat(personal_accounts, ", ")))
  elseif err then
    table.insert(results, string.format("personal_listAccounts failed: %s", err))
  end

  -- Return results
  if #results > 0 then
    return table.concat(results, "\n")
  else
    return "No accounts found or access denied."
  end
end
