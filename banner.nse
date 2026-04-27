local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
This is a robust banner scanner.
Connects to a TCP service, waits for a passive banner, sends two Enter
keystrokes if no data is received, and retries with "GET /" if the service
closes the connection or remains silent. The received banner is stored in
host.registry and reported in the script output in all cases.
]]

author = "CIRCL/Paul JUNG (Thanat0s)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "discovery", "safe" }

---
-- @args smart-banner.wait Passive banner wait time in milliseconds.
--       Defaults to 500.
-- @args smart-banner.timeout Read timeout after sending data, in
--       milliseconds. Defaults to 2000.
-- @args smart-banner.maxbytes Maximum banner bytes to collect.
--       Defaults to 4096.
--
-- @usage
-- nmap -sV --script ./smart-banner.nse -p <ports> <target>
--
-- @output
-- |_ smart-banner: SSH-2.0-OpenSSH_9.2p1\x0A

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end

local SCRIPT_KEY = SCRIPT_NAME

local function get_arg(name, default)
  return tonumber(stdnse.get_script_args(SCRIPT_KEY .. "." .. name)) or default
end

local function is_close_error(err)
  if not err then
    return false
  end

  err = string.lower(tostring(err))
  return err:match("closed") or err:match("eof") or err:match("reset")
end

local function replace_nonprint(data, len)
  local output = {}
  local count = 0

  for char in data:gmatch(".") do
    local byte = char:byte()
    if byte < 32 or byte > 126 then
      output[#output + 1] = string.format("\\x%02X", byte)
      count = count + 4
    else
      output[#output + 1] = char
      count = count + 1
    end

    if type(len) == "number" and count >= len then
      break
    end
  end

  return table.concat(output)
end

local function save_banner(host, port, result)
  host.registry[SCRIPT_KEY] = host.registry[SCRIPT_KEY] or {}
  host.registry[SCRIPT_KEY][port.number .. "/" .. port.protocol] = result
end

local function extra_output()
  return (nmap.verbosity() - nmap.debugging() > 0 and nmap.verbosity() - nmap.debugging()) or 0
end

local function output_banner(out)
  if type(out) ~= "string" or out == "" then
    return nil
  end

  local filename = SCRIPT_NAME
  local line_len = 75
  local fline_offset = 5
  local fline_len

  if filename:len() < (line_len - fline_offset) then
    fline_len = line_len - 1 - filename:len() - fline_offset
  else
    fline_len = 0
  end

  local sline_len = line_len - 1 - (fline_offset - 2)
  local total_out_chars

  if fline_len > 0 then
    total_out_chars = fline_len + (extra_output() * sline_len)
  else
    total_out_chars = (1 + extra_output()) * sline_len
  end

  out = replace_nonprint(out:match("^%s*(.-)%s*$"), 1 + total_out_chars)

  if out:len() > total_out_chars then
    while out:len() > total_out_chars do
      if out:sub(-4, -1):match("\\x%x%x") then
        out = out:sub(1, -5)
      else
        out = out:sub(1, -2)
      end
    end
    out = ("%s..."):format(out:sub(1, total_out_chars - 3))
  end

  local ptr = fline_len
  local lines = {}
  while true do
    if out:len() >= ptr then
      lines[#lines + 1] = (ptr > 0 and out:sub(1, ptr)) or " "
      out = out:sub(ptr + 1)
      ptr = sline_len
    else
      lines[#lines + 1] = out
      break
    end
  end

  return table.concat(lines, "\n")
end

local function connect_socket(host, port, timeout)
  local socket = nmap.new_socket()
  socket:set_timeout(timeout)

  local status, err = socket:connect(host.ip, port.number, port.protocol)
  if not status then
    socket:close()
    return nil, err
  end

  return socket
end

local function read_available(socket, first_timeout, next_timeout, max_bytes)
  local chunks = {}
  local total = 0
  local last_error

  socket:set_timeout(first_timeout)

  while total < max_bytes do
    local status, data = socket:receive_bytes(1)
    if not status then
      last_error = data
      break
    end

    if not data or data == "" then
      break
    end

    if total + #data > max_bytes then
      data = data:sub(1, max_bytes - total)
    end

    table.insert(chunks, data)
    total = total + #data
    socket:set_timeout(next_timeout)
  end

  if #chunks > 0 then
    return table.concat(chunks), nil
  end

  return "", last_error
end

local function attempt_passive_then_enter(host, port, wait_timeout, read_timeout, max_bytes)
  local socket, err = connect_socket(host, port, read_timeout)
  if not socket then
    return {
      stage = "connect",
      banner = "",
      closed = false,
      error = "connect failed: " .. (err or "unknown error")
    }
  end

  local banner, read_error = read_available(socket, wait_timeout, 250, max_bytes)
  if banner ~= "" then
    socket:close()
    return {
      stage = "passive",
      banner = banner,
      closed = false
    }
  end

  if is_close_error(read_error) then
    socket:close()
    return {
      stage = "passive",
      banner = "",
      closed = true,
      error = read_error
    }
  end

  local status, send_error = socket:send("\r\n\r\n")
  if not status then
    socket:close()
    return {
      stage = "enter",
      banner = "",
      closed = is_close_error(send_error),
      error = send_error
    }
  end

  banner, read_error = read_available(socket, read_timeout, 250, max_bytes)
  socket:close()

  return {
    stage = "enter",
    banner = banner,
    closed = is_close_error(read_error),
    error = read_error
  }
end

local function attempt_get(host, port, read_timeout, max_bytes)
  local socket, err = connect_socket(host, port, read_timeout)
  if not socket then
    return {
      stage = "get",
      banner = "",
      closed = false,
      error = "reconnect failed: " .. (err or "unknown error")
    }
  end

  local status, send_error = socket:send("GET /\r\n\r\n")
  if not status then
    socket:close()
    return {
      stage = "get",
      banner = "",
      closed = is_close_error(send_error),
      error = send_error
    }
  end

  local banner, read_error = read_available(socket, read_timeout, 250, max_bytes)
  socket:close()

  return {
    stage = "get",
    banner = banner,
    closed = is_close_error(read_error),
    error = read_error
  }
end

action = function(host, port)
  local wait_timeout = get_arg("wait", 500)
  local read_timeout = get_arg("timeout", 2000)
  local max_bytes = get_arg("maxbytes", 4096)

  local result = attempt_passive_then_enter(host, port, wait_timeout, read_timeout, max_bytes)
  if result.closed or result.banner == "" then
    result = attempt_get(host, port, read_timeout, max_bytes)
  end

  save_banner(host, port, result)
  return output_banner(result.banner)
end
