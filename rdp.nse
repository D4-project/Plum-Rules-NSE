local match = require "match"
local rdp = require "rdp"
local shortport = require "shortport"
local stdnse = require "stdnse"
local smbauth = require "smbauth"
local datetime = require "datetime"
local sslcert = require "sslcert"

description = [[
Collects RDP metadata before login: security negotiation including RDSTLS,
host names, build and time from NTLM challenges, RDP version over native and
TLS security, certificates, and native encryption methods.
Sends only an NTLM Type 1 negotiate, never a Type 3 authenticate or credentials.
RDP and NTLM metadata do not prove that the implementation is Microsoft Windows.
TLS support is not a TLS cipher-suite audit. Missing fields remain unknown.
]]
author = "CIRCL; NTLM negotiate based on Nmap rdp-ntlm-info (Tom Sellers)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}
portrule = shortport.port_or_service(3389, "ms-wbt-server", "tcp")

-- @usage
-- nmap -n -Pn -sT -p3389 --script /absolute/path/rdp.nse <target>
-- Use +/absolute/path/rdp.nse to force execution on another TCP port.
local protocols = {[0]="Native RDP", [1]="TLS", [2]="CredSSP (NLA)",
  [4]="RDSTLS", [8]="CredSSP with Early User Auth"}
local native_methods = {
  [0]="None", [1]="RC4 40-bit", [8]="RC4 56-bit", [2]="RC4 128-bit", [16]="FIPS",
}
local errors = {[1]="SSL_REQUIRED_BY_SERVER", [2]="SSL_NOT_ALLOWED_BY_SERVER",
  [3]="SSL_CERT_NOT_ON_SERVER", [4]="INCONSISTENT_FLAGS",
  [5]="HYBRID_REQUIRED_BY_SERVER", [6]="SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER"}
local negotiate = stdnse.fromhex(
  "3037a003020160a130302e302ca02a0428" ..
  "4e544c4d5353500001000000b78208e2" ..
  "000000000000000000000000000000000a0063450000000f")

local function exact(socket, count)
  local ok, data = socket:receive_buf(match.numbytes(count), true)
  if not ok then error("receive failed: " .. tostring(data)) end
  return data
end

local function receive_tpkt(socket, minimum, maximum)
  local header = exact(socket, 4)
  assert(header:byte(1) == 3 and header:byte(2) == 0, "invalid TPKT")
  local length = string.unpack(">I2", header, 3)
  assert(length >= minimum and length <= maximum, "invalid TPKT length")
  return exact(socket, length - 4)
end

local function connection(comm, requested)
  assert(comm:connect(), "connection failed")
  assert(comm:send(rdp.Request.ConnectionRequest:new(requested)), "send failed")
  local body = receive_tpkt(comm.socket, 11, 4096)
  assert(body:byte(2)==0xd0 and body:byte(1)==#body-1, "invalid X.224 confirm")
  if #body==7 then return {legacy=true} end
  assert(#body==15, "invalid RDP negotiation length")
  local kind, flags, size, value = string.unpack("<BBI2I4", body, 8)
  assert(size==8 and (kind==2 or kind==3), "invalid RDP negotiation")
  if kind==3 then return {failure=value} end
  assert(protocols[value], "unknown selected protocol")
  assert(value==0 or (requested & value)~=0, "server selected unoffered protocol")
  return {selected=value, flags=flags}
end

local function describe_certificate(cert)
  if not cert or not cert.subject then return end
  local c = stdnse.output_table()
  c.subject_cn = cert.subject.commonName or "unknown"
  c.issuer_cn = cert.issuer.commonName or "unknown"
  c.key_type = cert.pubkey.type
  c.key_bits = cert.pubkey.bits
  c.signature_algorithm = cert.sig_algorithm
  for _, k in ipairs({"notBefore", "notAfter"}) do
    local v=cert.validity[k]
    c[k]=type(v)=="table" and datetime.format_timestamp(v) or v
  end
  for _, extension in ipairs(cert.extensions or {}) do
    if extension.name == "X509v3 Subject Alternative Name" then
      c.subject_alt_name = extension.value
      break
    end
  end
  return c
end

local function certificate(socket, out)
  out.certificate = describe_certificate(socket:get_ssl_certificate()) or out.certificate
end

local function ber_value(data, pos)
  local length = data:byte(pos)
  assert(length, "missing MCS field length")
  pos = pos + 1
  if length >= 128 then
    local width = length - 128
    assert(width >= 1 and width <= 2 and pos + width - 1 <= #data,
      "invalid MCS field length")
    length, pos = string.unpack(">I" .. width, data, pos)
  end
  local next_pos = pos + length
  assert(next_pos <= #data + 1, "truncated MCS field")
  return pos, next_pos
end

local function per_length(data, pos)
  local first = data:byte(pos)
  assert(first, "missing GCC field length")
  if first < 128 then return first, pos + 1 end
  local low = data:byte(pos + 1)
  assert(low, "truncated GCC field length")
  return ((first & 0x7f) << 8) | low, pos + 2
end

local function gcc_server_blocks(body)
  assert(body:sub(1, 5) == "\x02\xf0\x80\x7f\x66", "invalid MCS Connect Response")
  local pos, end_pos = ber_value(body, 6)
  assert(end_pos == #body + 1, "invalid MCS Connect Response length")
  for _, tag in ipairs({0x0a, 0x02, 0x30, 0x04}) do
    assert(pos < end_pos and body:byte(pos) == tag, "unexpected MCS field")
    local first, next_pos = ber_value(body, pos + 1)
    if tag == 0x0a then
      assert(next_pos == first + 1 and body:byte(first) == 0, "MCS connection rejected")
    end
    if tag == 0x04 then
      assert(next_pos == end_pos, "invalid MCS user data length")
      local gcc = body:sub(first, next_pos - 1)
      assert(gcc:sub(1, 7) == "\x00\x05\x00\x14\x7c\x00\x01", "invalid GCC object ID")
      local _, choice_pos = per_length(gcc, 8)
      assert(gcc:byte(choice_pos) == 0x14, "invalid GCC Conference Create Response")
      local tag_length, tag_start = per_length(gcc, choice_pos + 3)
      local key = tag_start + tag_length
      assert(gcc:sub(key, key + 7) == "\x00\x01\xc0\x00McDn", "invalid GCC server data key")
      local length, start = per_length(gcc, key + 8)
      assert(start + length == #gcc + 1, "invalid GCC server data length")
      return gcc:sub(start)
    end
    pos = next_pos
  end
end

local function native_certificate(blob)
  assert(#blob >= 4, "truncated server certificate")
  local version, pos = string.unpack("<I4", blob)
  version = version & 0x7fffffff
  if version == 1 then
    assert(#blob >= 40, "truncated proprietary server certificate")
    local signature_algorithm, key_algorithm, key_type, key_length =
      string.unpack("<I4I4I2I2", blob, pos)
    local signature_pos = 17 + key_length
    assert(signature_algorithm == 1 and key_algorithm == 1 and key_type == 6
      and key_length >= 20 and signature_pos + 3 <= #blob
      and blob:sub(17, 20) == "RSA1", "invalid proprietary server key")
    local signature_type, signature_length, signature_start =
      string.unpack("<I2I2", blob, signature_pos)
    assert(signature_type == 8 and signature_length > 0
      and signature_start + signature_length == #blob + 1, "invalid proprietary server signature")
    local key_bits = string.unpack("<I4", blob, 25)
    assert(key_bits > 0 and key_bits <= (key_length - 20) * 8,
      "invalid proprietary server key length")
    local details = stdnse.output_table()
    details.format = "proprietary"
    details.key_type = "rsa"
    details.key_bits = key_bits
    return details
  end
  assert(version == 2 and #blob >= 8, "invalid server certificate format")
  local count
  count, pos = string.unpack("<I4", blob, pos)
  assert(count >= 2 and count <= 200, "invalid RDP certificate chain length")
  local der
  for _ = 1, count do
    assert(pos + 3 <= #blob, "truncated RDP certificate length")
    local size, start = string.unpack("<I4", blob, pos)
    pos = start + size
    assert(size > 0 and pos <= #blob + 1, "truncated RDP certificate")
    der = blob:sub(start, pos - 1)
  end
  local cert = sslcert.parse_ssl_certificate(der)
  assert(cert, "invalid X.509 server certificate")
  local details = describe_certificate(cert) or stdnse.output_table()
  details.format = "X.509"
  return details
end

local function mcs_settings(comm, selected_protocol, offered_methods, out)
  local request = rdp.Request.MCSConnectInitial:new(offered_methods, selected_protocol)
  assert(comm:send(request), "MCS send failed")
  local blocks = gcc_server_blocks(receive_tpkt(comm.socket, 10, 65535))
  local selected_method
  local pos = 1
  while pos <= #blocks do
    assert(pos + 3 <= #blocks, "truncated GCC block header")
    local kind, length = string.unpack("<I2I2", blocks, pos)
    local next_pos = pos + length
    assert(length >= 4 and next_pos <= #blocks + 1, "invalid GCC block length")
    if kind == 0x0c01 and out then
      assert(length >= 8, "truncated RDP version")
      local version = string.unpack("<I4", blocks, pos + 4)
      local label = "Unknown"
      if version == 0x00080001 then
        label = " RDP 4.0 server"
      elseif version == 0x00080004 then
        label = " RDP 5.x, 6.x, 7.x, or 8.x server"
      elseif version >= 0x00080005 and version <= 0x00080011 then
        label = (" RDP 10.%d server"):format(version - 0x00080005)
      end
      out.protocol_version = "RDP Protocol Version: " .. label
      out.protocol_version_code = ("0x%08x"):format(version)
    elseif kind == 0x0c02 and selected_protocol == 0 then
      assert(length >= 12, "truncated native RDP security settings")
      local method, level = string.unpack("<I4I4", blocks, pos + 4)
      selected_method = method
      if out then
        local encryption = stdnse.output_table()
        encryption.method = native_methods[method] or "unknown"
        encryption.level = ({[0]="None", [1]="Low", [2]="Client Compatible",
          [3]="High", [4]="FIPS"})[level] or "unknown"
        out.native_encryption = encryption
        if method ~= 0 or level ~= 0 then
          assert(length >= 20, "truncated native RDP certificate lengths")
          local random_size, cert_size = string.unpack("<I4I4", blocks, pos + 12)
          local first = pos + 20 + random_size
          assert(random_size == 32 and cert_size > 0 and first + cert_size == next_pos,
            "invalid native RDP certificate length")
          out.native_certificate = native_certificate(blocks:sub(first, next_pos - 1))
        end
      end
    end
    pos = next_pos
  end
  return selected_method
end

local function ntlm_payload_bounds(blob, length, offset, header_size)
  assert(length == 0 or (offset >= header_size and offset + length <= #blob),
    "invalid NTLM challenge payload bounds")
end

local function ntlm_metadata(blob, out)
  assert(#blob >= 48 and blob:sub(1, 8) == "NTLMSSP\0"
    and string.unpack("<I4", blob, 9) == 2, "invalid NTLM challenge")
  local flags = string.unpack("<I4", blob, 21)
  local version_present = (flags & 0x02000000) ~= 0
  local header_size = version_present and 56 or 48
  assert(#blob >= header_size, "truncated NTLM challenge header")
  local name_size, _, name_offset = string.unpack("<I2I2I4", blob, 13)
  local info_size, _, info_offset = string.unpack("<I2I2I4", blob, 41)
  ntlm_payload_bounds(blob, name_size, name_offset, header_size)
  ntlm_payload_bounds(blob, info_size, info_offset, header_size)

  local info = smbauth.get_host_info_from_security_blob(blob)
  assert(type(info) == "table", "invalid NTLM challenge metadata")
  local fields = {
    workstation = "netbios_computer_name",
    fqdn = "fqdn",
    netbios_domain = "netbios_domain_name",
    dns_domain = "dns_domain_name",
    dns_forest = "dns_forest_name",
    target_name = "target_realm",
  }
  for key, field in pairs(fields) do
    if type(info[field]) == "string" and #info[field] > 0 then out[key] = info[field] end
  end
  if version_present and blob:sub(53, 56) == "\x00\x00\x00\x0f" then
    local major, minor, build = string.unpack("<BBI2", blob, 49)
    out.os_version = ("%d.%d"):format(major, minor)
    out.os_build = ("%d.%d.%d"):format(major, minor, build)
    out.implementation = "Microsoft Windows compatible (NTLM advertised build; not verified)"
  end
  if info.timestamp and info.timestamp > 0 then
    out.server_time = datetime.format_timestamp(info.timestamp // 10000000 - 11644473600, 0)
  end
end

local function ntlm(socket, out)
  assert(socket:send(negotiate), "NTLM negotiate send failed")
  local header=exact(socket,2)
  assert(header:byte(1)==0x30, "invalid CredSSP sequence")
  local length=header:byte(2)
  if length>=128 then
    local count=length-128
    assert(count>=1 and count<=3, "invalid DER length")
    local bytes=exact(socket,count)
    length=0
    for i=1,#bytes do length=length*256+bytes:byte(i) end
  end
  assert(length>0 and length<=65536, "CredSSP response too large")
  local data=exact(socket,length)
  local start=data:find("NTLMSSP\0",1,true)
  assert(start, "NTLM challenge not returned")
  ntlm_metadata(data:sub(start), out)
  out.ntlm="challenge received; no authentication submitted"
end

local function probe(host,port,requested,after)
  local comm=rdp.Comm:new(host,port)
  local result
  local ok,err=pcall(function()
    result=connection(comm,requested)
    if after then after(comm,result) end
  end)
  if comm.socket then pcall(function() comm:close() end) end
  if ok then return result end
  return result, tostring(err)
end

local function probe_native_encryption(host, port)
  local methods = stdnse.output_table()
  for _, requested_method in ipairs({1, 8, 2, 16}) do
    local selected_method
    local result, err = probe(host, port, 0, function(comm, reply)
      if reply.selected == 0 or reply.legacy then
        selected_method = mcs_settings(comm, 0, requested_method)
      end
    end)
    local status = "unknown"
    if not err then
      if selected_method == requested_method then
        status = "accepted"
      elseif selected_method ~= nil then
        status = "not selected"
      elseif result and result.failure then
        status = "rejected: " .. (errors[result.failure] or tostring(result.failure))
      end
    end
    methods[native_methods[requested_method]] = status
    stdnse.sleep(0.2)
  end
  return methods
end

action=function(host,port)
  local out=stdnse.output_table()
  out.rdp="unknown"
  out.implementation="unknown"
  out.workstation="unknown"
  out.fqdn="unknown"
  out.os_build="unknown"
  out.nla_required="unknown"
  out.ntlm="unknown"
  local security=stdnse.output_table()
  out.security=security
  local tls_selected, native_selected, nla_required=false,false,false
  local layers = {{"TLS",1}, {"Native_RDP",0}, {"NLA",3}, {"NLA_extended",11},
    {"RDSTLS",4}}
  for _, entry in ipairs(layers) do
    local label,request=entry[1],entry[2]
    local result,err=probe(host,port,request,function(comm,r)
      if r.selected==0 or (r.legacy and request==0) then
        native_selected=true
        mcs_settings(comm, 0, 27, out)
      elseif r.selected==1 then
        tls_selected=true
        assert(comm.socket:reconnect_ssl(), "TLS handshake failed")
        certificate(comm.socket, out)
        mcs_settings(comm, 1, 0, out)
      elseif (r.selected==2 or r.selected==8) and out.ntlm=="unknown" then
        assert(comm.socket:reconnect_ssl(), "TLS handshake failed")
        certificate(comm.socket,out)
        ntlm(comm.socket,out)
      end
    end)
    if result then
      out.rdp="detected"
      if result.failure then
        security[label]="rejected: " .. (errors[result.failure] or tostring(result.failure))
        if result.failure==5 or result.failure==6 then nla_required=true end
      elseif result.legacy then
        security[label]="legacy X.224 confirm; negotiation absent"
      else
        security[label]="selected " .. protocols[result.selected]
      end
      if err then security[label]=security[label] .. "; metadata incomplete: " .. err end
    else
      security[label]="unknown: " .. (err or "no response")
    end
    stdnse.sleep(0.2)
  end
  if tls_selected or native_selected then out.nla_required="no (non-NLA negotiation accepted)"
  elseif nla_required then out.nla_required="yes (server negotiation rejection)" end
  if native_selected then
    out.native_encryption_methods = probe_native_encryption(host, port)
  end
  if out.rdp=="detected" then out.tag="_plum_tag_:proto:rdp" end
  return out
end
