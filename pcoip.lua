-------------------------------------------------
-- PCoIP postdissector --
-------------------------------------------------

-------------------------------------------------
-- Copyright - Advance Seven Limited, 2016
-- License - GNU GPL v3
--      see http://www.gnu.org/licenses/gpl.html
-------------------------------------------------

-------------------------------------------------
-- This code is an output from the Advance7
-- TribeLab project - see www.tribelabzero.com
-------------------------------------------------

------------------------History--------------------------
-- r1 - pjo - Initial release
-- r2 - pjo - Improved the decoding of the PCoIP and ESP
-- r3 - pjo - Removed returns from prefs labels
-- r4 - pjo - Fix sequence number bug
--
---------------------------------------------------------

-- Execution controls -------------------------------------
debug_set = false
go_bang = {}
-- End of Execution Controls ------------------------------


-- Add entries to the service port table for packets to be treated as services
-- This is populated with preferences "service ports" data
udp_svc_port = {}

-- declare the extractors for some Fields to be read
-- these work like getters
frame_number_f = Field.new("frame.number")
eth_type_f = Field.new("eth.type")
ip_proto_f = Field.new("ip.proto")
ipv6_nxt_f = Field.new("ipv6.nxt")


this_udp_src_f = Field.new("udp.srcport")
this_udp_dst_f = Field.new("udp.dstport")
udp_stream_f = Field.new("udp.stream")
this_udp_len_f = Field.new("udp.length")
this_udp_data_f = Field.new("data.data")

-- declare the PCoIP as a protocol
pcoip = Proto("pcoip","PCoIP Postdissector")

esp_seq_array = {}
info_suffix_array = {}

-- Packet information
this_frame = 0
udp_stream = 0
stream_and_dir = 0
last_frame = 0

pcoip_dir = ""          -- Direction label used in the protocol tree - "C->S" or "S->C"
pcoip_dir_numeric = 0;  -- 0 = C->S and 1 = S->C

pcoip_th = ByteArray.new()
esp_spi = ByteArray.new()
esp_seq = 0
pcoip_missing_count = 0 -- Number of PCoIP APDUs missing in the current sequence

-- add the field to the protocol
-- create the fields for our "protocol"
pcoip_dir_F = ProtoField.string("pcoip.dir","PCoIP Direction")
pcoip_th_F = ProtoField.string("pcoip.th","PCoIP Transport Header")
esp_spi_F = ProtoField.string("pcoip.spi","ESP SPI")
esp_seq_F = ProtoField.uint32("pcoip.seq","ESP Seq")

pcoip_missing_apdus = ProtoExpert.new("pcoip.missing_apdus.expert", "PCoIP APDUs are missing", expert.group.SEQUENCE, expert.severity.WARN)

-- add the field to the protocol
pcoip.fields = {pcoip_dir_F, pcoip_th_F, esp_spi_F, esp_seq_F}
pcoip.experts = {pcoip_missing_apdus}

-- master switch to determine whether this is a PCoIP packet
is_pcoip = false;

function string:explode( inSplitPattern, outResults )
  if not outResults then
    outResults = { }
  end
  local theStart = 1
  local theSplitStart, theSplitEnd = string.find( self, inSplitPattern, theStart )
  while theSplitStart do
    table.insert( outResults, string.sub( self, theStart, theSplitStart-1 ) )
    theStart = theSplitEnd + 1
    theSplitStart, theSplitEnd = string.find( self, inSplitPattern, theStart )
  end
  table.insert( outResults, string.sub( self, theStart ) )
  return outResults
end


-- This function gets called when a new trace file is loaded
function pcoip.init()
  local i
  
  if debug_set then info("pcoip.init()") end
  
  prefs_table = {}

  prefs_table = pcoip.prefs.udpports:explode(",")
  for i = 1, #prefs_table do
    udp_svc_port[tonumber(prefs_table[i])] = true
  end
    
  for i=0, 20 do
    esp_seq_array[i] = 0
  end
  
  return  
end


-- This function set globals for common frame values.

function set_proto_values(pinfo)
  this_frame = pinfo.number
  
  if debug_set then
    info("==========================================================================")
    info(" ")
    info("Frame: " .. this_frame)
    info("Visited: " .. tostring(pinfo.visited))
  end

  ip_protocol = nil
  is_pcoip = false -- default
  pcoip_missing_count = 0

  local eth_type = eth_type_f()
  
  if not eth_type then return end  -- This is an 802.3 frame

  x_eth_type = eth_type.value

  if x_eth_type == 0x0800 or x_eth_type == 0x86dd then

    local ip_proto = ip_proto_f()
    local srcport = nil
    local dstport = nil

    if x_eth_type == 0x0800 then  ip_proto = ip_proto_f()
    elseif x_eth_type == 0x86dd then ip_proto = ipv6_nxt_f()
    end

    this_ip_protocol = tonumber(ip_proto.value)

    if this_ip_protocol == 17 then

      -- It's UDP
      srcport = this_udp_src_f()
      dstport = this_udp_dst_f()

      local udp_len = this_udp_len_f()
      i_udp_len = tonumber(udp_len.value)

      if i_udp_len > 0 then

        this_srcport = tonumber(srcport.value)
        this_dstport = tonumber(dstport.value)
        
        if udp_svc_port[this_srcport] or udp_svc_port[this_dstport] then

          if udp_svc_port[this_dstport] then
            pcoip_dir = "C->S"
            pcoip_dir_numeric = 0
          else
            pcoip_dir = "S->C"
            pcoip_dir_numeric = 1
          end
          
          udp_stream = udp_stream_f()
          stream_and_dir = (udp_stream.value * 2) + pcoip_dir_numeric

          is_pcoip = true
        end
      end
    end
  end

end

-- This function adds the RTE data to the tree
function write_pcoip(tree)
  local subtree = tree:add(pcoip,"PCoIP Header Data")
  local tempString = ""

  local new_item
  new_item = subtree:add(pcoip_dir_F, pcoip_dir)
  tempString = pcoip_th:tohex(true, ":")
  new_item = subtree:add(pcoip_th_F, tempString)
  tempString = esp_spi:tohex(true, ":")
  new_item = subtree:add(esp_spi_F, tempString)
  new_item = subtree:add(esp_seq_F, esp_seq)

  -- if pcoip_missing_count > 0 then
  --   new_item = subtree:add_proto_expert_info(pcoip_missing_apdus)
  -- end

end

function pcoip.dissector(buffer,pinfo,tree)

  local info_text
  local udp_data
  local ptr
  local tvbr
  
  set_proto_values(pinfo)
  
  -- Have to wipe the info suffixes if we reload a file or load a new one
  if not pinfo.visited then
    info_suffix_array[this_frame] = ""
  end

  if debug_set then info("SNAP01 esp_seq_array[stream_and_dir]: " .. esp_seq_array[stream_and_dir]) end

  if is_pcoip then
    udp_data = this_udp_data_f()

    ptr = udp_data.offset + 0 -- set a pointer to the offset of the PCoIP Transport Header within the tvb
    tvbr = buffer:range(ptr, 4) -- set up a range
    pcoip_th = tvbr:bytes() -- extract the bytes

    ptr = udp_data.offset + 4 -- set a pointer to the offset of the PCoIP Transport Header within the tvb
    tvbr = buffer:range(ptr, 4) -- set up a range
    esp_spi = tvbr:bytes() -- extract the bytes

    ptr = udp_data.offset + 8 -- set a pointer to the offset of the ESP sequence number within the tvb
    tvbr = buffer:range(ptr, 4) -- set up a range
    esp_seq = tvbr:uint() -- extract the integer value
    
    if pinfo.visited then
      write_pcoip(tree)

      -- Set the Info column text
      info_text = "PCoIP " .. pcoip_dir .. " - ESP Seq. No: " .. esp_seq
      
      if info_suffix_array[this_frame] then
        info_text = info_text .. " " .. info_suffix_array[this_frame]
      end

      pinfo.cols.info:set(info_text)
      pinfo.cols.info:fence()
    else
      if debug_set then info("SNAP02 esp_seq_array[stream_and_dir]: " .. esp_seq_array[stream_and_dir]) end

      -- Check for missing sequence numbers
      if esp_seq < esp_seq_array[stream_and_dir] then
        info_suffix_array[this_frame] = "Sequence number has wrapped"
      else
        if (esp_seq - 1) > esp_seq_array[stream_and_dir] then
          pcoip_missing_count = esp_seq - 1 - esp_seq_array[stream_and_dir]
          info_suffix_array[this_frame] = " - The " .. pcoip_missing_count .. " previous PCoIP APDUs are missing"
        end
      end
      
    end

    esp_seq_array[stream_and_dir] = esp_seq
    
    if debug_set then info("SNAP03 esp_seq_array[stream_and_dir]: " .. esp_seq_array[stream_and_dir]) end
      
  end
  
  last_frame = this_frame
end

-- register our protocol as a postdissector
register_postdissector(pcoip)

pcoip.prefs.header = Pref.statictext("PCoIP Dissector r4")

-- Create a range preference for the service ports that this dissector should process
-- Create a range preference that shows under Foo Protocol's preferences
pcoip.prefs.udpports = Pref.range("PCoIP UDP service ports", "4172", "Add and remove ports numbers separated by commas", 65535)

pcoip.prefs.footer = Pref.statictext("Developed by the TribeLab team at Advance7 - see www.tribelab.com", "")
