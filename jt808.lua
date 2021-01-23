
require "bit32"


SIXOCTETS = 6
FOUROCTETS = 4
TWOOCTETS = 2
ONEOCTET = 1

jt808_proto = Proto("jt808", "JT808 Protocol")

jt808_proto.fields = {}
local fds3 = jt808_proto.fields
-- fds3.jt808_flag = ProtoField.new("Flag", "jt808.version", ftypes.UINT8)
fds3.jt808_flag = ProtoField.uint8("jt808.flag", "Flag", base.HEX, null)
fds3.jt808_msg_type = ProtoField.new("MsgType", "jt808.msg_type", ftypes.STRING)


fds3.jt808_msg_attr = ProtoField.uint16("jt808.msg_attr", "Msg Attr", base.HEX, null)
fds3.jt808_msg_attr_resv   = ProtoField.uint16("jt808.msg_attr.reserve", "Reserve", base.HEX, null, 0xC000)
fds3.jt808_msg_attr_flag   = ProtoField.uint16("jt808.msg_attr.flag", "Flag", base.HEX, null, 0x2000)
fds3.jt808_msg_attr_secure = ProtoField.uint16("jt808.msg_attr.reserve", "Secure", base.HEX, null, 0x1C00)
fds3.jt808_msg_attr_length = ProtoField.uint16("jt808.msg_attr.reserve", "Length", base.HEX, null, 0x03FF)
fds3.terminal_phone_number = ProtoField.new("Terminal Phone Number", "jt808.terminal_phone_number", ftypes.STRING)
fds3.msg_seq = ProtoField.uint16("jt808.seq", "Msg Sequences", base.HEX, null)

fds3.jt808_crc = ProtoField.uint8("jt808.crc", "CRC", base.HEX, null)


--------------------------------------------------------
mytable = {}

mytable[0x0001] = {name = "Terminal Common Response", callback = null}

fds3.platform_common_response_seq = ProtoField.new("Response Seq", "jt808.platform_common_response_seq", ftypes.UINT16)
fds3.platform_common_response_id = ProtoField.new("Response Id", "jt808.platform_common_response_id", ftypes.UINT16)
fds3.platform_common_response_result = ProtoField.new("Result", "jt808.platform_common_response_result", ftypes.STRING)
function dissect_platform_common_response_8001(buffer, offset, subtree)
    data, len = get_two_bytes(buffer, offset)
    subtree:add(fds3.platform_common_response_seq, buffer(offset, len), tostring(data))
    offset = offset + len

    data, len = get_two_bytes(buffer, offset)
    subtree:add(fds3.platform_common_response_id, buffer(offset, len), tostring(data))
    offset = offset + len

    data, len = get_one_byte(buffer, offset)
    if data == 0x0 then
        info = "success"
    elseif data == 0x01 then
        info = "failure"
    elseif data == 0x02 then
        info = "msg error"
    elseif data == 0x03 then
        info = "not support"
    elseif data == 0x04 then
        info = "warnging ack"
    else
        info = "unkwon"
    end
    info = info .. " (" .. tostring(data) .. ")"

    subtree:add(fds3.platform_common_response_result, buffer(offset, len), info)
    offset = offset + len
    return offset
end
mytable[0x8001] = {name = "Platform Common Response", callback = dissect_platform_common_response_8001}

mytable[0x0002] = {name = "Ternimal Heartbeat", callback = null}
mytable[0x0003] = {name = "Terminal Logout", callback = null}
mytable[0x0004] = {name = "Server Time Request", callback = null}
mytable[0x8004] = {name = "Server Time Respone", callback = null}
mytable[0x8003] = {name = "Server Send Package Request", callback=null}
mytable[0x0005] = {name = "Ternimal Send Package Request", callback=null}
mytable[0x0100] = {name = "Ternimal Register Request", callback=null}
mytable[0x8100] = {name = "Ternimal Register Response", callback=null}
mytable[0x0102] = {name = "Terminal Auth", callback=null}
mytable[0x8103] = {name = "Terminal Param Set", callback=null}
mytable[0x8104] = {name = "Terminal Param Request", callback=null}
mytable[0x0104] = {name = "Terminal Param Response", callback=null}
mytable[0x8105] = {name = "Terminal Control", callback=null}
mytable[0x8106] = {name = "Terminal Sepc Param Search", callback=null}
mytable[0x8107] = {name = "Terminal Attr Request", callback=null}
mytable[0x0107] = {name = "Terminal Attr Response", callback=null}
mytable[0x8108] = {name = "Push Down Upgrade Package", callback=null}
mytable[0x0108] = {name = "Terminal Upgrade Result", callback=null}
mytable[0x0200] = {name = "Location Info", callback=null}
mytable[0x8201] = {name = "Location Search Request", callback=null}
mytable[0x0201] = {name = "Location Search Response", callback=null}
mytable[0x8202] = {name = "Temp Location Control", callback=null}
mytable[0x8203] = {name = "Ack Call To Police", callback=null}
mytable[0x8204] = {name = "Link Check", callback=null}


fds3.down_text_flag = ProtoField.uint8("jt808.down_text_flag", "Flag", base.HEX, null)
local down_text_flag_value = {
    [0] = "[Unkown]",
    [1] = "[Service]",
    [2] = "[Emergency]",
    [3] = "[Notify]"
}
fds3.down_text_flag_resv   = ProtoField.uint8("jt808.down_text_flag.type", "Type", base.HEX, down_text_flag_value, 0x03)
fds3.down_text_flag_terminal_display   = ProtoField.uint8("jt808.down_text_flag.terminal_display", "Terminal Display", base.HEX, null, 0x04)
fds3.down_text_flag_tts = ProtoField.uint8("jt808.down_text_flag.tts", "TTS", base.HEX, null, 0x08)
fds3.down_text_flag_reserve = ProtoField.uint8("jt808.down_text_flag.reserve", "Reserve", base.HEX, null, 0x10)
local down_text_info_type_value = {
    [0] = "[Central Navigation Info]",
    [1] = "[Fault Info Code]"
}
fds3.down_text_flag_info_type = ProtoField.uint8("jt808.down_text_flag.info_type", "Info Type", base.HEX, down_text_info_type_value, 0x20)
fds3.down_text_flag_reserve2 = ProtoField.uint8("jt808.down_text_flag.reserve2", "Reserve", base.HEX, null, 0xC0)
fds3.down_text_type = ProtoField.new("Down Text Type", "jt808.down_text_type", ftypes.STRING)
fds3.down_text_content = ProtoField.new("Down Text Content", "jt808.down_text_content", ftypes.STRING)
function dissect_down_text_8300(buffer, offset, subtree)
    data, len = get_one_byte(buffer, offset)
    local flag_subtree =subtree:add(fds3.down_text_flag, buffer(offset, len), tostring(data))
    flag_subtree:add(fds3.down_text_flag_reserve2, buffer(offset, len))
    flag_subtree:add(fds3.down_text_flag_info_type, buffer(offset, len))
    flag_subtree:add(fds3.down_text_flag_reserve, buffer(offset, len))
    flag_subtree:add(fds3.down_text_flag_tts, buffer(offset, len))
    flag_subtree:add(fds3.down_text_flag_terminal_display, buffer(offset, len))
    flag_subtree:add(fds3.down_text_flag_resv, buffer(offset, len))
    offset = offset + len

    data, len = get_one_byte(buffer, offset)
    if data == 0x01 then
        info = "Notify"
    elseif data == 0x02 then
        info = "Service"
    end
    subtree:add(fds3.down_text_type, buffer(offset, len), info)
    offset = offset + len

    return offset
end
mytable[0x8300] = {name = "Down Text Info", callback=dissect_down_text_8300}

mytable[0x8400] = {name = "Back To Dial", callback=null}
mytable[0x8401] = {name = "Phone Book Setting", callback=null}
mytable[0x8500] = {name = "Car Control", callback=null}
mytable[0x0500] = {name = "Car Control Response", callback=null}
mytable[0x8600] = {name = "Circular Area Setting", callback=null}
mytable[0x8601] = {name = "Circular Area Delete", callback=null}
mytable[0x8602] = {name = "Rectangular Area Setting", callback=null}
mytable[0x8603] = {name = "Rectangular Area Delete", callback=null}
mytable[0x8604] = {name = "Polygon Area Setting", callback=null}
mytable[0x8605] = {name = "Polygon Area Delete", callback=null}
mytable[0x8606] = {name = "Route Setting", callback=null}
mytable[0x8607] = {name = "Route Delete", callback=null}
mytable[0x8608] = {name = "Area/Route Search Request", callback=null}
mytable[0x0608] = {name = "Area/Route Search Respone", callback=null}
--------------------------------------------------------

--[[
fds3.application_protocol = ProtoField.new("Application Protocol", "hep3.application_protocol", ftypes.STRING)
fds3.source_ipv4_address = ProtoField.new("Source IPv4 address", "hep3.source_ipv4_address", ftypes.IPv4)
fds3.destination_ipv4_address = ProtoField.new("Destination IPv4 address", "hep3.destination_ipv4_address", ftypes.IPv4)
fds3.source_ipv6_address = ProtoField.new("Source IPv6 address", "hep3.source_ipv6_address", ftypes.IPv6)
fds3.destination_ipv6_address = ProtoField.new("Destination IPv6 address", "hep3.destination_ipv6_address", ftypes.IPv6)

fds3.group_id = ProtoField.new("Group ID", "hep3.group_id", ftypes.STRING)
fds3.source_mac = ProtoField.new("Source MAC address", "hep3.source_mac", ftypes.STRING) -- .ETHER
fds3.destination_mac = ProtoField.new("Destination MAC address", "hep3.destination_mac", ftypes.STRING) -- .ETHER
fds3.ethernet_type = ProtoField.new("Ethernet Type", "hep3.ethernet_type", ftypes.UINT16)
fds3.ip_TOS = ProtoField.new("IP TOS", "hep3.ip_TOS", ftypes.UINT8)
fds3.tcp_flags = ProtoField.new("TCP Flags", "hep3.tcp_flags", ftypes.UINT8)
fds3.source_port = ProtoField.new("Source port", "hep3.source_port", ftypes.UINT16)
fds3.destination_port = ProtoField.new("Destination port", "hep3.destination_port", ftypes.UINT16)
fds3.mos = ProtoField.new("MOS", "hep3.mos", ftypes.UINT16)
fds3.timestamp_unix = ProtoField.new("Unix Timestamp", "hep3.timestamp_unix", ftypes.UINT32)
fds3.timestamp_microsec = ProtoField.new("Timestamp µs", "hep3.timestamp_microsec", ftypes.UINT32)
fds3.capture_node_id = ProtoField.new("Capture Node ID", "hep3.capture_node_id", ftypes.UINT32)
fds3.auth_key = ProtoField.new("Authentication Key", "hep3.auth_key", ftypes.STRING)
fds3.correlation_id = ProtoField.new("Correlation ID", "hep3.correlation_id", ftypes.STRING)
fds3.payload = ProtoField.new("Encapsulated Payload", "hep3.payload", ftypes.STRING)
fds3.vendor_id = ProtoField.new("Vendor ID", "hep3.vendor_id", ftypes.UINT16)
--]]

-------------------------------parse function-------------------------------------------------

function get_one_byte(buffer, offset)
    return buffer(offset, ONEOCTET):uint(), ONEOCTET
end

function get_two_bytes(buffer, offset)
    return buffer(offset, TWOOCTETS):uint(), TWOOCTETS
end

function get_four_bytes(buffer, offset)
    return buffer(offset, FOUROCTETS):uint(), FOUROCTETS
end

function get_six_bytes(buffer, offset)
    return buffer(offset, SIXOCTETS):bytes(), SIXOCTETS
end

function get_more_bytes(buffer, offset, length)

end

-- flag = 7e
function get_flag(buffer, offset, subtree)
    data, len = get_one_byte(buffer, offset)
    subtree:add(fds3.jt808_flag, buffer(offset, len), tostring(data))
    return offset + len
end

function get_msg_type(buffer, offset, pinfo, subtree)
    type,len = get_two_bytes(buffer, offset)
    t = mytable[type]
    if t == null then
        info = "unkown"
    else
        info = t.name
    end
    pinfo.cols.info = info
    info = info .. " (" .. string.format("0x%02x", type) .. ")"
    subtree:add(fds3.jt808_msg_type, buffer(offset, len), info)
    return offset + len, type
end

function get_msg_attr(buffer, offset, subtree)
    data, len = get_two_bytes(buffer, offset)
    local msg_attr_subtree =subtree:add(fds3.jt808_msg_attr, buffer(offset, len), tostring(data))
    msg_attr_subtree:add(fds3.jt808_msg_attr_resv, buffer(offset, len))
    msg_attr_subtree:add(fds3.jt808_msg_attr_flag, buffer(offset, len))
    msg_attr_subtree:add(fds3.jt808_msg_attr_secure, buffer(offset, len))
    msg_attr_subtree:add(fds3.jt808_msg_attr_length, buffer(offset, len))
    return offset + len, bit32.band(data, 0x03FF)
end

function get_terminal_phone_number(buffer, offset, subtree)
    data, len = get_six_bytes(buffer, offset)
    subtree:add(fds3.terminal_phone_number, buffer(offset, len), tostring(data))
    return offset + len
end

function get_msg_seq(buffer, offset, subtree)
    data, len = get_two_bytes(buffer, offset)
    subtree:add(fds3.msg_seq, buffer(offset, len), tostring(data))
    return offset + len
end

function get_crc(buffer, offset, subtree)
    data, len = get_one_byte(buffer, offset)
    subtree:add(fds3.jt808_crc, buffer(offset, len), tostring(data))
    return offset + len
end

function dissect_jt808(buffer, offset, subtree, pinfo, tree)
    flag = buffer(offset, ONEOCTET):uint()
    subtree:add(fds3.jt808_flag, buffer(offset, ONEOCTET), flag)

    offset = offset + ONEOCTET
    start_pos = offset
    header_tree = subtree:add(jt808_proto, buffer(offset), "JT808 Header")
    offset, msg_type = get_msg_type(buffer, offset, pinfo, header_tree)
    offset, payload_length = get_msg_attr(buffer, offset, header_tree)
    offset = get_terminal_phone_number(buffer, offset, header_tree)
    offset = get_msg_seq(buffer, offset, header_tree)
    header_tree:set_len(offset - start_pos)

    t = mytable[msg_type]
    if t ~= null and t.callback ~= null then
        body_tree = subtree:add(jt808_proto, buffer(offset, payload_length), "JT808 Body")
        offset = t.callback(buffer, offset, body_tree)
    end
    offset = get_crc(buffer, offset, subtree)
    subtree:add(fds3.jt808_flag, buffer(offset, ONEOCTET), flag)
    -- jt808_flag = buffer(offset, ONEOCTET):uint
    -- subtree:add(fds3.jt808_flag, buffer(offset, ONEOCTET), jt808_flag)
    -- offset = offset + ONEOCTET

--[[
    while current_len < total_len do

      if chunk_type == "00000001" then
        offset = get_ip_family(buffer, offset, subtree)
      elseif chunk_type == "00000002" then
        offset = get_transport_proto_id(buffer, offset, subtree)
      elseif chunk_type == "00000003" then
        offset = get_source_ipv4_address(buffer, offset, subtree)
      elseif chunk_type == "00000004" then
        offset = get_destination_ipv4_address(buffer, offset, subtree)
      elseif chunk_type == "00000005" then
        offset = get_source_ipv6_address(buffer, offset, subtree)
      elseif chunk_type == "00000006" then
        offset = get_destination_ipv6_address(buffer, offset, subtree)
      elseif chunk_type == "00000007" then
        offset = get_source_port(buffer, offset, subtree)
      elseif chunk_type == "00000008" then
        offset = get_destination_port(buffer, offset, subtree)
      elseif chunk_type == "00000009" then
        offset = get_timestamp(buffer, offset, subtree)
      elseif chunk_type == "0000000a" then
        offset = get_timestamp_microsec(buffer, offset, subtree)
      elseif chunk_type == "0000000b" then
        offset, application_protocol = get_application_protocol(buffer, offset, subtree)
      elseif chunk_type == "0000000c" then
        offset = get_capture_node_id(buffer, offset, subtree)
      elseif chunk_type == "0000000e" then
        offset = get_auth_key(buffer, offset, subtree)
      elseif chunk_type == "0000000f" then
        offset = determine_payload_content(buffer, offset, subtree, pinfo, tree, application_protocol)
      elseif chunk_type == "00000010" then
        -- compressed payload. Treat as normal payload
        -- https://github.com/sipcapture/hep-wireshark/issues/5
        offset = determine_payload_content(buffer, offset, subtree, pinfo, tree, application_protocol)
      elseif chunk_type == "00000011" then
        offset = get_correlation_id(buffer, offset, subtree)
      elseif chunk_type == "00000012" then
        offset = get_vlan_id(buffer, offset, subtree)
      elseif chunk_type == "00000013" then
        offset = get_group_id(buffer, offset, subtree)
      elseif chunk_type == "00000014" then
        offset = get_source_mac(buffer, offset, subtree)
      elseif chunk_type == "00000015" then
        offset = get_destination_mac(buffer, offset, subtree)
      elseif chunk_type == "00000016" then
        offset = get_ethernet_type(buffer, offset, subtree)
      elseif chunk_type == "00000017" then
        offset = get_tcp_flags(buffer, offset, subtree)
      elseif chunk_type == "00000018" then
        offset = get_ip_TOS(buffer, offset, subtree)
      elseif chunk_type == "00000020" then
        offset = get_mos(buffer, offset, subtree)			
      else
        -- proceed unknown chunk
          if (offset < (total_len - 1)) then
          offset = skip_unknown_chunk(buffer, offset)
          end                              
      end
  
      if (offset < (total_len - 1)) then
        chunk_type = get_chunk_data(buffer, offset)
      end
    end -- while
--]]

end

function jt808_proto_dissector(buffer, pinfo, tree)
    local subtree = tree:add(jt808_proto, buffer(), "JT808 Protocol")
    dissect_jt808(buffer, offset, subtree, pinfo, tree)
end


function jt808_decoding(buffer)
    data_string = "7e"
    i = 1
    while i < buffer:len() - 1 do
        if buffer(i, 1):uint() == 0x7d and buffer(i+1, 1):uint() == 0x01 then
            data_string = data_string .. "7d"
            i = i + 1
        elseif buffer(i, 1):uint() == 0x7d and buffer(i+1, 1):uint() == 0x02 then
            data_string = data_string .. "7e"
            i = i + 1
        else
            data_string = data_string .. string.format("%02x", buffer(i, 1):uint())
        end
        i = i + 1
    end
    data_string = data_string .. "7e"
    return ByteArray.tvb(ByteArray.new(data_string), "new-data-buffer")
end

function jt808_proto.dissector(buffer, pinfo, tree)
    offset = 0
    flag = buffer(offset, ONEOCTET):uint()
    
    if (flag == 0x7e) then
        pinfo.cols.protocol = "JT808"
        data = jt808_decoding(buffer)
        jt808_proto_dissector(data, pinfo, tree)
        return
    end
    
end


tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(1983, jt808_proto)



