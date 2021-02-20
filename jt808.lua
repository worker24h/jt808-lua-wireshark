
require "bit32"


SIXOCTETS = 6
FOUROCTETS = 4
TWOOCTETS = 2
ONEOCTET = 1
CRC_TOKEN_LEN = 2

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


----------------------------table function----------------------------
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

fds3.terminal_reg_province_id = ProtoField.uint16("jt808.terminal_reg_province_id", "Province", base.HEX, null)
fds3.terminal_reg_city_id = ProtoField.uint16("jt808.terminal_reg_city_id", "City", base.HEX, null)
fds3.terminal_reg_vendor = ProtoField.new("Vendor Info", "jt808.terminal_reg_vendor", ftypes.STRING)
fds3.terminal_reg_terminal_model = ProtoField.new("Terminal Model", "jt808.terminal_reg_terminal_model", ftypes.STRING)
fds3.terminal_reg_terminal_id = ProtoField.new("Terminal Id", "jt808.terminal_reg_terminal_id", ftypes.STRING)
-- 车牌颜色
local color = {
  [0] = "[unkown]",
  [1] = "[蓝色]",
  [2] = "[黄色]",
  [3] = "[黑色]",
  [4] = "[白色]",
  [9] = "[其他]",
}
fds3.terminal_reg_terminal_color = ProtoField.uint8("jt808.terminal_reg_terminal_id", "Color", base.HEX, color, null)
fds3.terminal_reg_terminal_number = ProtoField.new("Number", "jt808.terminal_reg_terminal_id", ftypes.STRING)
fds3.terminal_reg_terminal_vehicle_id = ProtoField.new("VehicleId", "jt808.terminal_reg_terminal_vehicle_id", ftypes.STRING)

function dissect_terminal_register_0100(buffer, offset, subtree)
  data, len = get_two_bytes(buffer, offset)
  subtree:add(fds3.terminal_reg_province_id, buffer(offset, len), tostring(data))
  offset = offset + len

  data, len = get_two_bytes(buffer, offset)
  subtree:add(fds3.terminal_reg_city_id, buffer(offset, len), tostring(data))
  offset = offset + len

  data, len = get_more_bytes(buffer, offset, 5)
  subtree:add(fds3.terminal_reg_vendor, buffer(offset, len), tostring(data))
  offset = offset + len

  data, len = get_string(buffer, offset, 20)
  subtree:add(fds3.terminal_reg_terminal_model, buffer(offset, len), data)
  offset = offset + len

  data, len = get_string(buffer, offset, 7)
  subtree:add(fds3.terminal_reg_terminal_id, buffer(offset, len), data)
  offset = offset + len

  data, len = get_one_byte(buffer, offset)
  -- flag_subtree:add(fds3.down_text_flag_reserve2, buffer(offset, len))

  subtree:add(fds3.terminal_reg_terminal_color, buffer(offset, len))
  offset = offset + len

  vehicleId_len = buffer:len() - offset - CRC_TOKEN_LEN
  data, len = get_string(buffer, offset, vehicleId_len)
  subtree:add(fds3.terminal_reg_terminal_vehicle_id, buffer(offset, len), data)
  offset = offset + len

  return offset
end
mytable[0x0100] = {name = "Ternimal Register Request", callback=dissect_terminal_register_0100}

fds3.terminal_reg_response_seq = ProtoField.uint16("jt808.terminal_reg_response_seq", "Seq", base.HEX, null)
local reg_result = {
  [0] = "[成功]",
  [1] = "[车辆已被注册]",
  [2] = "[数据库中无该车辆]",
  [3] = "[终端已经被注册]",
  [4] = "[数据库中无该终端]",
}
fds3.terminal_reg_response_result = ProtoField.uint8("jt808.terminal_reg_response_result", "Result", base.HEX, reg_result, null)
fds3.terminal_reg_response_authcode = ProtoField.new("AuthCode", "jt808.terminal_reg_response_authcode", ftypes.STRING)
function dissect_terminal_register_8100(buffer, offset, subtree)

  subtree:add(fds3.terminal_reg_response_seq, buffer(offset, 2))
  offset = offset + 2

  subtree:add(fds3.terminal_reg_response_result, buffer(offset, 1))
  offset = offset + 1

  authcode_len = buffer:len() - offset - CRC_TOKEN_LEN
  data, len = get_string(buffer, offset, authcode_len)
  subtree:add(fds3.terminal_reg_response_authcode, buffer(offset, len), data)
  offset = offset + len

  return offset
end
mytable[0x8100] = {name = "Ternimal Register Response", callback=dissect_terminal_register_8100}

fds3.terminal_authcode = ProtoField.new("AuthCode", "jt808.terminal_authcode", ftypes.STRING)
function dissect_terminal_authcode_0102(buffer, offset, subtree)

  authcode_len = buffer:len() - offset - CRC_TOKEN_LEN
  data, len = get_string(buffer, offset, authcode_len)
  subtree:add(fds3.terminal_authcode, buffer(offset, len), data)
  offset = offset + len

  return offset
end
mytable[0x0102] = {name = "Terminal Auth", callback=dissect_terminal_authcode_0102}
mytable[0x8103] = {name = "Terminal Param Set", callback=null}
mytable[0x8104] = {name = "Terminal Param Request", callback=null}
mytable[0x0104] = {name = "Terminal Param Response", callback=null}
mytable[0x8105] = {name = "Terminal Control", callback=null}
mytable[0x8106] = {name = "Terminal Sepc Param Search", callback=null}
mytable[0x8107] = {name = "Terminal Attr Request", callback=null}
mytable[0x0107] = {name = "Terminal Attr Response", callback=null}
mytable[0x8108] = {name = "Push Down Upgrade Package", callback=null}
mytable[0x0108] = {name = "Terminal Upgrade Result", callback=null}

-- 位置基本信息
fds3.location_basic_warning = ProtoField.uint32("jt808.location_basic_warning", "Warning", base.HEX, null)
local warnging0 = {
  [0] = "",
  [1] = "[紧急报警]"
}
fds3.location_basic_warning0 = ProtoField.uint32("jt808.location_basic_warning0", "Warning", base.HEX, warnging0, 0x80000000)

local warnging1 = {
  [0] = "",
  [1] = "[超速报警]"
}
fds3.location_basic_warning1 = ProtoField.uint32("jt808.location_basic_warning1", "Warning", base.HEX, warnging1, 0x40000000)

local warnging2 = {
  [0] = "",
  [1] = "[疲劳驾驶报警]"
}
fds3.location_basic_warning2 = ProtoField.uint32("jt808.location_basic_warning2", "Warning", base.HEX, warnging2, 0x20000000)

local warnging3 = {
  [0] = "",
  [1] = "[危险驾驶行为报警]"
}
fds3.location_basic_warning3 = ProtoField.uint32("jt808.location_basic_warning3", "Warning", base.HEX, warnging3, 0x10000000)

local warnging4 = {
  [0] = "",
  [1] = "[GNSS模块发生故障报警]"
}
fds3.location_basic_warning4 = ProtoField.uint32("jt808.location_basic_warning4", "Warning", base.HEX, warnging4, 0x08000000)

local warnging5 = {
  [0] = "",
  [1] = "[GNSS天线未接或被剪断报警]"
}
fds3.location_basic_warning5 = ProtoField.uint32("jt808.location_basic_warning5", "Warning", base.HEX, warnging5, 0x04000000)

local warnging6 = {
  [0] = "",
  [1] = "[GNSS天线短路报警]"
}
fds3.location_basic_warning6 = ProtoField.uint32("jt808.location_basic_warning6", "Warning", base.HEX, warnging6, 0x02000000)

local warnging7 = {
  [0] = "",
  [1] = "[终端主电源欠压报警]"
}
fds3.location_basic_warning7 = ProtoField.uint32("jt808.location_basic_warning7", "Warning", base.HEX, warnging7, 0x01000000)

local warnging8 = {
  [0] = "",
  [1] = "[终端主电源掉电报警]"
}

fds3.location_basic_warning8 = ProtoField.uint32("jt808.location_basic_warning8", "Warning", base.HEX, warnging8, 0x00800000)

local warnging9 = {
  [0] = "",
  [1] = "[终端LCD或显示器故障报警]"
}
fds3.location_basic_warning9 = ProtoField.uint32("jt808.location_basic_warning9", "Warning", base.HEX, warnging9, 0x00400000)

local warnging10 = {
  [0] = "",
  [1] = "[TTS模块故障报警]"
}
fds3.location_basic_warning10 = ProtoField.uint32("jt808.location_basic_warning10", "Warning", base.HEX, warnging10, 0x00200000)

local warnging11 = {
  [0] = "",
  [1] = "[摄像头故障报警]"
}
fds3.location_basic_warning11 = ProtoField.uint32("jt808.location_basic_warning11", "Warning", base.HEX, warnging11, 0x00100000)

local warnging12 = {
  [0] = "",
  [1] = "[道路运输证IC卡模块故障报警]"
}
fds3.location_basic_warning12 = ProtoField.uint32("jt808.location_basic_warning12", "Warning", base.HEX, warnging12, 0x00080000)

local warnging13 = {
  [0] = "",
  [1] = "[超速预警]"
}
fds3.location_basic_warning13 = ProtoField.uint32("jt808.location_basic_warning13", "Warning", base.HEX, warnging13, 0x00040000)

local warnging14 = {
  [0] = "",
  [1] = "[疲劳驾驶预警]"
}
fds3.location_basic_warning14 = ProtoField.uint32("jt808.location_basic_warning14", "Warning", base.HEX, warnging14, 0x00020000)

local warnging15 = {
  [0] = "",
  [1] = "[违规行驶报警]"
}
fds3.location_basic_warning15 = ProtoField.uint32("jt808.location_basic_warning15", "Warning", base.HEX, warnging15, 0x00010000)

local warnging16 = {
  [0] = "",
  [1] = "[胎压预警]"
}
fds3.location_basic_warning16 = ProtoField.uint32("jt808.location_basic_warning16", "Warning", base.HEX, warnging16, 0x00008000)

local warnging17 = {
  [0] = "",
  [1] = "[右转盲区异常报警]"
}
fds3.location_basic_warning17 = ProtoField.uint32("jt808.location_basic_warning17", "Warning", base.HEX, warnging17, 0x00004000)

local warnging18 = {
  [0] = "",
  [1] = "[当天累计驾驶超时报警]"
}
fds3.location_basic_warning18 = ProtoField.uint32("jt808.location_basic_warning18", "Warning", base.HEX, warnging18, 0x00002000)

local warnging19 = {
  [0] = "",
  [1] = "[超时停车报警]"
}
fds3.location_basic_warning19 = ProtoField.uint32("jt808.location_basic_warning19", "Warning", base.HEX, warnging19, 0x00001000)

local warnging20 = {
  [0] = "",
  [1] = "[进出区域报警]"
}
fds3.location_basic_warning20 = ProtoField.uint32("jt808.location_basic_warning20", "Warning", base.HEX, warnging20, 0x00000800)
local warnging21 = {
  [0] = "",
  [1] = "[进出路线报警]"
}
fds3.location_basic_warning21 = ProtoField.uint32("jt808.location_basic_warning21", "Warning", base.HEX, warnging21, 0x00000400)
local warnging22 = {
  [0] = "",
  [1] = "[路段行驶时间不足/过长报警]"
}
fds3.location_basic_warning22 = ProtoField.uint32("jt808.location_basic_warning22", "Warning", base.HEX, warnging22, 0x00000200)
local warnging23 = {
  [0] = "",
  [1] = "[路线偏离报警]"
}
fds3.location_basic_warning23 = ProtoField.uint32("jt808.location_basic_warning23", "Warning", base.HEX, warnging23, 0x00000100)
local warnging24 = {
  [0] = "",
  [1] = "[车辆VSS故障]"
}
fds3.location_basic_warning24 = ProtoField.uint32("jt808.location_basic_warning24", "Warning", base.HEX, warnging24, 0x00000080)
local warnging25 = {
  [0] = "",
  [1] = "[车辆油量异常报警]"
}
fds3.location_basic_warning25 = ProtoField.uint32("jt808.location_basic_warning25", "Warning", base.HEX, warnging25, 0x00000040)
local warnging26 = {
  [0] = "",
  [1] = "[车联被盗报警]"
}
fds3.location_basic_warning26 = ProtoField.uint32("jt808.location_basic_warning26", "Warning", base.HEX, warnging26, 0x00000020)
local warnging27 = {
  [0] = "",
  [1] = "[车辆非法点火报警]"
}
fds3.location_basic_warning27 = ProtoField.uint32("jt808.location_basic_warning27", "Warning", base.HEX, warnging27, 0x00000010)
local warnging28 = {
  [0] = "",
  [1] = "[车辆非法位移报警]"
}
fds3.location_basic_warning28 = ProtoField.uint32("jt808.location_basic_warning28", "Warning", base.HEX, warnging28, 0x00000008)
local warnging29 = {
  [0] = "",
  [1] = "[碰撞侧翻报警]"
}
fds3.location_basic_warning29 = ProtoField.uint32("jt808.location_basic_warning29", "Warning", base.HEX, warnging29, 0x00000004)
local warnging30 = {
  [0] = "",
  [1] = "[侧翻预警]"
}
fds3.location_basic_warning30 = ProtoField.uint32("jt808.location_basic_warning30", "Warning", base.HEX, warnging30, 0x00000002)
local warnging31 = {
  [0] = "[Resv]",
  [1] = "[Resv]"
}
fds3.location_basic_warning31 = ProtoField.uint32("jt808.location_basic_warning31", "Warning", base.HEX, warnging31, 0x00000001)


fds3.location_basic_status = ProtoField.uint32("jt808.location_basic_status", "Status", base.HEX, null)

local status0 = {
  [0] = "[ACC关闭]",
  [1] = "[ACC开启]"
}
fds3.location_basic_status0 = ProtoField.uint32("jt808.location_basic_status0", "Acc", base.HEX, status0, 0x80000000)

local status1 = {
  [0] = "[未定位]",
  [1] = "[定位]"
}
fds3.location_basic_status1 = ProtoField.uint32("jt808.location_basic_status1", "Location", base.HEX, status1, 0x40000000)

local status2 = {
  [0] = "[北纬]]",
  [1] = "[南纬]"
}
fds3.location_basic_status2 = ProtoField.uint32("jt808.location_basic_status2", "Latitude", base.HEX, status2, 0x20000000)

local status3 = {
  [0] = "[东经]",
  [1] = "[西经]"
}
fds3.location_basic_status3 = ProtoField.uint32("jt808.location_basic_status3", "Longitude", base.HEX, status3, 0x10000000)

local status4 = {
  [0] = "[运营]",
  [1] = "[未运营]]"
}
fds3.location_basic_status4 = ProtoField.uint32("jt808.location_basic_status4", "Operating", base.HEX, status4, 0x08000000)

local status5 = {
  [0] = "[经纬度未加密]",
  [1] = "[经纬度加密]"
}
fds3.location_basic_status5 = ProtoField.uint32("jt808.location_basic_status5", "Encrypted", base.HEX, status5, 0x04000000)

local status6 = {
  [0] = "",
  [1] = "[紧急刹车系统采集的前撞预警]"
}
fds3.location_basic_status6 = ProtoField.uint32("jt808.location_basic_status6", "Status", base.HEX, status6, 0x02000000)

local status7 = {
  [0] = "",
  [1] = "[车道偏移预警]"
}
fds3.location_basic_status7 = ProtoField.uint32("jt808.location_basic_status7", "Status", base.HEX, status7, 0x01000000)

local status8_9 = {
  [00] = "[空车]",
  [01] = "[半载]",
  [10] = "[Resv]",
  [11] = "[满载]"
}
fds3.location_basic_status8_9 = ProtoField.uint32("jt808.location_basic_status8_9", "Reserve", base.HEX, status8_9, 0x00C00000)

local status10 = {
  [0] = "[车辆油路正常]",
  [1] = "[车辆油路断开]"
}
fds3.location_basic_status10 = ProtoField.uint32("jt808.location_basic_status10", "Oil", base.HEX, status10, 0x00200000)

local status11 = {
  [0] = "[车辆电路正常]",
  [1] = "[车辆电路断开]"
}
fds3.location_basic_status11 = ProtoField.uint32("jt808.location_basic_status11", "Circuit", base.HEX, status11, 0x00100000)

local status12 = {
  [0] = "[车门解锁]",
  [1] = "[车门加锁]"
}
fds3.location_basic_status12 = ProtoField.uint32("jt808.location_basic_status12", "DoorLock", base.HEX, status12, 0x00080000)

local status13 = {
  [0] = "[门1关]",
  [1] = "[门1开]"
}
fds3.location_basic_status13 = ProtoField.uint32("jt808.location_basic_status13", "Door1", base.HEX, status13, 0x00040000)

local status14 = {
  [0] = "[门2关]",
  [1] = "[门2开]"
}
fds3.location_basic_status14 = ProtoField.uint32("jt808.location_basic_status14", "Door2", base.HEX, status14, 0x00020000)

local status15 = {
  [0] = "[门3关]",
  [1] = "[门3开]"
}
fds3.location_basic_status15 = ProtoField.uint32("jt808.location_basic_status15", "Door3", base.HEX, status15, 0x00010000)

local status16 = {
  [0] = "[门4关]",
  [1] = "[门4开]"
}
fds3.location_basic_status16 = ProtoField.uint32("jt808.location_basic_status16", "Door4", base.HEX, status16, 0x00008000)

local status17 = {
  [0] = "[门5关]",
  [1] = "[门5开]"
}
fds3.location_basic_status17 = ProtoField.uint32("jt808.location_basic_status17", "Door5", base.HEX, status17, 0x00004000)

local status18 = {
  [0] = "[未使用GPS卫星进行定位]",
  [1] = "[使用GPS卫星进行定位]"
}
fds3.location_basic_status18 = ProtoField.uint32("jt808.location_basic_status18", "GPS", base.HEX, status18, 0x00002000)

local status19 = {
  [0] = "[未使用北斗卫星进行定位]",
  [1] = "[使用北斗卫星进行定位]"
}
fds3.location_basic_status19 = ProtoField.uint32("jt808.location_basic_status19", "BeiDou", base.HEX, status19, 0x00001000)

local status20 = {
  [0] = "[未使用GLONASS卫星进行定位]",
  [1] = "[使用GLONASS卫星进行定位]"
}
fds3.location_basic_status20 = ProtoField.uint32("jt808.location_basic_status20", "GLONASS", base.HEX, status20, 0x00000800)

local status21 = {
  [0] = "[未使用Galileo卫星进行定位]",
  [1] = "[使用Galileo卫星进行定位]"
}
fds3.location_basic_status21 = ProtoField.uint32("jt808.location_basic_status21", "Galileo", base.HEX, status21, 0x00000400)

local status22 = {
  [0] = "[车辆处于停止状态]",
  [1] = "[车辆处于行驶状态]"
}
fds3.location_basic_status22 = ProtoField.uint32("jt808.location_basic_status22", "Status", base.HEX, status22, 0x00000200)

local status_others = {
  [0] = "[RESV]",
  [1] = "[RESV]"
}
fds3.location_basic_status_others = ProtoField.uint32("jt808.location_basic_status_others", "Resv", base.HEX, status_others, 0x000001FF)

-- 纬度
fds3.location_basic_latitude = ProtoField.new("Latitude", "jt808.location_basic_latitude", ftypes.UINT32)
-- 经度
fds3.location_basic_longitude = ProtoField.new("Longitude", "jt808.location_basic_longitude", ftypes.UINT32)
-- 海拔
fds3.location_basic_altitude = ProtoField.new("Altitude", "jt808.location_basic_altitude", ftypes.UINT16)

fds3.location_basic_speed = ProtoField.new("Speed", "jt808.location_basic_speed", ftypes.UINT16)
fds3.location_basic_direction = ProtoField.new("Direction", "jt808.location_basic_direction", ftypes.UINT16)
fds3.location_time = ProtoField.new("Date", "jt808.location_date", ftypes.STRING)
-- 位置扩展信息

function dissect_location_info_0200(buffer, offset, subtree)
  data, len = get_four_bytes(buffer, offset)
  local location_warning_subtree = subtree:add(fds3.location_basic_warning, buffer(offset, len), tostring(data))
  location_warning_subtree:add(fds3.location_basic_warning0, buffer(offset, len))
  location_warning_subtree:add(fds3.location_basic_warning1, buffer(offset, len))
  location_warning_subtree:add(fds3.location_basic_warning2, buffer(offset, len))
  location_warning_subtree:add(fds3.location_basic_warning3, buffer(offset, len))
  location_warning_subtree:add(fds3.location_basic_warning4, buffer(offset, len))
  location_warning_subtree:add(fds3.location_basic_warning5, buffer(offset, len))
  location_warning_subtree:add(fds3.location_basic_warning6, buffer(offset, len))
  location_warning_subtree:add(fds3.location_basic_warning7, buffer(offset, len))
  location_warning_subtree:add(fds3.location_basic_warning8, buffer(offset, len))
  location_warning_subtree:add(fds3.location_basic_warning9, buffer(offset, len))
  location_warning_subtree:add(fds3.location_basic_warning10, buffer(offset, len))
  location_warning_subtree:add(fds3.location_basic_warning11, buffer(offset, len))
  location_warning_subtree:add(fds3.location_basic_warning12, buffer(offset, len))
  location_warning_subtree:add(fds3.location_basic_warning13, buffer(offset, len))
  location_warning_subtree:add(fds3.location_basic_warning14, buffer(offset, len))
  location_warning_subtree:add(fds3.location_basic_warning15, buffer(offset, len))
  location_warning_subtree:add(fds3.location_basic_warning16, buffer(offset, len))
  location_warning_subtree:add(fds3.location_basic_warning17, buffer(offset, len))
  location_warning_subtree:add(fds3.location_basic_warning18, buffer(offset, len))
  location_warning_subtree:add(fds3.location_basic_warning19, buffer(offset, len))
  location_warning_subtree:add(fds3.location_basic_warning20, buffer(offset, len))
  location_warning_subtree:add(fds3.location_basic_warning21, buffer(offset, len))
  location_warning_subtree:add(fds3.location_basic_warning22, buffer(offset, len))
  location_warning_subtree:add(fds3.location_basic_warning23, buffer(offset, len))
  location_warning_subtree:add(fds3.location_basic_warning24, buffer(offset, len))
  location_warning_subtree:add(fds3.location_basic_warning25, buffer(offset, len))
  location_warning_subtree:add(fds3.location_basic_warning26, buffer(offset, len))
  location_warning_subtree:add(fds3.location_basic_warning27, buffer(offset, len))
  location_warning_subtree:add(fds3.location_basic_warning28, buffer(offset, len))
  location_warning_subtree:add(fds3.location_basic_warning29, buffer(offset, len))
  location_warning_subtree:add(fds3.location_basic_warning30, buffer(offset, len))
  location_warning_subtree:add(fds3.location_basic_warning31, buffer(offset, len))
  offset = offset + len


  data, len = get_four_bytes(buffer, offset)
  local location_status_subtree = subtree:add(fds3.location_basic_status, buffer(offset, len), tostring(data))
  location_status_subtree:add(fds3.location_basic_status0, buffer(offset, len))
  location_status_subtree:add(fds3.location_basic_status1, buffer(offset, len))
  location_status_subtree:add(fds3.location_basic_status2, buffer(offset, len))
  location_status_subtree:add(fds3.location_basic_status3, buffer(offset, len))
  location_status_subtree:add(fds3.location_basic_status4, buffer(offset, len))
  location_status_subtree:add(fds3.location_basic_status5, buffer(offset, len))
  location_status_subtree:add(fds3.location_basic_status6, buffer(offset, len))
  location_status_subtree:add(fds3.location_basic_status7, buffer(offset, len))
  location_status_subtree:add(fds3.location_basic_status8_9, buffer(offset, len))
  location_status_subtree:add(fds3.location_basic_status10, buffer(offset, len))
  location_status_subtree:add(fds3.location_basic_status11, buffer(offset, len))
  location_status_subtree:add(fds3.location_basic_status12, buffer(offset, len))
  location_status_subtree:add(fds3.location_basic_status13, buffer(offset, len))
  location_status_subtree:add(fds3.location_basic_status14, buffer(offset, len))
  location_status_subtree:add(fds3.location_basic_status15, buffer(offset, len))
  location_status_subtree:add(fds3.location_basic_status16, buffer(offset, len))
  location_status_subtree:add(fds3.location_basic_status17, buffer(offset, len))
  location_status_subtree:add(fds3.location_basic_status18, buffer(offset, len))
  location_status_subtree:add(fds3.location_basic_status19, buffer(offset, len))
  location_status_subtree:add(fds3.location_basic_status20, buffer(offset, len))
  location_status_subtree:add(fds3.location_basic_status21, buffer(offset, len))
  location_status_subtree:add(fds3.location_basic_status22, buffer(offset, len))
  location_status_subtree:add(fds3.location_basic_status_others, buffer(offset, len))
  offset = offset + len

  data, len = get_four_bytes(buffer, offset)
  subtree:add(fds3.location_basic_latitude, buffer(offset, len))
  offset = offset + len

  data, len = get_four_bytes(buffer, offset)
  subtree:add(fds3.location_basic_longitude, buffer(offset, len))
  offset = offset + len

  data, len = get_two_bytes(buffer, offset)
  subtree:add(fds3.location_basic_altitude, buffer(offset, len))
  offset = offset + len

  data, len = get_two_bytes(buffer, offset)
  subtree:add(fds3.location_basic_speed, buffer(offset, len))
  offset = offset + len

  data, len = get_two_bytes(buffer, offset)
  subtree:add(fds3.location_basic_direction, buffer(offset, len))
  offset = offset + len

  data, len = get_six_bytes(buffer, offset)
  subtree:add(fds3.location_time, buffer(offset, len), tostring(data))
  offset = offset + len

  return offset
end
mytable[0x0200] = {name = "Location Info", callback=dissect_location_info_0200}

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
    else
        info = "Unkown"
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
  return buffer(offset, length):bytes(), length
end

function get_string(buffer, offset, length)
  return buffer(offset, length):string(), length
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
-- You can add other tcp port 
-- tcp_table:add(XXXX, jt808_proto)

udp_table = DissectorTable.get("udp.port")
udp_table:add(1983, jt808_proto)
-- You can add other udp port 
-- udp_table:add(XXXX, jt808_proto)
