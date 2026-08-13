-- PN532 RFID reader for Lilka (13.56 MHz / MIFARE) over I2C.
-- Step 1: just read and show the tag UID.
-- Wiring PN532 in I2C mode (DIP switches set to I2C):
--   Lilka 3.3V -> VCC, GND -> GND, SDA -> SDA, SCL -> SCL

local PN532_ADDR = 0x24  -- 7-bit I2C address of PN532
local SDA_PIN = 13       -- Lilka extension header: SDA on pin 13
local SCL_PIN = 12       -- SCL on pin 12 (any free GPIO works for I2C on ESP32-S3)

local BLACK = display.color565(0,   0,   0)
local WHITE = display.color565(255, 255, 255)
local GREEN = display.color565(0,   200, 80)
local CYAN  = display.color565(0,   220, 220)
local GRAY  = display.color565(140, 140, 140)
local AMBER = display.color565(240, 165, 0)

-- Runtime state shown on screen
local device_ok = false        -- PN532 answered GetFirmwareVersion
local fw_text    = ""          -- e.g. "v1.6"
local uid        = nil         -- table of UID bytes
local uid_hex    = ""          -- pretty hex string
local atqa       = nil         -- SENS_RES (2 bytes)
local sak        = nil         -- SEL_RES (1 byte)
local read_count = 0           -- how many successful reads
local last_seen  = 0           -- util.time() of last successful read

-- ---------------------------------------------------------------------------
-- Low-level PN532 frame helpers
-- ---------------------------------------------------------------------------

-- Build and send a command frame. `cmd` is the data bytes (command code + params),
-- TFI (0xD4) is added automatically.
local function write_command(cmd)
    local len = #cmd + 1                         -- +1 for TFI
    local lcs = (0x100 - len) % 0x100            -- length checksum
    local frame = {0x00, 0x00, 0xFF, len, lcs, 0xD4}
    local sum = 0xD4
    for _, b in ipairs(cmd) do
        frame[#frame + 1] = b
        sum = sum + b
    end
    frame[#frame + 1] = (0x100 - (sum % 0x100)) % 0x100  -- data checksum
    frame[#frame + 1] = 0x00                             -- postamble
    i2c.write(PN532_ADDR, frame)
end

-- Every PN532 I2C read starts with a ready-status byte: bit0 = 1 means ready.
local function is_ready()
    local r = i2c.read(PN532_ADDR, 1)
    return r ~= nil and r[1] ~= nil and (r[1] & 0x01) == 1
end

local function wait_ready(timeout_s)
    local t = util.time()
    while util.time() - t < timeout_s do
        if is_ready() then return true end
        util.sleep(0.005)
    end
    return false
end

-- Read `n` data bytes (the leading ready-status byte is stripped).
local function read_bytes(n)
    local r = i2c.read(PN532_ADDR, n + 1)
    if not r then return nil end
    local out = {}
    for i = 2, n + 1 do out[#out + 1] = r[i] or 0 end
    return out
end

-- Locate the 00 00 FF preamble inside a raw response buffer.
local function find_preamble(buf)
    for i = 1, #buf - 2 do
        if buf[i] == 0x00 and buf[i + 1] == 0x00 and buf[i + 2] == 0xFF then
            return i
        end
    end
    return nil
end

-- ---------------------------------------------------------------------------
-- PN532 commands
-- ---------------------------------------------------------------------------

-- GetFirmwareVersion (0x02). Returns "vX.Y" string or nil if no answer.
local function get_firmware()
    write_command({0x02})
    if not wait_ready(0.1) then return nil end
    read_bytes(6)                       -- consume ACK
    if not wait_ready(0.1) then return nil end
    local resp = read_bytes(14)
    if not resp then return nil end
    local s = find_preamble(resp)
    if not s then return nil end
    -- ... D5 03 IC Ver Rev Support
    if resp[s + 5] ~= 0xD5 or resp[s + 6] ~= 0x03 then return nil end
    local ver = resp[s + 8]
    local rev = resp[s + 9]
    return string.format("v%d.%d", ver, rev)
end

-- SAMConfiguration: normal mode, ~1s timeout, use IRQ line = 0x01 (harmless).
local function sam_config()
    write_command({0x14, 0x01, 0x14, 0x01})
    if not wait_ready(0.2) then return false end
    read_bytes(6)                       -- ACK
    if not wait_ready(0.2) then return false end
    read_bytes(10)                      -- response D5 15
    return true
end

-- RFConfiguration -> MaxRetries. Passive activation = 1 attempt, so
-- InListPassiveTarget returns quickly when no card is present (non-blocking feel).
local function set_retries()
    write_command({0x32, 0x05, 0xFF, 0x01, 0x01})
    if not wait_ready(0.2) then return false end
    read_bytes(6)                       -- ACK
    if not wait_ready(0.2) then return false end
    read_bytes(10)                      -- response D5 33
    return true
end

-- InListPassiveTarget (0x4A): MaxTg=1, BrTy=0x00 (106 kbps type A / MIFARE).
-- Returns uid(table), atqa(table[2]), sak(int) on success, or nil.
local function read_passive()
    write_command({0x4A, 0x01, 0x00})
    if not wait_ready(0.1) then return nil end
    read_bytes(6)                       -- ACK
    if not wait_ready(0.25) then return nil end
    local resp = read_bytes(28)
    if not resp then return nil end
    local s = find_preamble(resp)
    if not s then return nil end
    -- ... D5 4B NbTg Tg SENS_RES(2) SEL_RES NFCIDLength NFCID...
    if resp[s + 5] ~= 0xD5 or resp[s + 6] ~= 0x4B then return nil end
    local nbtg = resp[s + 7]
    if not nbtg or nbtg == 0 then return nil end
    local sens = { resp[s + 9], resp[s + 10] }
    local sel  = resp[s + 11]
    local nlen = resp[s + 12]
    if not nlen or nlen == 0 or nlen > 10 then return nil end
    local id = {}
    for i = 1, nlen do
        id[i] = resp[s + 12 + i]
        if id[i] == nil then return nil end
    end
    return id, sens, sel
end

local function to_hex(bytes)
    local parts = {}
    for _, b in ipairs(bytes) do
        parts[#parts + 1] = string.format("%02X", b)
    end
    return table.concat(parts, " ")
end

-- ---------------------------------------------------------------------------
-- Lilka lifecycle
-- ---------------------------------------------------------------------------

function lilka.init()
    i2c.begin(SDA_PIN, SCL_PIN)         -- SDA = 13, SCL = 12 on the header
    fw_text = get_firmware() or ""
    device_ok = fw_text ~= ""
    if device_ok then
        sam_config()
        set_retries()
    end
end

function lilka.update(delta)
    if controller.get_state().b.just_pressed then util.exit() end

    -- Retry detection if the module was not found at start.
    if not device_ok then
        fw_text = get_firmware() or ""
        device_ok = fw_text ~= ""
        if device_ok then
            sam_config()
            set_retries()
        end
        return
    end

    local id, sens, sel = read_passive()
    if id then
        uid       = id
        uid_hex   = to_hex(id)
        atqa      = sens
        sak       = sel
        last_seen = util.time()
        read_count = read_count + 1
    end
end

function lilka.draw()
    local W = display.width
    local H = display.height
    display.fill_screen(BLACK)

    display.set_font("9x15")
    display.set_text_color(WHITE)
    display.set_cursor(10, 24)
    display.print("PN532 RFID")

    display.set_font("6x13")
    display.set_text_color(GRAY)
    display.set_cursor(10, 42)
    if device_ok then
        display.print("Reader " .. fw_text .. "  (13.56 MHz)")
    else
        display.print("Reader not found")
    end

    if not device_ok then
        -- Wiring guide (module in I2C mode!)
        local L = 10
        local R = W // 2 + 10
        display.set_font("6x13")
        display.set_text_color(GRAY)
        display.set_cursor(10, 66)
        display.print("Set PN532 DIP to I2C, wire:")

        display.set_text_color(CYAN)
        display.set_cursor(L, 92)
        display.print("Lilka")
        display.set_cursor(R, 92)
        display.print("PN532")

        display.set_text_color(WHITE)
        local rows = {
            {"3.3V", "VCC"},
            {"GND",  "GND"},
            {"13",  "SDA"},
            {"12",  "SCL"},
        }
        for i, row in ipairs(rows) do
            local y = 92 + i * 18
            display.set_cursor(L, y)
            display.print(row[1])
            display.set_cursor(R, y)
            display.print(row[2])
        end
    elseif uid then
        -- Show the last read UID
        display.set_font("9x15")
        display.set_text_color(GREEN)
        display.set_cursor(10, 74)
        display.print("UID (" .. #uid .. " bytes):")

        -- Big UID; if too long for one line, use a smaller font
        if #uid <= 4 then
            display.set_font("10x20")
            display.set_text_size(2)
        else
            display.set_font("10x20")
            display.set_text_size(1)
        end
        display.set_text_color(WHITE)
        display.set_cursor(10, 108)
        display.print(uid_hex)
        display.set_text_size(1)

        display.set_font("6x13")
        display.set_text_color(GRAY)
        display.set_cursor(10, 140)
        if atqa and sak then
            display.print(string.format("ATQA %02X%02X  SAK %02X",
                atqa[1] or 0, atqa[2] or 0, sak))
        end
        display.set_cursor(10, 158)
        display.print("Reads: " .. read_count)

        -- Fade hint when tag was lifted away
        if util.time() - last_seen > 0.5 then
            display.set_text_color(AMBER)
            display.set_cursor(10, 176)
            display.print("Hold tag near the antenna")
        end
    else
        display.set_font("9x15")
        display.set_text_color(CYAN)
        display.set_cursor(10, 110)
        display.print("Hold a tag near")
        display.set_cursor(10, 132)
        display.print("the PN532 antenna...")
    end

    display.set_font("9x15")
    display.set_text_color(WHITE)
    display.set_cursor(W // 2, H - 20)
    display.print("B - exit")
end
