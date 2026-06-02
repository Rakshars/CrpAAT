-- ============================================================================
-- cryptoshield_dissector.lua
-- Custom Wireshark Protocol Dissector for B.M.S. College of Engineering AAT
-- registers on TCP Port 9999 to dissect Adaptive CryptoShield Packets.
-- ============================================================================

-- 1. Declare the protocol
local cryptoshield_protocol = Proto("CryptoShield", "Adaptive CryptoShield Custom Protocol")

-- 2. Declare Protocol Fields for display inside Wireshark
local f_type = ProtoField.string("cryptoshield.type", "Envelope / Packet Type")
local f_iv = ProtoField.string("cryptoshield.iv", "Initialization Vector (IV)")
local f_ciphertext = ProtoField.string("cryptoshield.ciphertext", "Encrypted Ciphertext")
local f_nonce = ProtoField.string("cryptoshield.nonce", "Replay Protection Nonce")
local f_timestamp = ProtoField.string("cryptoshield.timestamp", "Packet Timestamp (UTC)")
local f_hmac = ProtoField.string("cryptoshield.hmac", "HMAC-SHA256 Signature")
local f_enc_key = ProtoField.string("cryptoshield.encrypted_key", "RSA Encrypted AES Session Key")
local f_rsa_e = ProtoField.string("cryptoshield.rsa_e", "RSA Public Exponent (E)")
local f_rsa_n = ProtoField.string("cryptoshield.rsa_n", "RSA Modulus (N)")
local f_status = ProtoField.string("cryptoshield.status", "Operation Status")
local f_msg = ProtoField.string("cryptoshield.msg", "Response/Alert Message")
local f_filename = ProtoField.string("cryptoshield.filename", "Transferred Filename")
local f_honey = ProtoField.string("cryptoshield.honey_flag", "Honeypot Decoy Trap Flag")

cryptoshield_protocol.fields = {
    f_type, f_iv, f_ciphertext, f_nonce, f_timestamp, 
    f_hmac, f_enc_key, f_rsa_e, f_rsa_n, f_status, f_msg,
    f_filename, f_honey
}

-- 3. Define the dissector logic
function cryptoshield_protocol.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length == 0 then return end

    -- Extract raw packet payload as string
    local raw_str = buffer():string()

    -- Update Wireshark GUI Columns
    pinfo.cols.protocol = cryptoshield_protocol.name
    pinfo.cols.info = "CryptoShield Custom Socket Frame"

    -- Add main protocol node to the layout tree
    local subtree = tree:add(cryptoshield_protocol, buffer(), "CryptoShield Protocol Data (" .. length .. " bytes)")

    -- Robust Lua pattern matching to extract JSON fields
    local pkt_type = raw_str:match('"type"%s*:%s*"([^"]+)"')
    local status = raw_str:match('"status"%s*:%s*"([^"]+)"')
    local msg = raw_str:match('"msg"%s*:%s*"([^"]+)"')
    local iv = raw_str:match('"iv"%s*:%s*"([^"]+)"')
    local ciphertext = raw_str:match('"ciphertext"%s*:%s*"([^"]+)"')
    local nonce = raw_str:match('"nonce"%s*:%s*"([^"]+)"')
    local timestamp = raw_str:match('"timestamp"%s*:%s*"([^"]+)"')
    local hmac = raw_str:match('"hmac"%s*:%s*"([^"]+)"')
    local enc_key = raw_str:match('"encrypted_key"%s*:%s*"([^"]+)"')
    local rsa_e = raw_str:match('"e"%s*:%s*"([^"]+)"')
    local rsa_n = raw_str:match('"n"%s*:%s*"([^"]+)"')
    local filename = raw_str:match('"filename"%s*:%s*"([^"]+)"')
    local honey_flag = raw_str:match('"honey_flag"%s*:%s*"([^"]+)"')

    -- Dissect based on discovered parameters
    if pkt_type then
        subtree:add(f_type, pkt_type)
        pinfo.cols.info = "CryptoShield Payload [Type: " .. pkt_type .. "]"
    elseif status then
        subtree:add(f_status, status)
        pinfo.cols.info = "CryptoShield Response [Status: " .. status .. "]"
    end

    if iv then subtree:add(f_iv, iv) end
    if ciphertext then subtree:add(f_ciphertext, ciphertext) end
    if nonce then subtree:add(f_nonce, nonce) end
    if timestamp then subtree:add(f_timestamp, timestamp) end
    if hmac then subtree:add(f_hmac, hmac) end
    if enc_key then 
        subtree:add(f_enc_key, enc_key) 
        pinfo.cols.info = "CryptoShield: AES Key Exchange (RSA Encrypted)"
    end
    if rsa_e then subtree:add(f_rsa_e, rsa_e) end
    if rsa_n then subtree:add(f_rsa_n, rsa_n) end
    if msg then subtree:add(f_msg, msg) end
    if filename then subtree:add(f_filename, filename) end
    if honey_flag then 
        subtree:add(f_honey, honey_flag)
        pinfo.cols.info = "🔥 HONEYPOT DECOY TRAP: FLAG TRIGGERED!"
    end

    -- Add the raw JSON dump to the tree as a leaf
    local raw_tree = subtree:add("Raw JSON Stream")
    raw_tree:add(raw_str)
end

-- 4. Register the dissector on TCP Port 9999
local tcp_port_table = DissectorTable.get("tcp.port")
tcp_port_table:add(9999, cryptoshield_protocol)
