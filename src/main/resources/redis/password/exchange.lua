-- KEYS: current challenge, optional replacement grant or challenge and latest-challenge pointer.
-- ARGV: purpose, submitted code, attempt limit, current time, expiration, then replacement fields.
local current = redis.call('HMGET', KEYS[1], 'purpose', 'code', 'expiresAt', 'userId',
    'credentialVersion', 'sessionId', 'channel', 'destination', 'previousChannel',
    'previousDestination', 'identifierKey')
local purpose, code, expiresAt, userId, version, sessionId, channel, destination,
    previousChannel, previousDestination, identifierKey = unpack(current)
local now = tonumber(ARGV[4])
if purpose ~= ARGV[1] or tonumber(expiresAt) <= now then return 0 end
if code ~= ARGV[2] then
    local attempts = redis.call('HINCRBY', KEYS[1], 'failedAttempts', 1)
    if attempts >= tonumber(ARGV[3]) then redis.call('DEL', KEYS[1]) end
    return -attempts
end
if not KEYS[2] then return 1 end

local ttl = tonumber(ARGV[5]) - now
if ttl <= 0 or redis.call('EXISTS', KEYS[2]) == 1 then return 0 end
local replacement = {}
for index = 6, #ARGV, 2 do replacement[ARGV[index]] = ARGV[index + 1] end
if replacement.purpose ~= purpose or replacement.userId ~= userId
    or replacement.credentialVersion ~= version or replacement.sessionId ~= sessionId then
    return 0
end
if KEYS[3] then
    if purpose ~= 'RESET' or previousChannel ~= '' or replacement.channel == channel
        or replacement.previousChannel ~= channel or replacement.previousDestination ~= destination
        or replacement.identifierKey ~= identifierKey or replacement.code == code
        or redis.call('GET', KEYS[3]) ~= KEYS[1] then
        return 0
    end
elseif replacement.channel ~= channel or replacement.destination ~= destination
    or replacement.otherChannel ~= previousChannel or replacement.otherDestination ~= previousDestination then
    return 0
end

redis.call('HSET', KEYS[2], unpack(ARGV, 6))
redis.call('PEXPIRE', KEYS[2], ttl)
if KEYS[3] then redis.call('SET', KEYS[3], KEYS[2], 'PX', ttl) end
redis.call('DEL', KEYS[1])
return 1
