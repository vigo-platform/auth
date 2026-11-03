-- KEYS: existing login challenge, new expired-password grant.
-- ARGV: login claim owner, current time, grant expiration, then grant fields.
local state, owner, expiresAt, userId, version, channel, destination, passwordVerified = unpack(redis.call(
    'HMGET', KEYS[1], 'state', 'owner', 'expiresAt', 'userId', 'credentialVersion',
    'channel', 'destination', 'passwordVerified'))
local now = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3]) - now
if state ~= 'CLAIMED' or owner ~= ARGV[1] or tonumber(expiresAt) <= now
    or ttl <= 0 or redis.call('EXISTS', KEYS[2]) == 1 then
    return 0
end
local grant = {}
for index = 4, #ARGV, 2 do grant[ARGV[index]] = ARGV[index + 1] end
if grant.purpose ~= 'EXPIRED' or grant.userId ~= userId or grant.credentialVersion ~= version
    or grant.channel ~= channel or grant.destination ~= destination
    or grant.passwordVerified ~= (passwordVerified or 'false') then
    return 0
end
redis.call('HSET', KEYS[2], unpack(ARGV, 4))
redis.call('PEXPIRE', KEYS[2], ttl)
redis.call('HSET', KEYS[1], 'state', 'CLOSED')
redis.call('HDEL', KEYS[1], 'owner')
return 1
