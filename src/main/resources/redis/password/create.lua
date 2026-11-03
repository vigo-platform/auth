-- KEYS: new grant or challenge, optional latest-challenge pointer.
-- ARGV: current time, expiration, then alternating hash fields and values.
local ttl = tonumber(ARGV[2]) - tonumber(ARGV[1])
if ttl <= 0 or redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
local previous
if KEYS[2] then previous = redis.call('GET', KEYS[2]) end
redis.call('HSET', KEYS[1], unpack(ARGV, 3))
redis.call('PEXPIRE', KEYS[1], ttl)
if KEYS[2] then
    redis.call('SET', KEYS[2], KEYS[1], 'PX', ttl)
    if previous then redis.call('DEL', previous) end
end
return 1
