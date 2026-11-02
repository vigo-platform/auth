local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local untilTime = tonumber(redis.call('HGET', KEYS[1], 'lockedUntil') or '0')
return math.max(0, untilTime - now)
