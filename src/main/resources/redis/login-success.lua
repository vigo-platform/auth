local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local untilTime = tonumber(redis.call('HGET', KEYS[1], 'lockedUntil') or '0')
-- Do not erase a new lock established by concurrent failed attempts after authentication completed.
if untilTime <= now then redis.call('DEL', KEYS[1]) end
return 0
