-- One hash keeps the failure window and progressive lock atomic, including under Redis Cluster.
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local untilTime = tonumber(redis.call('HGET', KEYS[1], 'lockedUntil') or '0')
if untilTime > now then return untilTime - now end
local count = redis.call('HINCRBY', KEYS[1], 'failures', 1)
if count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[2]) end
local threshold = tonumber(ARGV[1])
if count >= threshold then
    local rounds = math.floor(count / threshold) - 1
    local duration = math.min(tonumber(ARGV[4]), tonumber(ARGV[3]) * (2 ^ math.min(rounds, 20)))
    redis.call('HSET', KEYS[1], 'lockedUntil', now + duration)
    if redis.call('PTTL', KEYS[1]) < duration then redis.call('PEXPIRE', KEYS[1], duration) end
    return duration
end
return 0
