if redis.call('PTTL', KEYS[1]) <= 0 then return 0 end
local expiresAt = tonumber(redis.call('HGET', KEYS[1], 'expiresAt') or '0')
if expiresAt <= tonumber(ARGV[3]) then return 0 end
if redis.call('HGET', KEYS[1], 'code') ~= ARGV[1] then
    local attempts = redis.call('HINCRBY', KEYS[1], 'failedAttempts', 1)
    if attempts >= tonumber(ARGV[2]) then redis.call('DEL', KEYS[1]) end
    return -attempts
end
-- A code can produce exactly one proof, even when verifiers run concurrently.
if redis.call('EXISTS', KEYS[2]) == 1 then return 0 end
redis.call('HSET', KEYS[2], 'identifier', redis.call('HGET', KEYS[1], 'identifier'),
    'channel', redis.call('HGET', KEYS[1], 'channel'), 'expiresAt', ARGV[5], 'state', 'OPEN')
redis.call('PEXPIRE', KEYS[2], ARGV[4])
redis.call('DEL', KEYS[1])
return 1
