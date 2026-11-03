-- Replacement and TTLs are atomic; all keys use the registration cluster slot.
local oldKey = redis.call('GET', KEYS[2])
if oldKey then redis.call('DEL', oldKey) end
redis.call('HSET', KEYS[1], 'identifier', ARGV[2], 'channel', ARGV[3],
    'code', ARGV[4], 'expiresAt', ARGV[5], 'failedAttempts', '0')
redis.call('PEXPIRE', KEYS[1], ARGV[1])
redis.call('SET', KEYS[2], KEYS[1], 'PX', ARGV[1])
return 1
