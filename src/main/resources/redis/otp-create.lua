-- All OTP keys share a hash slot. Replacement and expiry are applied atomically.
local oldKey = redis.call('GET', KEYS[2])
if oldKey then redis.call('DEL', oldKey) end
redis.call('HSET', KEYS[1],
    'identifierKey', ARGV[2], 'destination', ARGV[3], 'userId', ARGV[4],
    'credentialVersion', ARGV[5], 'code', ARGV[6], 'channel', ARGV[7],
    'expiresAt', ARGV[8], 'failedAttempts', '0', 'state', 'OPEN')
redis.call('PEXPIRE', KEYS[1], ARGV[1])
redis.call('SET', KEYS[2], KEYS[1], 'PX', ARGV[1])
return 1
