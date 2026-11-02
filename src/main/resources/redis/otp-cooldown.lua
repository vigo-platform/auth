local remaining = redis.call('PTTL', KEYS[1])
if remaining > 0 then return remaining end
redis.call('SET', KEYS[1], '1', 'PX', ARGV[1])
return 0
