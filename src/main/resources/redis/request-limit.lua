local count = redis.call('INCR', KEYS[1])
if count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[2]) end
if count > tonumber(ARGV[1]) then
    return math.max(1, redis.call('PTTL', KEYS[1]))
end
return 0
