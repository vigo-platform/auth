if redis.call('PTTL', KEYS[1]) <= 0 then return 0 end
local state = redis.call('HGET', KEYS[1], 'state')
local operation = ARGV[1]
if operation == 'claim' and state == 'OPEN' then
    if tonumber(redis.call('HGET', KEYS[1], 'expiresAt') or '0') <= tonumber(ARGV[3]) then return 0 end
    redis.call('HSET', KEYS[1], 'state', 'CLAIMED', 'owner', ARGV[2])
    return 1
end
-- No expiring lease: a slow/uncertain CreateUser must never permit a second mutation.
if state ~= 'CLAIMED' or redis.call('HGET', KEYS[1], 'owner') ~= ARGV[2] then return 0 end
if operation == 'release' then
    redis.call('HSET', KEYS[1], 'state', 'OPEN')
    redis.call('HDEL', KEYS[1], 'owner')
    return 1
end
if operation == 'complete' then
    -- A completed registration is single-use; never cache a replayable success.
    return redis.call('DEL', KEYS[1])
end
return 0
