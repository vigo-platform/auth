local state = redis.call('HGET', KEYS[1], 'state')
if not state then return 0 end
local operation = ARGV[1]
if operation == 'fail' and state == 'OPEN' then
    local attempts = redis.call('HINCRBY', KEYS[1], 'failedAttempts', 1)
    if attempts >= tonumber(ARGV[3]) then redis.call('DEL', KEYS[1]) end
    return attempts
end
if operation == 'claim' and state == 'OPEN' then
    redis.call('HSET', KEYS[1], 'state', 'CLAIMED', 'owner', ARGV[2])
    return 1
end
-- A claim never times out independently of the OTP: a stalled verifier cannot allow a second issuer.
-- Only the owning transaction can release it after rollback or close it after commit.
if state == 'CLAIMED' and redis.call('HGET', KEYS[1], 'owner') == ARGV[2] then
    if operation == 'release' then
        redis.call('HSET', KEYS[1], 'state', 'OPEN')
        redis.call('HDEL', KEYS[1], 'owner')
        return 1
    end
    if operation == 'complete' then
        redis.call('HSET', KEYS[1], 'state', 'CLOSED')
        redis.call('HDEL', KEYS[1], 'owner')
        return 1
    end
end
return 0
