-- Claims live until explicit release/completion or until the whole grant expires.
local state, owner, expiresAt, purpose = unpack(redis.call('HMGET', KEYS[1],
    'state', 'owner', 'expiresAt', 'purpose'))
if not state then return 0 end
local operation = ARGV[1]
if operation == 'claim' then
    if tonumber(expiresAt) <= tonumber(ARGV[3]) or purpose ~= ARGV[4] then return 0 end
    if state == 'CLAIMED' then return -1 end
    if state ~= 'OPEN' then return 0 end
    redis.call('HSET', KEYS[1], 'state', 'CLAIMED', 'owner', ARGV[2])
    return 1
end
if state == 'CLAIMED' and owner == ARGV[2] then
    if operation == 'release' then
        redis.call('HSET', KEYS[1], 'state', 'OPEN')
    elseif operation == 'complete' then
        redis.call('HSET', KEYS[1], 'state', 'SPENT')
    else
        return 0
    end
    redis.call('HDEL', KEYS[1], 'owner')
    return 1
end
return 0
