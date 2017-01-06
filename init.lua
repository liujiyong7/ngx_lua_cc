local cjson = require 'cjson'
local redis = require "resty.redis"
local limit = ngx.shared.limit

local file = io.open("/usr/local/openresty/nginx/conf/ngx_lua_cc/config.json", "r");
cfg  = cjson.decode(file:read("*all"));
file:close();

redis_host='10.93.80.33'
redis_port=6379

-- init config
parse_config = {}
for site,req_cfg in pairs(cfg['host']) do
	if req_cfg then
		local host_cfg
		if parse_config[site] then
			host_cfg = parse_config[site]
		else
			host_cfg = {}
			parse_config[site] = host_cfg
		end

		for i, rule in ipairs(req_cfg['rule']) do
			if rule['state'] == 'on' and rule['pattern'] and rule['pattern']['rate'] then
				local rate_cfg = rule['pattern']['rate']
				if rate_cfg['dim'] then
					rule['pattern']['suffix'] = rate_cfg['phase']..':'..rate_cfg['limit']..':'..rate_cfg['block_time']
					local index = 0
					for i,dim in ipairs(rate_cfg['dim']) do
						--ip:1 uri:2 ua:4
						if dim == 'ip' then
							index = index + 1
						elseif dim == 'uri' then
							index = index + 2
						elseif dim == 'ua' then
							index = index + 4
						end
					end
					local index_cfg
					if host_cfg[tostring(index)] then
						index_cfg = host_cfg[tostring(index)]
					else
						index_cfg = {}
						index_cfg['count'] = {}
						for i,dim in ipairs(rate_cfg['dim']) do
							--ip:1 uri:2 ua:4
							if dim == 'ip' then
								rule['pattern']['ip'] = 1
								index_cfg['ip'] = 1
								--ngx.say("ip:", index, parse_config[site][index]['ip'])
							elseif dim == 'uri' then
								rule['pattern']['ip'] = 1
								index_cfg['uri'] = 1
							elseif dim == 'ua' then
								rule['pattern']['ip'] = 1
								index_cfg['ua'] = 1
							end
						end
						host_cfg[tostring(index)] = index_cfg
					end
	
					local phase = rule['pattern']['rate']['phase']
					index_cfg['count'][tostring(phase)] = {}
					local limit = rule['pattern']['rate']['limit']
					index_cfg['count'][tostring(phase)][tostring(limit)] = {}
					local block_time = rule['pattern']['rate']['block_time']
					index_cfg['count'][tostring(phase)][tostring(limit)][tostring(block_time)] = block_time
				end
			end
		end
	end
end
------------------------------------------

function getClientIp()
	local clientIP = ngx.req.get_headers()["X-Real-IP"]
	if clientIP == nil then
		clientIP = ngx.req.get_headers()["x_forwarded_for"]
	end
	if clientIP == nil then
		clientIP = ngx.var.remote_addr
	end
	return clientIP
end

function close_redis(red)  
    if not red then  
        return  
    end  
    --释放连接(连接池实现)  
    local pool_max_idle_time = 10000 --毫秒  
    local pool_size = 100 --连接池大小  
    local ok, err = red:set_keepalive(pool_max_idle_time, pool_size)  
  
    if not ok then  
        --ngx_log(ngx_ERR, "set redis keepalive error : ", err)  
    end  
end

function deny_cc()
	-- host ip uri ua
	local clientIP = getClientIp()
	local uri = ngx.var.uri
	local ua = ngx.req.get_headers()["User-Agent"]
	local host = ngx.req.get_headers()["Host"]

	-- judge
	req_cfg = cfg['host'][host]
	if req_cfg then
		for i, rule in ipairs(req_cfg['rule']) do
			if rule['state'] == 'on' and rule['pattern'] then
				local pattern = rule['pattern']
				--ngx.say(rule['id'])
				local isblock = true
				if isblock and pattern['uri'] then

				end
				if isblock and pattern['ua'] then

				end
				if isblock and pattern['rate'] then
					key = "u:"..host
					if pattern['ip'] then
						key = key..":"..clientIP
					end
					if pattern['uri'] then
						key = key..":"..uri
					end
					if pattern['ua'] then
						key = key..":"..ua
					end
					key = key..":"..pattern['suffix']
					--ngx.say(rule['id'], key)
					local flag, _= limit:get(key)
					if not flag then
						isblock = false
					end
				end
				if isblock then
					ngx.exit(501)
					return
				end
			end
		end
	end
end

function count_redis(premature, host, clientIP, uri, ua)
	local host_cfg = parse_config[host]
	if host_cfg then
		local red = redis:new()
		red:set_timeout(5000) -- 1 secs
		local ok, err = red:connect(redis_host, redis_port, {pool = "anticc_redis_pool"})
		if not ok then
	 	    return close_redis(red)
		end

		local prefix = 'u:'..host
		local keys = {}
		local index = 1
		for _, req_cfg in pairs(host_cfg) do
			local req = ''
			if req_cfg['ip'] then
				req = req..':'..clientIP
			end
			if req_cfg['uri'] then
				req = req..':'..uri
			end
			if req_cfg['ua'] then
				req = req..':'..ua
			end

			for phase,limit_cfg in pairs(req_cfg['count']) do
				local key = prefix..req..':'..phase
				keys[index] = key
				local res, err = red:eval("local res, err = redis.call('incr',KEYS[1]) if res == 1 then local resexpire, err = redis.call('expire',KEYS[1],KEYS[2]) end return (res)",2,key, phase)
				for limit_str, block_time_cfg in pairs(limit_cfg) do
					for _, block_time in pairs(block_time_cfg) do
						if res >= tonumber(limit_str) then
							shared_key = keys[index]..':'..limit_str..':'..block_time
							limit:set(shared_key, 1, block_time)
						end
					end
				end
				index = index + 1
			end
		end
	end
end
