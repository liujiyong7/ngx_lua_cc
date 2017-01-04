local clientIP = getClientIp()
local uri = ngx.var.uri
local ua = ngx.req.get_headers()["User-Agent"]
local host = ngx.req.get_headers()["Host"]
local ok, err = ngx.timer.at(0, count_redis, host, clientIP, uri, ua)
