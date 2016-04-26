local jwt = require "resty.jwt"
local cjson = require "cjson"

local function enabled(val)
  if val == nil then return nil end
  return val == true or (val == "1" or val == "true" or val == "on")
end

local function decode_secret(s)
  -- convert from URL-safe Base64 to Base64
  local r = #s % 4
  if r == 2 then
    s = s .. "=="
  elseif r == 3 then
    s = s .. "="
  end
  s = string.gsub(s, "-", "+")
  s = string.gsub(s, "_", "/")

  -- convert from Base64 to UTF-8 string
  return ngx.decode_base64(s)
end

local defaults = {
  secret            = ngx.var.jwt_secret,
  secret_is_base64  = enabled(ngx.var.jwt_secret_is_base64 or false),
  issuer            = ngx.var.jwt_issuer,
  cookie_name       = ngx.var.jwt_cookie or "id_token"
}

if defaults.secret ~= nil and defaults.secret_is_base64 then
  defaults.secret = decode_secret(defaults.secret)
  defaults.secret_is_base64 = false
end

local M = {}

function M.auth(opts)
  local o, d = opts or defaults, defaults
  local cookie_name = o.cookie_name or d.cookie_name
  local secret_is_base64 = o.secret_is_base64 or d.secret_is_base64
  local valid_issuer = o.valid_issuer or d.valid_issuer
  local grace_period = o.grace_period or 120
  local secret = o.secret
  if secret ~= nil then
    if secret_is_base64 then secret = decode_secret(secret) end
  else
    secret = d.secret
  end

  local claim_specs = o.claim_specs

  -- check Authorization request header
  local header = ngx.var.http_Authorization
  local err, id_token

  if header == nil or header:find(" ") == nil then
    -- before giving up, check if a bearer cookie is present
    id_token = ngx.var["cookie_" .. cookie_name]
    if not id_token then
      err = {
        code = 403,
        msg = "no Authorization header or " .. cookie_name .. " cookie found"
      }
      ngx.log(ngx.WARN, err.msg)
      return nil, err
    end
    ngx.log(ngx.INFO, cookie_name .. " cookie: " .. id_token)
  else
    ngx.log(ngx.INFO, "Authorization header: " .. header)

    local divider = header:find(' ')
    if string.lower(header:sub(0, divider-1)) ~= string.lower("Bearer") then
      err = {
        code = 403,
        msg = "no Bearer authorization header value found"
      }
      ngx.log(ngx.WARN, err.msg)
      return nil, err
    end

    id_token = header:sub(divider+1)
    if id_token == nil then
      err = {
        code = 403,
        msg = "no Bearer access token value found"
      }
      ngx.log(ngx.WARN, err.msg)
      return nil, err
    end
  end

  -- require valid JWT
  local verify_opts = {
    lifetime_grace_period = grace_period,
    require_exp_claim = true
  }
  if valid_issuer then
    verify_opts.valid_issuer = { valid_issuer }
  end
  local jwt_obj = jwt:verify(secret, id_token, verify_opts)

  if jwt_obj.verified == false then
    err = {
      code = 401,
      msg = "Invalid token: " .. jwt_obj.reason
    }
    ngx.log(ngx.WARN, err.msg)
    return nil, err
  end

  ngx.log(ngx.INFO, "JWT: " .. cjson.encode(jwt_obj))

  -- optionally require specific claims
  if claim_specs ~= nil then
    --TODO: test
    -- make sure they passed a Table
    if type(claim_specs) ~= 'table' then
      err = {
        code = 500,
        msg = "Configuration error: claim_specs arg must be a table"
      }
      ngx.log(ngx.ERR, err.msg)
      return nil, err
    end

    -- process each claim
    local blocking_claim = ""
    for claim, spec in pairs(claim_specs) do
      -- make sure token actually contains the claim
      local claim_value = jwt_obj.payload[claim]
      if claim_value == nil then
        blocking_claim = claim .. " (missing)"
        break
      end

      local spec_actions = {
        -- claim spec is a string (pattern)
        ["string"] = function(pattern, val)
          return string.match(val, pattern) ~= nil
        end,

        -- claim spec is a predicate function
        ["function"] = function(func, val)
          -- convert truthy to true/false
          if func(val) then
            return true
          else
            return false
          end
        end
      }

      local spec_action = spec_actions[type(spec)]

      -- make sure claim spec is a supported type
      -- TODO: test
      if spec_action == nil then
        err = {
          code = 500,
          msg = "Configuration error: claim_specs arg claim '" .. claim .. "' must be a string or a table"
        }
        ngx.log(ngx.ERR, err.msg)
        return nil, err
      end

      -- make sure token claim value satisfies the claim spec
      if not spec_action(spec, claim_value) then
        blocking_claim = claim
        break
      end
    end

    if blocking_claim ~= "" then
      err = {
        code = 403,
        msg = "User did not satisfy claim: " .. blocking_claim
      }
      ngx.log(ngx.WARN, err.msg)
      return nil, err
    end
  end

  return {
    jwt       = id_token,
    jwt_table = jwt_obj
  }, nil

  -- write the X-Auth-UserId header
  --ngx.header["X-Auth-UserId"] = jwt_obj.payload.sub
end

function M.table_contains(table, item)
  for _, value in pairs(table) do
    if value == item then return true end
  end
  return false
end

return M
