--[[
AP-TI reporter for apti-rspamd.

Posts the result of every scanned message with a score of at least
`min_score` to apti-rspamd, which reports IPs and envelope-from domains that
keep sending bad messages to aptid. Install as
$LOCAL_CONFDIR/lua.local.d/apti.lua and configure it in
modules.local.d/apti.conf (or an `apti { }` block in rspamd.conf.local).

Only the sending IP, the envelope-from domain, the score, the action, the
names and scores of the symbols that fired and whether the sender was
authenticated are sent. Failures are logged and never affect mail
processing.
]]--

local N = 'apti'

local rspamd_http = require "rspamd_http"
local rspamd_logger = require "rspamd_logger"
local lua_util = require "lua_util"
local ucl = require "ucl"

local settings = {
  url = 'http://127.0.0.1:11380/v1/report',
  -- Must match ingest.report_secret in the apti-rspamd config.
  secret = '',
  timeout = 2.0,
  -- Messages below this score are not sent. Keep it at or below
  -- ingest.min_score in the apti-rspamd config.
  min_score = 5.0,
}

local opts = rspamd_config:get_all_opt(N)
if opts then
  settings = lua_util.override_defaults(settings, opts)
end

if not settings.secret or settings.secret == '' then
  rspamd_logger.infox(rspamd_config, '%s: no secret configured, reporting disabled', N)
  return
end

local function apti_report(task)
  local ip = task:get_from_ip()
  if not ip or not ip:is_valid() or ip:is_local() then
    return
  end
  local res = task:get_metric_score('default')
  local score = res and res[1]
  if not score or score < settings.min_score then
    return
  end

  -- All fired symbols, also those with score 0: apti-rspamd matches
  -- symbols such as R_SPF_ALLOW or FREEMAIL_ENVFROM by name.
  local symbols = {}
  for _, s in ipairs(task:get_symbols_all() or {}) do
    table.insert(symbols, { name = s.name, score = s.score or 0 })
  end

  local body = {
    ip = ip:to_string(),
    score = score,
    action = task:get_metric_action('default'),
    symbols = symbols,
    authenticated = task:get_user() ~= nil,
  }
  -- Domain of the SMTP envelope sender; empty for bounces.
  local from = task:get_from('smtp')
  if from and from[1] and from[1].domain and from[1].domain ~= '' then
    body.from_domain = string.lower(from[1].domain)
  end

  rspamd_http.request({
    task = task,
    url = settings.url,
    method = 'post',
    body = ucl.to_format(body, 'json-compact'),
    headers = { Authorization = 'Bearer ' .. settings.secret },
    mime_type = 'application/json',
    timeout = settings.timeout,
    callback = function(err, code, resp)
      if err then
        rspamd_logger.warnx(task, '%s: report failed: %s', N, err)
      elseif code ~= 200 then
        rspamd_logger.warnx(task, '%s: report rejected: HTTP %s: %s', N, code, resp)
      end
    end,
  })
end

-- Idempotent symbols run after scoring, when the result is final.
rspamd_config:register_symbol({
  name = 'APTI_REPORT',
  type = 'idempotent',
  callback = apti_report,
})
