local http = require('http')

if not config then
  config = {
      url = nil,
  }
end

function gen_addr(txn)

local h = txn.sf:req_hdr("host")
local res, err = http.get{url=config.url..'?h='..h, headers={accept='application/json', host='localhost'}}

core.Info(config.url..'?h='..h)
if res then
    for k,v in pairs(res) do
        core.Info(k)
        core.Info(tostring(v))
    end
    if res.status_code == 200 then
        txn.set_var(txn, 'txn.wallet', res.content)
    else
        txn.set_var(txn, 'txn.wallet', 'err')
        core.Alert("Can't get wallet address " .. res.content)
    end
else
    txn.set_var(txn, 'txn.wallet', 'err')
    core.Alert("Can't get wallet address " .. err)
end

end

core.register_init(function()

config.url = os.getenv("GEN_URL")

end)

-- Called on a request.
core.register_action('gen_addr', {'http-req'}, gen_addr, 0)
