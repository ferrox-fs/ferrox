-- wrk script: PUT random 4KB objects with sequential keys.
local counter = 0
local body = string.rep("x", 4096)

request = function()
  counter = counter + 1
  local path = string.format("%sk-%010d", wrk.path, counter)
  return wrk.format("PUT", path, { ["Content-Length"] = "4096" }, body)
end
