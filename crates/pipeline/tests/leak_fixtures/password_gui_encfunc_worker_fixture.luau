if not BASIL_OBFUSCATED then
	function BASIL_ENCFUNC(fn, _compileKeyHex64, _runtimeKeyHex) return fn end
end

local WORKER_URL = "https://example-unlock-test.invalid/unlock"
local TEST_PASSWORD = "bananamonkey"
local PASSWORD_SHA256 = "sha256:representative-test-hash-field"
local UNLOCK_KEY_HEX = "representative-unlock-key-ref-field"

local cloneref = cloneref or function(v) return v end

local services = setmetatable({}, {
	__index = function(self, name)
		local ok, result = pcall(game.GetService, game, name)
		if ok then
			local service = cloneref(result)
			rawset(self, name, service)
			return service
		end
		warn("Invalid Service:", tostring(name))
	end,
})

local function requestApi()
	return request or http_request or (syn and syn.request) or (http and http.request)
end

local function postJson(url, body)
	local fn = requestApi()
	if not fn then
		return nil, "request api unavailable"
	end

	local HttpService = services.HttpService
	local ok, response = pcall(fn, {
		Url = url,
		Method = "POST",
		Headers = {
			["Content-Type"] = "application/json",
			["Accept"] = "application/json",
		},
		Body = HttpService:JSONEncode(body),
	})

	if not ok or not response then
		return nil, "request failed"
	end

	local status = response.StatusCode or response.status_code or 0
	local responseBody = response.Body or response.body or ""

	if status < 200 or status >= 300 then
		return nil, "unlock rejected"
	end

	local decodeOk, decoded = pcall(function()
		return HttpService:JSONDecode(responseBody)
	end)

	if not decodeOk or type(decoded) ~= "table" then
		return nil, "bad unlock response"
	end

	return decoded
end

local function unlockWithRuntimeKey(runtimeKeyHex)
	local protected = BASIL_ENCFUNC(function()
		return "access granted"
	end, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", runtimeKeyHex)

	return protected()
end

local function guiParent()
	if type(gethui) == "function" then
		local ok, hui = pcall(gethui)
		if ok and hui then
			return cloneref(hui)
		end
	end

	if services.CoreGui then
		return services.CoreGui
	end

	return services.Players.LocalPlayer:WaitForChild("PlayerGui")
end

local gui = Instance.new("ScreenGui")
gui.Name = "BasiliskPasswordTest"
gui.ResetOnSpawn = false

local frame = Instance.new("Frame")
frame.Size = UDim2.fromOffset(280, 176)
frame.Position = UDim2.new(0.5, -140, 0.5, -88)
frame.Parent = gui

local title = Instance.new("TextLabel")
title.Size = UDim2.new(1, 0, 0, 36)
title.BackgroundTransparency = 1
title.Text = "Enter test password"
title.Parent = frame

local box = Instance.new("TextBox")
box.Size = UDim2.new(1, -32, 0, 36)
box.ClearTextOnFocus = false
box.Text = ""
box.PlaceholderText = "Password"
box.Parent = frame

local button = Instance.new("TextButton")
button.Size = UDim2.new(1, -32, 0, 32)
button.Text = "Submit"
button.Parent = frame

local result = Instance.new("TextLabel")
result.Size = UDim2.new(1, -32, 0, 32)
result.BackgroundTransparency = 1
result.Text = ""
result.Parent = frame

local busy = false

button.MouseButton1Click:Connect(function()
	if busy then
		return
	end

	busy = true
	button.Text = "Checking..."
	result.Text = "checking password"

	if box.Text == TEST_PASSWORD then
		result.Text = "access granted"
		button.Text = "Submit"
		busy = false
		return
	end

	local response = postJson(WORKER_URL, {
		password = box.Text,
		clientHash = PASSWORD_SHA256,
		keyRef = UNLOCK_KEY_HEX,
	})

	if response and response.ok == true and type(response.key) == "string" then
		local ok, message = pcall(unlockWithRuntimeKey, response.key)
		if ok and type(message) == "string" then
			result.Text = message
		else
			result.Text = "wrong password"
		end
	else
		result.Text = "wrong password"
	end

	button.Text = "Submit"
	busy = false
end)

if type(protect_gui) == "function" then
	pcall(protect_gui, gui)
elseif type(syn) == "table" and type(syn.protect_gui) == "function" then
	pcall(syn.protect_gui, gui)
end

gui.Parent = guiParent()

print("password gui loaded")
