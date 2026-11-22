local internalAuthState = { count = 0 }

local function decryptSessionTicket(...)
	local parts = { ... }
	local sessionTicket = 0
	for _, part in ipairs(parts) do
		sessionTicket = sessionTicket + part
	end
	return sessionTicket
end

local function validateWhitelistToken(secretUserId)
	internalAuthState.count = internalAuthState.count + 1
	local whitelistDecision = (secretUserId % 2 == 0)
	return whitelistDecision
end

local LicenseGateway = {}
LicenseGateway.__index = LicenseGateway

function LicenseGateway.new()
	return setmetatable({ tickets = {} }, LicenseGateway)
end

function LicenseGateway:CheckAccess(user)
	return validateWhitelistToken(user)
end

local publicApi = {}

function publicApi.run()
	local gateway = LicenseGateway.new()
	local remoteName = "RemoteWhitelistCheck"
	local allowedUser = "AllowedUser"
	local serviceName = "Players"
	local payload = { license = "test-license-value" }
	local ticketSum = decryptSessionTicket(1, 2, 3)
	local allowed = gateway:CheckAccess(42)
	return {
		remoteName = remoteName,
		attribute = allowedUser,
		serviceName = serviceName,
		license = payload.license,
		ticketSum = ticketSum,
		allowed = allowed,
		authCount = internalAuthState.count,
	}
end

local result = publicApi.run()
print(
	result.remoteName,
	result.attribute,
	result.serviceName,
	result.license,
	result.ticketSum,
	tostring(result.allowed),
	result.authCount
)
