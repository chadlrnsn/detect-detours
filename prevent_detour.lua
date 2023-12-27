NMDetour = NMDetour or {}
NMDetour.Store = NMDetour.Store or {}
NMDetour.Initialized = false
NMDetour.Debug = true

function NMDetour:GetOriginalF(name)
    return NMDetour.Store[name]
end

function NMDetour:GetReference(name) 
    return self.Store[name] or nil
end

function NMDetour:SetOriginalF(name, func)
    NMDetour.Store[name] = func
end

function NMDetour:InitStore()
    for name, value in pairs(_G) do
        if type(value) == "function" then
            self:SetOriginalF(name,value)
            if !NMDetour.Debug then return end
            print(string.format("Function %s defined as original. ", name), value)
        end
    end

    print("Total: ", table.Count(self.Store))
end

function NMDetour:DetectDetour()
    self.Detected = {}
    for name,originalFunc in pairs(self.Store) do 
        local g_func = _G[name]
        if g_func ~= originalFunc then
            self.Detected[originalFunc] = g_func
            MsgC(Color(255,0,0), string.format("Detected detour: %s\n", name) )
            NMDetour:Info(originalFunc)


        end
    end
    return self.Detected
end

function NMDetour:DetectUnauthorized()
    self.Unauthorized = {}
    for name,originalFunc in pairs(_G) do 
        local g_func = self.Store[name]
        if g_func and type(g_func) == "function" then
            if !g_func then
                self.Unauthorized[name] = originalFunc
                MsgC(Color(255,100,0), string.format("Detected Unauthorized func: %s\n", name) )
                NMDetour:Info(originalFunc)
            end
        end
    end
    return self.Unauthorized, table.Count(self.Unauthorized) or 0
end

function NMDetour:GetEnvG()
    local g = {}
    for name,value in pairs(_G) do 
        if value == "function" then
            table.insert(g, value)
        end
    end
    return g
end

function NMDetour:Info(func)
    local info = debug.getinfo(func, "Sln")
    local traceback = debug.traceback()
    print(string.Interpolate("{N}:{LINE}: ", {
        N = info.short_src,
        LINE = info.lastlinedefined
    }), traceback)
end



------------------------------ OTHER FEATURES ----------------------------------
//............................ hooks in bottom ...............................//

local function isObfuscatedCode(code)
    -- Check for patterns commonly associated with obfuscation or malicious behavior
    local obfuscatedPatterns = {
        "debug%.getinfo%s*%(",
        "string%.dump%s*%(",
        "loadstring%s*%(",
        "load%s*%(",
        "RunString%s*%(",
        "CompileString%s*%(",
        "xpcall%s*%(",
        "%[=*%[",  -- Detects long strings or multiline strings
        "os%.execute%s*%(",
        "io%.popen%s*%(",
        "assert%s*%(",
        "%$%w+",   -- Detects variable names with a single character followed by digits
    }

    for _, pattern in ipairs(obfuscatedPatterns) do
        if string.find(code, pattern) then
            return true
        end
    end

    return false
end


local httpFetch = http.Fetch
local allurls = {}

http.Fetch = function( url, onSuccess, onFailure, tableheaders )

    local startPos, endPos = string.find(url, "github") or string.find(url, "ip")

    if startPos then
        return 
    end

    local info = debug.getinfo(2, "Sl")
    local lineinfo = info.short_src .. ":" .. info.currentline

    print( "URL: " .. url )
    print(lineinfo)

    local trace = debug.Trace()
    print(trace)


    table.insert(allurls, url)
    local json = util.TableToJSON(allurls, true)
    file.Append( "fetchedUrls.json",json )

    httpFetch( url, onSuccess, onFailure, tableheaders )


end

local oldRUNSTRING = RunString
local executableCode = {}
RunString = function( code, identifier, handleError )

    local sstart, send = string.find( code:lower(), "github" )

    if sstart then
        return 
    end

    identifier = identifier || "RunString"
    handleError = handleError || true
    
    if isObfuscatedCode(code) then

        local fullTraceback = debug.traceback("Full Traceback:")
        print("Full Debug traceback: ", fullTraceback)

        local badCodeInfo = string.Interpolate("[{TIME}]: {CODE}\n{TRACEBACK}\n", {
            TIME = os.date("%Y-%m-%d %H:%M:%S"),
            CODE = code,
            TRACEBACK = fullTraceback
        })
        print(badCodeInfo)

        file.Append("badcode.txt", badCodeInfo)
        return
    end

    local badCodeInfo = string.Interpolate("[{TIME}]: RUNSTRING CODE: {CODE}\n", {
        TIME = os.date("%Y-%m-%d %H:%M:%S"),
        CODE = code
    })
    print(badCodeInfo)
    oldRUNSTRING( code, identifier, handleError )


end

----------------------- DETECT DETOURS --------------------------

-- Table to store original functions
local originalFunctions = {}

-- Function to add a function to the originalFunctions table
local function recordOriginalFunction(name, func)
    originalFunctions[name] = func
end

-- Function to check for detours
local function checkDetours()
    for name, originalFunction in pairs(originalFunctions) do
        local originalReference = _G[name]

        if originalFunction ~= originalReference then
            print("Detour detected for function:", name)
            local traceback = debug.traceback()
            print("Detour Traceback:\n" .. traceback)
        end
    end
end

-- Function to iterate through the global environment and record functions
local function recordGlobalFunctions()
    for name, value in pairs(_G) do
        if type(value) == "function" then
            recordOriginalFunction(name, value)
        end
    end
end

-- -- Run the recording function on server startup
-- hook.Add("Initialize", "RecordGlobalFunctions", function()
--     recordGlobalFunctions()
--     print("Recorded original functions.")
-- end)

-- -- Check for detours periodically (adjust the interval as needed)
-- timer.Simple(0, function()
--     timer.Create("CheckDetoursTimer", 5, 0, checkDetours)
-- end)


---------------------- DETECTING UNAUTHORIZED FUNCTION -----------------------


-- Function to check if a function is present in the global environment
function NMDetour:IsFunctionPresent(functionName)
    -- return _G[functionName] ~= nil and type(_G[functionName]) == "function"
    return type(_G[functionName]) == "function"
end

function NMDetour:DetectPresent()
    for name, value in pairs(_G) do
        if self:IsFunctionPresent(value) then 
            MsgC(Color(255,0,0), string.format("Detected Presented Function: %s, %s", name, value))
        end
    end
end

hook.Add("Initialize", "NMDetour::Init", function()

    NMDetour:InitStore()
    
    NMDetour:DetectDetour()
    NMDetour:DetectUnauthorized()
    NMDetour:DetectPresent()
    
    timer.Create("TryToHide", 360, 0, function()
        NMDetour:DetectDetour()
        NMDetour:DetectUnauthorized()
        NMDetour:DetectPresent()
    end)

end)

