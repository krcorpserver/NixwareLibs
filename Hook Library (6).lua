-- make: SYR1337
assert(ffi, "ffi is unavailable")
ffi.cdef([[
    typedef struct Thread32Entry {
        uint32_t dwSize;
        uint32_t cntUsage;
        uint32_t th32ThreadID;
        uint32_t th32OwnerProcessID;
        long tpBasePri;
        long tpDeltaPri;
        uint32_t dwFlags;
    } Thread32Entry;
    
    int CloseHandle(void*);
    void* GetCurrentProcess();
    uint32_t ResumeThread(void*);
    uint32_t GetCurrentThreadId();
    uint32_t SuspendThread(void*);
    uint32_t GetCurrentProcessId();
    void* OpenThread(uint32_t, int, uint32_t);
    int Thread32Next(void*, struct Thread32Entry*);
    int Thread32First(void*, struct Thread32Entry*);
    void* CreateToolhelp32Snapshot(uint32_t, uint32_t);
    int VirtualProtect(void*, uint64_t, uint32_t, uint32_t*);
]])

local arrHooks = {}
local arrThreads = {}
local NULLPTR = ffi.cast("void*", 0)
local INVALID_HANDLE = ffi.cast("void*", - 1)
local function Thread(nTheardID)
    local hThread = ffi.C.OpenThread(0x0002, 0, nTheardID)
    if hThread == NULLPTR or hThread == INVALID_HANDLE then
        return false
    end

    return setmetatable({
        bValid = true,
        nId = nTheardID,
        hThread = hThread,
        bIsSuspended = false
    }, {
        __index = {
            Suspend = function(self)
                if self.bIsSuspended or not self.bValid then
                    return false
                end

                if ffi.C.SuspendThread(self.hThread) ~= - 1 then
                    self.bIsSuspended = true
                    return true
                end

                return false
            end,

            Resume = function(self)
                if not self.bIsSuspended or not self.bValid then
                    return false
                end

                if ffi.C.ResumeThread(self.hThread) ~= - 1 then
                    self.bIsSuspended = false
                    return true
                end

                return false
            end,

            Close = function(self)
                if not self.bValid then
                    return
                end

                self:Resume()
                self.bValid = false
                ffi.C.CloseHandle(self.hThread)
            end
        }
    })
end

local function UpdateThreadList()
    arrThreads = {}
    local hSnapShot = ffi.C.CreateToolhelp32Snapshot(0x00000004, 0)
    if hSnapShot == INVALID_HANDLE then
        return false
    end

    local pThreadEntry = ffi.new("struct Thread32Entry[1]")
    pThreadEntry[0].dwSize = ffi.sizeof("struct Thread32Entry")
    if ffi.C.Thread32First(hSnapShot, pThreadEntry) == 0 then
        ffi.C.CloseHandle(hSnapShot)
        return false
    end

    local nCurrentThreadID = ffi.C.GetCurrentThreadId()
    local nCurrentProcessID = ffi.C.GetCurrentProcessId()
    while ffi.C.Thread32Next(hSnapShot, pThreadEntry) > 0 do
        if pThreadEntry[0].dwSize >= 20 and pThreadEntry[0].th32OwnerProcessID == nCurrentProcessID and pThreadEntry[0].th32ThreadID ~= nCurrentThreadID then
            local hThread = Thread(pThreadEntry[0].th32ThreadID)
            if not hThread then
                for _, pThread in pairs(arrThreads) do
                    pThread:Close()
                end

                arrThreads = {}
                ffi.C.CloseHandle(hSnapShot)
                return false
            end

            table.insert(arrThreads, hThread)
        end
    end

    ffi.C.CloseHandle(hSnapShot)
    return true
end

local function SuspendThreads()
    if not UpdateThreadList() then
        return false
    end

    for _, hThread in pairs(arrThreads) do
        hThread:Suspend()
    end

    return true
end

local function ResumeThreads()
    for _, hThread in pairs(arrThreads) do
        hThread:Resume()
        hThread:Close()
    end
end

local function CreateHook(pTarget, pDetour, szType)
    assert(type(pDetour) == "function", "hook library error: invalid detour function")
    assert(type(pTarget) == "cdata" or type(pTarget) == "userdata" or type(pTarget) == "number" or type(pTarget) == "function", "hook library error: invalid target function")
    if not SuspendThreads() then
        ResumeThreads()
        print("hook library error: failed suspend threads")
        return false
    end

    local arrBackUp = ffi.new("uint8_t[14]")
    local pTargetFn = ffi.cast(szType, pTarget)
    local pBytes = ffi.cast("uint8_t*", pTargetFn)
    local arrShellCode = ffi.new("uint8_t[14]", {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    })

    if pBytes[0] == 0xE9 or (pBytes[0] == 0xFF and pBytes[1] == 0x25) then
        print(("warning: %p already hooked, rehook this function"):format(pTarget))
    end

    local __Object = {
        bValid = true,
        bAttached = false,
        pBackup = arrBackUp,
        pTarget = pTargetFn,
        pOldProtect = ffi.new("uint32_t[1]"),
        hCurrentProcess = ffi.C.GetCurrentProcess()
    }

    ffi.copy(arrBackUp, pTargetFn, ffi.sizeof(arrBackUp))
    ffi.cast("uintptr_t*", arrShellCode + 0x6)[0] = ffi.cast("uintptr_t", ffi.cast(szType, function(...)
        local bSuccessfully, pResult = pcall(pDetour, __Object, ...)
        if not bSuccessfully then
            __Object:Remove()
            print(("[hook library]: unexception runtime error -> %s"):format(pResult))
            return pTargetFn(...)
        end

        return pResult
    end))

    __Object.__index = setmetatable(__Object, {
        __call = function(self, ...)
            if not self.bValid then
                return nil
            end

            self:Detach()
            local bSuccessfully, pResult = pcall(self.pTarget, ...)
            if not bSuccessfully then
                self.bValid = false
                print(("[hook library]: runtime error -> %s"):format(pResult))
                return nil
            end

            self:Attach()
            return pResult
        end,

        __index = {
            Attach = function(self)
                if self.bAttached or not self.bValid then
                    return false
                end

                self.bAttached = true
                ffi.C.VirtualProtect(self.pTarget, ffi.sizeof(arrBackUp), 0x40, self.pOldProtect)
                ffi.copy(self.pTarget, arrShellCode, ffi.sizeof(arrBackUp))
                ffi.C.VirtualProtect(self.pTarget, ffi.sizeof(arrBackUp), self.pOldProtect[0], self.pOldProtect)
                return true
            end,

            Detach = function(self)
                if not self.bAttached or not self.bValid then
                    return false
                end

                self.bAttached = false
                ffi.C.VirtualProtect(self.pTarget, ffi.sizeof(arrBackUp), 0x40, self.pOldProtect)
                ffi.copy(self.pTarget, self.pBackup, ffi.sizeof(arrBackUp))
                ffi.C.VirtualProtect(self.pTarget, ffi.sizeof(arrBackUp), self.pOldProtect[0], self.pOldProtect)
                return true
            end,

            Remove = function(self)
                if not self.bValid then
                    return false
                end

                SuspendThreads()
                self:Detach()
                ResumeThreads()
                self.bValid = false
            end
        }
    })

    __Object:Attach()
    table.insert(arrHooks, __Object)
    ResumeThreads()
    return __Object
end

register_callback("unload", function()
    for _, pObject in pairs(arrHooks) do
        pObject:Remove()
    end
end)

return {
    create = CreateHook
}