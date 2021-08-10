ffi.cdef[[
    int VirtualProtect(void* lpAddress, unsigned long dwSize, unsigned long flNewProtect, unsigned long* lpflOldProtect);
    void* GetProcAddress(void* hModule, const char* lpProcName);
    void* GetModuleHandleA(const char* lpModuleName);
	typedef void* (__cdecl* tCreateInterface)(const char* name, int* returnCode);
    typedef int ClientFrameStage_t;
]]

local vmt = {hooks = {}}
function vmt.new(vt)
    local new_hook = {}
    local org_func = {}
    local old_prot = ffi.new('unsigned long[1]')
    local virtual_table = ffi.cast("uintptr_t**", vt)[0]
    new_hook.this = virtual_table

    new_hook.hookMethod = function(cast, func, method)
        org_func[method] = virtual_table[method]
        ffi.C.VirtualProtect(ffi.cast("void*", virtual_table + method), 4, 0x04, old_prot)
        virtual_table[method] = ffi.cast('intptr_t', ffi.cast('void*', ffi.cast(cast, func)))
        ffi.C.VirtualProtect(ffi.cast("void*", virtual_table + method), 4, old_prot[0], old_prot)
        return ffi.cast(cast, org_func[method])
    end

    new_hook.unHookMethod = function(method)
        ffi.C.VirtualProtect(ffi.cast("void*", virtual_table + method), 4, 0x04, old_prot)
        virtual_table[method] = org_func[method]
        ffi.C.VirtualProtect(ffi.cast("void*", virtual_table + method), 4, old_prot[0], old_prot)
        org_func[method] = nil
    end

    new_hook.unHookAll = function()
        for method, func in pairs(org_func) do
            new_hook.unHookMethod(method)
        end
        print('unhooked')
    end
    table.insert(vmt.hooks, new_hook.unHookAll)
    return new_hook
end

local Client = vmt.new(ffi.cast("tCreateInterface", ffi.C.GetProcAddress(ffi.C.GetModuleHandleA("client.dll"), "CreateInterface"))("VClient018", ffi.new("int*")))

function fsn_f(stage)
    print(stage)
    local res = fsn(stage)
    return res
end

fsn = Client.hookMethod("void(__stdcall*)(ClientFrameStage_t)", fsn_f, 37)




callbacks.Register("Unload", function()
    Client.unHookAll()
end)
