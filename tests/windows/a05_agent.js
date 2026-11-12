"use strict";

// Fixed witnesses for the two exports in the owned A05 fixture DLL.
let interception = null;
const uptime = new NativeFunction(
    Process.getModuleByName("kernel32.dll").getExportByName("GetTickCount64"), "uint64", []
);

function event(kind, value) {
    return { kind, value, pid: Process.id, tick: uptime().toString() };
}

function ownedModule(name) {
    if (name !== "a05-owned.dll" && name !== "a05-renamed.dll") {
        throw new Error("unsupported synthetic fixture");
    }
    return Process.getModuleByName(name);
}

function witness(name) {
    const call = new NativeFunction(ownedModule(name).getExportByName("a05_witness"), "uint32", []);
    return event("witness", call());
}

rpc.exports = {
    boot() {
        return event("spawn", 0xa05);
    },

    witness,

    intercept(name) {
        const address = ownedModule(name).getExportByName("a05_probe");
        let seen = false;
        interception = Interceptor.attach(address, {
            onEnter(args) {
                if (seen) return;
                seen = true;
                send(event("interceptor", args[0].toUInt32()));
            }
        });
        Interceptor.flush();
    },

    profile(name) {
        const address = ownedModule(name).getExportByName("a05_witness");
        interception = Interceptor.attach(address, {
            onLeave(value) { send(event("profiler", value.toUInt32())); }
        });
        Interceptor.flush();
    },

    trace(name, threadId) {
        const address = ownedModule(name).getExportByName("a05_probe");
        let seen = false;
        Stalker.addCallProbe(address, args => {
            if (seen) return;
            seen = true;
            send(event("stalker", args[0].toUInt32()));
        });
        Stalker.follow(threadId);
    },

    init(_stage, parameters) {
        if (parameters.gadget === true) {
            const result = witness(parameters.module);
            result.kind = "gadget";
            File.writeAllText(parameters.oracle, JSON.stringify(result));
            File.writeAllText(parameters.oracle + ".ready", "ready");
        }
    }
};
