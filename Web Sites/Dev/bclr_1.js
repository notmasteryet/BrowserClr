/* MIT License. Copyright 2010 by notmasteryet. */

/* Web Browser CLR Execution Environment */
/* Ecma-335 spec. Partion 1 */

function AppDomain() {
    var currentAppDomain = this;
    
    this.createThread = function() {
        var thread  = new Thread(this);
        this.threads.push(thread);
        return thread;
    }

    this.heap = new Array();

    this.createObject = function() {
        var obj = new Reference();
        this.heap.push(obj);
        return obj;
    }
    
    var index = 0;    
    
    function Reference() {
        this.index = index++;                
    }
    Reference.prototype.initStruct = function() { this.value = new Struct(); };
    Reference.prototype.initArray = function() { this.value = new Array(); };
       
    this.threads = new Array();
    var currentThreadIndex = 0;
    
    function Thread(appDomain) {
        this.appDomain = appDomain;
        this.state = undefined;
        this.stack = [];
        this.callStack = [];
        this.dispose = function() {
            var newThreads = [];
            for(var i=0;i<this.appDomain.threads.length;++i) {
                if(this.appDomain.threads[i] != this) {
                    newThreads.push(appDomain.threads[i]);
                } else if(currentThreadIndex >= i) 
                    --currentThreadIndex;
            }
            this.appDomain.threads = newThreads;
        }
    }
    Thread.prototype.execute = Thread_execute;
    
    this.collectGarbage = function() {
        var i, j;    
        for(i=0;i<this.heap.length;++i) {
            this.heap[i].used = false;
        }
        
        var queue = [];
        for(i=0;i<this.threads.length;++i) {
            var thread = this.threads[i];
            for(j=0;j<thread.stack.length;++j) {
                if(thread.stack[j] == undefined) continue;
                var obj = thread.stack[j];
                if(obj.constructor == Reference) {
                    if(!obj.used) {
                        queue.push(obj);
                        obj.used = true;
                    }
                } else if(obj.constructor == Struct) {
                    queue.push(obj);
                }
            }
            
            for(j=0;j<this.thead.callStack.length;++j) {
                var frame = this.thead.callStack[j];
                if(frame.locals != undefined) {
                    queue.push(frame.locals);
                }
            }
        }
        
        while(queue.length > 0) {
            var obj = queue.shift();
            
            if(typeof obj.value != "object" || obj.value == null) continue;
            
            var fields = [obj.value];
            while(fields.length > 0)
            {
                var field = fields.shift();   
                             
                if(field.constructor == Array) {
                    for(var i=0;i<field.length;++i) {
                        if(typeof field[i] == "object" && field[i] != null) 
                            fields.push(field[i]);
                    }
                } else if(field.constructor == Struct) {
                    for(var i in field) {
                        if(typeof field[i] == "object" && field[i] != null) 
                            fields.push(field[i]);
                    }
                } else if(field.constructor == Reference) {
                    if(!field.used) {
                        queue.push(field);
                        field.used = true;
                    }                    
                }
            }
        }

        var newHeap = new Array();
        var finalizables = new Array();
        for(i=0;i<this.heap.length;++i) {
            if(this.heap[i].used) 
                newHeap.push(this.heap[i]);
            else if(this.heap[i].isFinalizable) 
                finalizables.push(this.heap[i]);
            delete this.heap[i].used;
        }
        this.heap = newHeap;
        
        // TODO run finalizables
    }
    
    var thisClr = this;
    window.setInterval( function() {
       AppDomain_tick.call(thisClr);
    }, 20);
    
    function AppDomain_tick() {
        if(this.threads.length > 0) {
            var cutoffTime = new Date().valueOf() + 10;
            
            for(var attempts = this.threads.length;attempts > 0;--attempts) {            
                if(currentThreadIndex >= this.threads.length)
                    currentThreadIndex = 0;
                    
                var thread = this.threads[currentThreadIndex];            
                var active = thread.execute(cutoffTime);
                if(thread.callStack.length == 0) {
                    // thread finished
                    thread.dispose();
                }
                else {                
                    ++currentThreadIndex;
                }     
                         
                if(active) break;
           }
        }
    };        

    this.assemblies = new Object();
    this.loadAssembly = function(name, callback) {
        var currentDomain = this;
        var lowerName = name.toLowerCase();
        if(this.assemblies.hasOwnProperty(lowerName)) {
            callback(this.assemblies[lowerName]);
            return;
        }
            
        readAssembly(name + ".dll", function(data) {
            if(data == undefined) {
                readAssembly(name + ".exe", function(data) {
                    if(data == undefined) {
                        callback(undefined);
                    } else {
                        callback(createAssembly.call(currentDomain, lowerName, data));
                    }
                });
            } else {
                callback(createAssembly.call(currentDomain, lowerName, data));
            }
        });
        
    }

    
    var mscorlib = createAssembly.call(this, "mscorlib", null);
    mscorlib.nativeLib = new MscorlibAssembly();    

    function createAssembly(name, clrData) {
        var assemby = new Assembly(this, name, clrData);
        this.assemblies[name] = assemby;
        return assemby;
    }
}

function Assembly(appDomain, name, clrData) {
    this.appDomain = appDomain;
    this.name = name;
    this.clrData = clrData;
    this.run = function() {
        var entryPoint = this.clrData.header.entryPointToken;
        if((entryPoint >> 24) == CliMetadataTableIndex.MethodDef)
        {
            var args  = appDomain.createObject();
            args.initArray();
            // TODO command line args
            var callFrame = { callingAssembly:this, method:entryPoint, state: 0 };
            
            var thread = appDomain.createThread();
            thread.stack.push(args);            
            thread.callStack.push(callFrame);
        }
        else
            throw "Invalid entry point token";
    };
}

function Thread_execute(cutoffTime) {           
    var result;
    do {
        var frame = this.callStack[this.callStack.length - 1];
        var clrData = frame.callingAssembly.clrData;
        switch(frame.state) {
        case 0: // initialize frame
            frame.previousStackLength = this.stack.length;
            frame.thread = this;
            switch(frame.method >> 24) {
            case 0x06: // MethodDef
                frame.executingAssembly = frame.callingAssembly;
                frame.methodBody = clrData.getMethodBody(frame.method & 0xFFFFFF);
                frame.state = 1;
                frame.methodDef = clrData.metadataTables._MethodDef[frame.method & 0xFFFFFF];
                break;
            case 0x0A: // MemberRef
                var memberRef = clrData.metadataTables._MemberRef[frame.method & 0xFFFFFF];
                var signature = CliSignatureParser.parseMethodDefSig(memberRef.signature.createReader());
                
                switch(memberRef.classRef.table) {
                case 0x01: // TypeRef
                    var typeRef = memberRef.classRef.getItem();
                    switch(typeRef.resolutionScope.table) {
                    case 0x23: // AssemblyRef
                        var assemblyRef = clrData.metadataTables._AssemblyRef[typeRef.resolutionScope.index];
                        var assemblyName = assemblyRef.name.toLowerCase();
                        
                        if(this.appDomain.assemblies[assemblyName] != null) {
                            frame.state = 2;
                            this.appDomain.loadAssembly(assemblyRef.name, function(a) { 
                                frame.executingAssembly = a;
                                frame.state = 3;
                            });
                            return false;
                        } else {
                            frame.executingAssembly = this.appDomain.assemblies[assemblyName];                            
                            frame.state = 3;
                        }
                        break;
                    default:
                        throw "Invalid method class assembly ref";
                    }
                    break;
                default:
                    throw "Invalid method class ref";
                }
            case 0x2B: // MethodSpec
            default:
                throw "Invalid method token";
            }
            result = true;
            break;
        case 1:
            // method body execution setup
            frame.instructionPointer = 0;
            var methodDefSignature = frame.methodDef.signature;
            frame.signature = CliSignatureParser.parseMethodDefSig(methodDefSignature.createReader());
            frame.state = 5; 
            frame.argumentsCount = getMethodArgumentsInStack(frame.signature);
            
            if(frame.methodBody.localVarSigTok != undefined &&
                frame.methodBody.localVarSigTok != 0) {
                frame.locals = new Array();
            }
            result = true;                    
            break;
        case 2:
            // wait for assembly... do nothing
            break;
        case 3:
            // assembly set
            if(frame.executingAssembly.nativeLib != undefined) {
                var memberRef = clrData.metadataTables._MemberRef[frame.method & 0xFFFFFF];
                var typeRef = memberRef.classRef.getItem();
            
                frame.nativeCall = frame.executingAssembly.nativeLib.createCall(typeRef, memberRef);
                frame.state = 4;

                var memberRefSignature = memberRef.signature;
                frame.signature = CliSignatureParser.parseMethodDefSig(memberRefSignature.createReader());
                frame.argumentsCount = getMethodArgumentsInStack(frame.signature);
            } else {
                throw "TODO: find method and class"
            }
            result = true;
            break;
        case 4:
             // native method execution loop
            result = frame.nativeCall.call(frame.executingAssembly.nativeLib, this);
            if(result) {
                frame.state = 6;
            }
            break;
        case 5:
            // method execution
            result = ExecuteClrInstruction(this);
            break;
        case 6:
            for(var i=0;i<frame.argumentsCount;++i) {
                this.stack.pop();
            }
            this.callStack.pop();
            result = true;
            break;
        }
        if(cutoffTime <= new Date().valueOf()) break;
        if(this.callStack.length == 0) break;
    } while(result);
    return result; // active

    function getMethodArgumentsInStack(signature) {
        var argumentsCount = signature.ParamCount;
        if(signature.HASTHIS != undefined) ++argumentsCount;
        return argumentsCount;
    }    
}

function Struct() {
}

function PrimitiveValue(type, value) {
    this.type = type;
    this.value = value;
}

function MemoryPointer(getter, setter) {
    this.getter = getter;
    this.setter = setter;
}

/* Types mapping 

BOOLEAN 0x02 - boolean
CHAR 0x03 - Primitive: number
I1 0x04 - Primitive: number
U1 0x05 - Primitive: number
I2 0x06 - Primitive: number
U2 0x07 - Primitive: number
I4 0x08 - Primitive: number
U4 0x09 - Primitive: number
I8 0x0a - Primitive: string
U8 0x0b  - Primitive: string
R4 0x0c - Primitive: number
R8 0x0d - number
STRING 0x0e - string
PTR 0x0f - Primitive: number
BYREF 0x10 - MemoryPointer
VALUETYPE 0x11 - Struct
CLASS 0x12 - Reference
VAR 0x13 - n/a
ARRAY 0x14 - CliArray
GENERICINST 0x15 - n/a
TYPEDBYREF 0x16 - n/a
I 0x18 - Primitive: number
U 0x19 - Primitive: number
FNPTR 0x1b - Delegate
OBJECT 0x1c - Reference
SZARRAY 0x1d - Array
MVAR 0x1e - n/a

*/