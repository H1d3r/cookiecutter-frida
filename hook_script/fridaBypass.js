// import { just_trust_me } from "./just_trust_me";


var activityCls = Java.use("android.app.Activity");
var bundleCls = Java.use("android.os.Bundle");
var Class = Java.use("java.lang.Class");
var featureList = [];

function hasOwnProperty(obj, name) {
    try {
        return obj.hasOwnProperty(name) || name in obj;
    } catch (e) {
        return obj.hasOwnProperty(name);
    }
}

function getHandle(object) {
    if (hasOwnProperty(object, '$handle')) {
        if (object.$handle != undefined) {
            return object.$handle;
        }
    }
    if (hasOwnProperty(object, '$h')) {
        if (object.$h != undefined) {
            return object.$h;
        }
    }
    return null;
}
//查看域值
function inspectObjectField(obj) {
    var isInstance = false;
    var obj_class = null;
    if (getHandle(obj) === null) {
        obj_class = obj.class;
    } else {
        var Class = Java.use("java.lang.Class");
        obj_class = Java.cast(obj.getClass(), Class);
        isInstance = true;
    }
    console.log("Inspecting Fields: => ", isInstance, " => ", obj_class.toString());
    var fields = obj_class.getDeclaredFields();
    for (var i in fields) {
        if (isInstance || Boolean(fields[i].toString().indexOf("static ") >= 0)) {
            // output = output.concat("\t\t static static static " + fields[i].toString());
            var className = obj_class.toString().trim().split(" ")[1];
            // console.Red("className is => ",className);
            var fieldName = fields[i].toString().split(className.concat(".")).pop();
            var fieldType = fields[i].toString().split(" ").slice(-2)[0];
            var fieldValue = undefined;
            if (!(obj[fieldName] === undefined))
                fieldValue = obj[fieldName].value;
            console.log(fieldType + " \t" + fieldName + " => ", fieldValue + " => ", JSON.stringify(fieldValue));
        }
    }
    return null;
}

function inspectObject(obj) {
    // if (obj == undefined || obj == null) {
    //     console.log("null");
    //     return;
    // }
    var isInstance = false;
    var obj_class = null;
    if (getHandle(obj) === null) {
        obj_class = obj.class;
    } else {
        var Class = Java.use("java.lang.Class");
        obj_class = Java.cast(obj.getClass(), Class);
        isInstance = true;
    }
    var obj_class = Java.cast(obj.getClass(), Class);
    var fields = obj_class.getDeclaredFields();
    var methods = obj_class.getMethods();
    console.log("Inspecting->" + obj.getClass().toString());
    console.log("\t Fields: type, name value, jsonvalue")
    for (var i in fields) {
        var className = obj_class.toString().trim().split(" ")[1];
        var fieldName = fields[i].toString().split(className.concat(".")).pop();
        var fieldType = fields[i].toString().split(" ").slice(-2)[0];
        var fieldValue = undefined;
        if (!(obj[fieldName] === undefined)) {
            fieldValue = obj[fieldName].value;
        }
        // console.log("\t\t" + fields[i].toString());
        console.log("\t\t" + fieldType + " \t" + fieldName + " => ", fieldValue + " => ", JSON.stringify(fieldValue));
    }
    console.log("\t Methods:")
    for (var i in methods) {
        console.log("\t\t" + methods[i].toString())
    }
}

function hardenTest() {
    Java.perform(function () {
        console.log("android version", Java.androidVersion);
    });
}
function getFirstActivity() {
    Java.choose("android.app.Activity", {
        onMatch: function (instance) {
            console.log("first activity", instance);
            return "stop";
        },
        onComplete: function () {
            console.log("", "Activity enumertion complete");
        }
    })
}
function getAllActivity() {
    Java.choose("android.app.Activity", {
        onMatch: function (instance) {
            console.log("activity in heap->", instance);
        },
        onComplete: function () {
            console.log("", "Activity enumertion complete");
        }
    })
}

function hook_activity() {
    Java.perform(function () {
        var Activity = Java.use("android.app.Activity");
        //console.log(Object.getOwnPropertyNames(Activity)); 
        Activity.startActivity.overload('android.content.Intent').implementation = function (p1) {
            console.log("Hooking android.app.Activity.startActivity(p1) successfully,p1=" + p1);
            //console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));  
            console.log(decodeURIComponent(p1.toUri(256)));
            this.startActivity(p1);
        }

        activityCls.onCreate.overload("android.os.Bundle").implementation = function (bundle) {
            var clsName = this.getClass().getName();
            console.log("Activity onCreate->", clsName);
            return this.onCreate(bundle);
        };
        activityCls.onResume.overload().implementation = function () {
            var clsName = this.getClass().getName();
            console.log("Activity onResume->", clsName);
            return this.onResume();
        }
        activityCls.onPause.overload().implementation = function () {
            var clsName = this.getClass().getName();
            console.log("Activity onPause->", clsName);
            return this.onPause();
        }
        activityCls.onRestart.overload().implementation = function () {
            var clsName = this.getClass().getName();
            console.log("Activity onRestart->", clsName);
            return this.onRestart();
        }
    });
}

function hook_dlopen() {
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
        onEnter: function (args) {
            var pathptr = args[0];
            if (pathptr != undefined && pathptr != null) {
                var path = ptr(pathptr).readCString();
                console.log("load:" + path);
            }
        }
    })
}
function hook_open() {
    var ptr_open = Module.findExportByName(null, "open");

    Interceptor.attach(ptr_open, {
        onEnter: function (args) {
            if (args != undefined && args != null) {
                var filename_ptr = args[0];
                var filename = filename_ptr.readCString();
                if (filename.indexOf("/proc") !== -1 ||
                    filename.indexOf(".so") !== -1
                ) {
                    console.log("open hooked->", filename);
                }
            }
        }
    })
}
function hook_replace_str() {
    var ptr_strstr = Module.findExportByName("libc.so", "strstr");
    var ptr_strcmp = Module.findExportByName("libc.so", "strcmp");

    Interceptor.attach(ptr_strstr, {
        onEnter: function (args) {
            var str1 = args[0].readCString();
            var str2 = args[1].readCString();
            if (str2.indexOf("REJECT") !== -1 ||
                // str2.indexOf("tmp") !== -1 ||
                str2.indexOf("frida") !== -1 ||
                str2.indexOf("gum-js-loop") !== -1 ||
                str2.indexOf("gmain") !== -1 ||
                str2.indexOf("xpose") !== -1 ||
                str2.indexOf("linjector") !== -1) {
                if (!featureList.includes(str2)) {
                    featureList.push(str2);
                    console.log("strstr-> " + str1 + " and ", str2);
                    // console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                    //     .map(DebugSymbol.fromAddress).join('\n') + '\n');
                }
                this.hook = true;
            }

        },
        onLeave: function (retval) {
            if (this.hook) {
                retval.replace(0);
            }
        }
    })

    Interceptor.attach(ptr_strcmp, {
        onEnter: function (args) {
            var str1 = args[0].readCString();
            var str2 = args[1].readCString();
            if (str2.indexOf("REJECT") !== -1 ||
                // str2.indexOf("tmp") !== -1 ||
                str2.indexOf("frida") !== -1 ||
                str2.indexOf("gum-js-loop") !== -1 ||
                str2.indexOf("gmain") !== -1 ||
                str2.indexOf("xpose") !== -1 ||
                str2.indexOf("linjector") !== -1) {
                if (!featureList.includes(str2)) {
                    featureList.push(str2);
                    console.log("strcmp-> " + str1 + " and ", str2);
                    // console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                    //     .map(DebugSymbol.fromAddress).join('\n') + '\n');
                }
                this.hook = true;
            }

        },
        onLeave: function (retval) {
            if (this.hook) {
                retval.replace(0);
            }
        }
    })
}

function viewMethods(clsName) {
    if (clsName == undefined || clsName == null) {
        console.error("give class name");
        return;
    }
    Java.perform(function () {
        var classList = Java.enumerateLoadedClassesSync();
        console.log("enumerate loaded class->", classList.length);
        for (var i = 0; i < classList.length; i++) {
            if (classList[i].indexOf(clsName) != -1) {
                var className = classList[i];
                console.log("get target class->", className);
                var methodList = Java.use(className).class.getDeclaredMethods();
                console.log("enumerate methods->", methodList.length);
                for (var j = 0; j < methodList.length; j++) {
                    var method = methodList[j];
                    var methodName = method.getName();
                    console.log("method for " + className + "->", methodName, method, typeof (method));

                }
            }
        }
    })
}
function getLoadedClass(clsName) {
    if (clsName == undefined || clsName == null) {
        console.error("give class name");
        return;
    }
    Java.perform(function () {
        var classList = Java.enumerateLoadedClassesSync();
        console.log("enumerate loaded class->", classList.length);
        for (var i = 0; i < classList.length; i++) {
            if (classList[i].indexOf(clsName) != -1) {
                var className = classList[i];
                console.log("get target class->", className);
                Java.choose(className, {
                    onMatch: function (instance) {
                        console.log("get target object in heap->");
                        inspectObject(instance);

                    },
                    onComplete: function () {
                        console.log("complete for class->", className);
                    }
                })

            }
        }
    })
}
function hook_login() {
    Java.perform(function () {
        var loginCls = Java.use("com.yitong.financialservice.android.activity.login.C8159d");
        getLoadedClass("com.yitong.financialservice.android.activity.login.C8159d");
        loginCls.m6047a.implementation = function (args) {
            console.log("login hooked!");
            loginCls.m6047a(args);
        }

    })
}


function hook_click() {
    Java.perform(function () {
        var View = Java.use('android.view.View');
        var MotionEvent = Java.use('android.view.MotionEvent');
        View.onTouchEvent.overload('android.view.MotionEvent').implementation = function (event) {
            var action = event.getAction();
            if (action === MotionEvent.ACTION_DOWN) {
                console.log('点击事件被触发');
            }
            return this.onTouchEvent(event);
        };
        var Button = Java.use('android.widget.Button');
        Button.setOnClickListener.implementation = function (listener) {
            console.log('按钮被点击了');
            return this.setOnClickListener(listener);
        };

        var clickListener = Java.use("android.view.View$OnClickListener");
        clickListener.onClick.implementation = function (view) {
            console.log("onclick");
            return this.onClick(view);
        }

    });
}
function BypassALL() {
    var BYPASSALL = true;
    if (BYPASSALL) {
        const commonPaths = [
            "/su",
            "/su/bin/su",
            "/system/bin/cufsdosck",
            "/system/xbin/cufsdosck",
            "/system/bin/cufsmgr",
            "/system/xbin/cufsmgr",
            "/system/bin/cufaevdd",
            "/system/xbin/cufaevdd",
            "/system/bin/conbb",
            "/system/xbin/conbb",

            "com.ami.duosupdater.ui",
            "com.ami.launchmetro",
            "com.ami.syncduosservices",
            "com.bluestacks.home",
            "com.bluestacks.windowsfilemanager",
            "com.bluestacks.settings",
            "com.bluestacks.bluestackslocationprovider",
            "com.bluestacks.appsettings",
            "com.bluestacks.bstfolder",
            "com.bluestacks.BstCommandProcessor",
            "com.bluestacks.s2p",
            "com.bluestacks.setup",
            "com.kaopu001.tiantianserver",
            "com.kpzs.helpercenter",
            "com.kaopu001.tiantianime",
            "com.android.development_settings",
            "com.android.development",
            "com.android.customlocale2",
            "com.genymotion.superuser",
            "com.genymotion.clipboardproxy",
            "com.uc.xxzs.keyboard",
            "com.uc.xxzs",
            "com.blue.huang17.agent",
            "com.blue.huang17.launcher",
            "com.blue.huang17.ime",
            "com.microvirt.guide",
            "com.microvirt.market",
            "com.microvirt.memuime",
            "cn.itools.vm.launcher",
            "cn.itools.vm.proxy",
            "cn.itools.vm.softkeyboard",
            "cn.itools.avdmarket",
            "com.syd.IME",
            "com.bignox.app.store.hd",
            "com.bignox.launcher",
            "com.bignox.app.phone",
            "com.bignox.app.noxservice",
            "com.android.noxpush",
            "com.haimawan.push",
            "me.haima.helpcenter",
            "com.windroy.launcher",
            "com.windroy.superuser",
            "com.windroy.launcher",
            "com.windroy.ime",
            "com.android.flysilkworm",
            "com.android.emu.inputservice",
            "com.tiantian.ime",
            "com.microvirt.launcher",
            "me.le8.androidassist",
            "com.vphone.helper",
            "com.vphone.launcher",
            "com.duoyi.giftcenter.giftcenter",

            "/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace",
            "/system/bin/qemu-props",
            "/dev/socket/qemud",
            "/dev/qemu_pipe",
            "/dev/socket/baseband_genyd",
            "/dev/socket/genyd",


            // orignial:
            "/data/local/bin/su",
            "/data/local/su",
            "/data/local/xbin/su",
            "/dev/com.koushikdutta.superuser.daemon/",
            "/sbin/su",
            "/system/app/Superuser.apk",
            "/system/bin/failsafe/su",
            "/system/bin/su",
            "/su/bin/su",
            "/system/etc/init.d/99SuperSUDaemon",
            "/system/sd/xbin/su",
            "/system/xbin/busybox",
            "/system/xbin/daemonsu",
            "/system/xbin/su",
            "/system/sbin/su",
            "/vendor/bin/su",
            "/cache/su",
            "/data/su",
            "/dev/su",
            "/system/bin/.ext/su",
            "/system/usr/we-need-root/su",
            "/system/app/Kinguser.apk",
            "/data/adb/magisk",
            "/sbin/.magisk",
            "/cache/.disable_magisk",
            "/dev/.magisk.unblock",
            "/cache/magisk.log",
            "/data/adb/magisk.img",
            "/data/adb/magisk.db",
            "/data/adb/magisk_simple",
            "/init.magisk.rc",
            "/system/xbin/ku.sud",
            "/data/adb/ksu",
            "/data/adb/ksud"
        ];

        const ROOTmanagementApp = [
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.koushikdutta.rommanager",
            "com.koushikdutta.rommanager.license",
            "com.dimonvideo.luckypatcher",
            "com.chelpus.lackypatch",
            "com.ramdroid.appquarantine",
            "com.ramdroid.appquarantinepro",
            "com.topjohnwu.magisk",
            "me.weishu.kernelsu"
        ];



        function stackTraceHere(isLog) {
            var Exception = Java.use('java.lang.Exception');
            var Log = Java.use('android.util.Log');
            var stackinfo = Log.getStackTraceString(Exception.$new())
            if (isLog) {
                console.log(stackinfo)
            } else {
                return stackinfo
            }
        }

        function stackTraceNativeHere(isLog) {
            var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress)
                .join("\n\t");
            console.log(backtrace)
        }


        function bypassJavaFileCheck() {
            var UnixFileSystem = Java.use("java.io.UnixFileSystem")
            UnixFileSystem.checkAccess.implementation = function (file, access) {

                var stack = stackTraceHere(false)

                const filename = file.getAbsolutePath();

                if (filename.indexOf("magisk") >= 0) {
                    console.log("Anti Root Detect - check file: " + filename)
                    return false;
                }

                if (commonPaths.indexOf(filename) >= 0) {
                    console.log("Anti Root Detect - check file: " + filename)
                    return false;
                }

                return this.checkAccess(file, access)
            }

            //Update
            var IoFile = Java.use("java.io.File");
            var b = false;
            var i = 0;
            IoFile.exists.implementation = function () {
                // if (i < 10) {
                //     console.log(inspectObject(this));
                //     b = true;
                //     i +=1;
                // }
                var field = IoFile.class.getDeclaredField("path");
                field.setAccessible(true);
                var path = field.get(this);
                // if (i < 10) {
                //     console.log("File.exists called with ", path);
                //     i += 1;
                //     return false;
                // }
                if (commonPaths.indexOf(path) >= 0) {
                    console.log("File.exists called with ", path);
                    return false;
                }
                return this.exists();
            }
        }

        function bypassNativeFileCheck() {
            var fopen = Module.findExportByName("libc.so", "fopen")
            Interceptor.attach(fopen, {
                onEnter: function (args) {
                    this.inputPath = args[0].readUtf8String()
                },
                onLeave: function (retval) {
                    if (retval.toInt32() != 0) {
                        if (commonPaths.indexOf(this.inputPath) >= 0) {
                            console.log("Anti Root Detect - fopen : " + this.inputPath)
                            retval.replace(ptr(0x0))
                        }
                    }
                }
            })

            var access = Module.findExportByName("libc.so", "access")
            Interceptor.attach(access, {
                onEnter: function (args) {
                    this.inputPath = args[0].readUtf8String()
                },
                onLeave: function (retval) {
                    if (retval.toInt32() == 0) {
                        if (commonPaths.indexOf(this.inputPath) >= 0) {
                            console.log("Anti Root Detect - access : " + this.inputPath)
                            retval.replace(ptr(-1))
                        }
                    }
                }
            })
        }

        function setProp() {
            var Build = Java.use("android.os.Build")
            var TAGS = Build.class.getDeclaredField("TAGS")
            TAGS.setAccessible(true)
            TAGS.set(null, "release-keys")

            var FINGERPRINT = Build.class.getDeclaredField("FINGERPRINT")
            FINGERPRINT.setAccessible(true)
            FINGERPRINT.set(null, "google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys")

            // Build.deriveFingerprint.inplementation = function(){
            //     var ret = this.deriveFingerprint() //该函数无法通过反射调用
            //     console.log(ret)
            //     return ret
            // }

            var system_property_get = Module.findExportByName("libc.so", "__system_property_get")
            Interceptor.attach(system_property_get, {
                onEnter(args) {
                    this.key = args[0].readCString()
                    this.ret = args[1]
                },
                onLeave(ret) {
                    if (this.key == "ro.build.fingerprint") {
                        var tmp = "google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys"
                        var p = Memory.allocUtf8String(tmp)
                        Memory.copy(this.ret, p, tmp.length + 1)
                    }
                }
            })

        }

        //android.app.PackageManager
        function bypassRootAppCheck() {
            var ApplicationPackageManager = Java.use("android.app.ApplicationPackageManager")
            ApplicationPackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (str, i) {
                // console.log(str)
                if (ROOTmanagementApp.indexOf(str) >= 0) {
                    console.log("Anti Root Detect - check package : " + str)
                    str = "ashen.one.ye.not.found"
                }
                return this.getPackageInfo(str, i)
            }

            //shell pm check
        }

        function bypassShellCheck() {
            var String = Java.use('java.lang.String')

            var ProcessImpl = Java.use("java.lang.ProcessImpl")
            ProcessImpl.start.implementation = function (cmdarray, env, dir, redirects, redirectErrorStream) {

                if (cmdarray[0] == "mount") {
                    console.log("Anti Root Detect - Shell : " + cmdarray.toString())
                    arguments[0] = Java.array('java.lang.String', [String.$new("")])
                    return ProcessImpl.start.apply(this, arguments)
                }

                if (cmdarray[0] == "getprop") {
                    console.log("Anti Root Detect - Shell : " + cmdarray.toString())
                    const prop = [
                        "ro.secure",
                        "ro.debuggable"
                    ];
                    if (prop.indexOf(cmdarray[1]) >= 0) {
                        arguments[0] = Java.array('java.lang.String', [String.$new("")])
                        return ProcessImpl.start.apply(this, arguments)
                    }
                }

                if (cmdarray[0].indexOf("which") >= 0) {
                    const prop = [
                        "su"
                    ];
                    if (prop.indexOf(cmdarray[1]) >= 0) {
                        console.log("Anti Root Detect - Shell : " + cmdarray.toString())
                        arguments[0] = Java.array('java.lang.String', [String.$new("")])
                        return ProcessImpl.start.apply(this, arguments)
                    }
                }

                return ProcessImpl.start.apply(this, arguments)
            }
        }


        // console.log("Attach")
        bypassNativeFileCheck()
        bypassJavaFileCheck()
        setProp()
        bypassRootAppCheck()
        bypassShellCheck()
    }
}
function hook_certificateFactory(quiet = true) {
    Java.perform(function () {
        var CerFactory = Java.use("java.security.cert.CertificateFactory")
        var is = Java.use("java.io.InputStream")
        CerFactory.generateCertificate.overload("java.io.InputStream").implementation = function (inputStream) {
            // var byteArray = Java.array('byte', 10240);
            // inputStream.read(byteArray);
            var result = '';
            // for (var i = 0; i < byteArray.length; i++) {
            // result += String.fromCharCode(byteArray[i] & 0xff);
            // }
            while (inputStream.available()) {
                var i = inputStream.read();
                var c = String.fromCharCode(i & 0xff);
                result += c;
            }
            if (!quiet)
                console.log("generateCertificate read: \n----\n" + result + "\n------\n")
            return this.generateCertificate(inputStream)
        }
    })
}

function parse_enumeration(e) {
    var res = "";
    while (e.hasMoreElements()) {
        var s = e.nextElement();
        res += s;
        res += ";";
    }
    return res;
}
function dump_certificate(cer) {
    var bytearr = cer.getEncoded();
    var result = "";
    for (var i = 0; i < bytearr.length; i++) {
        var c = String.fromCharCode(bytearr[i] & 0xff);
        result += c;
    }
    console.log("Certificate dump cer:\n---------\n" + result + "\n-------------\n")
}
function hook_trustfactory() {
    Java.perform(function () {
        var fac = Java.use("javax.net.ssl.TrustManagerFactory")
        fac.init.overload("java.security.KeyStore").implementation = function (keystore) {
            console.log("trustfactory init called")
            // var a = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new())
            // console.log(a);
            return this.init(keystore)
        }
        fac.getTrustManagers.implementation = function () {
            var ret = this.getTrustManagers()
            console.log("getTrustManager:")
            console.log(ret)
            console.log(ret == null)
            console.log(ret.length)
            return ret
            // inspectObject(ret)
        }
    })
}
function hook_keystore() {
    Java.perform(function () {
        var cls = Java.use("java.security.KeyStore");
        cls.setCertificateEntry.overload("java.lang.String", "java.security.cert.Certificate").implementation = function (s, cer) {
            if (s === "smfp") {
                console.log("KeyStore.setCertificateEntry called " + s);
                var bytearr = cer.getEncoded();
                var result = "";
                for (var i = 0; i < bytearr.length; i++) {
                    var c = String.fromCharCode(bytearr[i] & 0xff);
                    result += c;
                }
                console.log("Keystore dump cer:\n---------\n" + result + "\n-------------\n")
            }
            console.log("Keystore setCertificateEntry: " + s);

            return this.setCertificateEntry(s, cer);
        }
        cls.getInstance.overload("java.lang.String").implementation = function (s) {
            console.log("Keystore getInstance called with: " + s);
            if (s === "BKS") {
                // var a = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new())
                // console.log(a);
            }
            return cls.getInstance(s);
        }
        cls.load.overload("java.security.KeyStore$LoadStoreParameter").implementation = function (p) {
            console.log("Keystore load called with " + p);
            return this.load(p);
        }
        cls.aliases.overload().implementation = function () {
            console.log("Keystore aliases called, result: " + parse_enumeration(this.aliases()));
            return this.aliases();
        }
        cls.getCertificate.overload("java.lang.String").implementation = function (s) {
            console.log("Keystore getCertificate called with: " + s);
            var cer = this.getCertificate(s);
            // dump_certificate(cer);
            return this.getCertificate(s);
        }

    })
}
function parse_certificate(cer, dump = false) {
    try {
        var d = "";
        var type = cer.getType();

        if (dump) {
            var bytearr = cer.getEncoded();
            var result = "";
            for (var i = 0; i < bytearr.length; i++) {
                var c = String.fromCharCode(bytearr[i] & 0xff);
                result += c;
            }
            d = "Certificate dump cer:\n---------\n" + result + "\n-------------\n";
        }
        var res = "[Certificate] Type: " + type + ", Dump:\n" + d;
        return res;
    } catch (err) {
        console.log("[Certificate] ");
        console.log(cer);
        console.log(err.toString());
    }

}
function get_keystore() {
    Java.choose("java.security.KeyStore", {
        onMatch: function (cer) {
            // inspectObject(cer);
            console.log("Find keystore in heap", cer);
            console.log("Size: " + cer.size() + "; Type: " + cer.getType() + "; CreationDate: " + cer.getCreationDate("smfp"));
            var e = cer.aliases();
            var r = parse_enumeration(e);
            console.log("Aliases: " + r);
        },
        onComplete: function () {
            console.log("", "Keystore enumertion complete");
        }
    })
}
function get_cer() {
    Java.choose("java.security.cert.Certificate", {
        onMatch: function (cer) {
            console.log("Find certificate in heap, type:" + cer.getType());
            var bytearr = cer.getEncoded();
            var result = "";
            for (var i = 0; i < bytearr.length; i++) {
                var c = String.fromCharCode(bytearr[i] & 0xff);
                result += c;
            }
            console.log("Certificate dump cer:\n---------\n" + result + "\n-------------\n")
        },
        onComplete: function () {
            console.log("", "Certificate enumeration complete");
        }


    })
}
function keystore_gettype() {
    Java.perform(function () {
        var cls = Java.use("java.security.KeyStore");
        var s = cls.getDefaultType();
        console.log(s);
    })
}

// var userInfoCls = Java.use("io.agora.rtc.models.UserInfo"); // class not found
function hook_getUserInfo() {
    Java.perform(function () {
        var cls = Java.use("io.agora.rtc.internal.RtcEngine");
        cls.getUserInfoByUid.overload("java.lang.Integer", "io.agora.rtc.models.UserInfo").implementation = function (id, userInfo) {
            var uid = userInfo.uid;
            var acc = userInfo.userAccount;
            var ret = this.getUserInfoByUid(id, userInfo);
            console.log("getUserInfo called with: " + id.toString() + "," + uid.toString() + "," + acc.toString() + "; ret: " + ret.toString());
            return ret;
        }
        var cls2 = Java.use("io.agora.rtc.RtcEngine");
        cls2.getUserInfoByUserAccount.overload("java.lang.String", "io.agora.rtc.models.UserInfo").implementation = function (id, userInfo) {
            var uid = userInfo.uid;
            var acc = userInfo.userAccount;
            var ret = this.getUserInfoByUid(id, userInfo);
            console.log("getUserInfo called with: " + id.toString() + "," + uid.toString() + "," + acc.toString() + "; ret: " + ret.toString());
            return ret;
        }
    })
}
function SSLUnpinning() {
    var SSLUNPINNING = true;
    if (SSLUNPINNING) {
        // DroidSSLUnpinning
        Java.perform(function () {

            /*
            hook list:
            1.SSLcontext
            2.okhttp
            3.webview
            4.XUtils
            5.httpclientandroidlib
            6.JSSE
            7.network\_security\_config (android 7.0+)
            8.Apache Http client (support partly)
            9.OpenSSLSocketImpl
            10.TrustKit
            11.Cronet
            */

            // Attempts to bypass SSL pinning implementations in a number of
            // ways. These include implementing a new TrustManager that will
            // accept any SSL certificate, overriding OkHTTP v3 check()
            // method etc.
            var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
            var SSLContext = Java.use('javax.net.ssl.SSLContext');
            var quiet_output = false;

            // Helper method to honor the quiet flag.

            function quiet_send(data) {

                if (quiet_output) {

                    return;
                }

                send(data)
            }
            function default_exception_handler(e) {
                quiet_send("Exception  >>>>>>>> " + e.message);

            }
            try {



                // Implement a new TrustManager
                // ref: https://gist.github.com/oleavr/3ca67a173ff7d207c6b8c3b0ca65a9d8
                // Java.registerClass() is only supported on ART for now(201803). 所以android 4.4以下不兼容,4.4要切换成ART使用.
                /*
            06-07 16:15:38.541 27021-27073/mi.sslpinningdemo W/System.err: java.lang.IllegalArgumentException: Required method checkServerTrusted(X509Certificate[], String, String, String) missing
            06-07 16:15:38.542 27021-27073/mi.sslpinningdemo W/System.err:     at android.net.http.X509TrustManagerExtensions.<init>(X509TrustManagerExtensions.java:73)
                    at mi.ssl.MiPinningTrustManger.<init>(MiPinningTrustManger.java:61)
            06-07 16:15:38.543 27021-27073/mi.sslpinningdemo W/System.err:     at mi.sslpinningdemo.OkHttpUtil.getSecPinningClient(OkHttpUtil.java:112)
                    at mi.sslpinningdemo.OkHttpUtil.get(OkHttpUtil.java:62)
                    at mi.sslpinningdemo.MainActivity$1$1.run(MainActivity.java:36)
            */
                var X509Certificate = Java.use("java.security.cert.X509Certificate");
                var TrustManager;
                try {
                    TrustManager = Java.registerClass({
                        name: 'org.wooyun.TrustManager',
                        implements: [X509TrustManager],
                        methods: {
                            checkClientTrusted: function (chain, authType) { },
                            checkServerTrusted: function (chain, authType) { },
                            getAcceptedIssuers: function () {
                                // var certs = [X509Certificate.$new()];
                                // return certs;
                                return [];
                            }
                        }
                    });
                } catch (e) {
                    quiet_send("registerClass from X509TrustManager >>>>>>>> " + e.message);
                }





                // Prepare the TrustManagers array to pass to SSLContext.init()
                var TrustManagers = [TrustManager.$new()];

                try {
                    // Prepare a Empty SSLFactory
                    var TLS_SSLContext = SSLContext.getInstance("TLS");
                    TLS_SSLContext.init(null, TrustManagers, null);
                    var EmptySSLFactory = TLS_SSLContext.getSocketFactory();
                } catch (e) {
                    quiet_send(e.message);
                }

                send('Custom, Empty TrustManager ready');

                // Get a handle on the init() on the SSLContext class
                var SSLContext_init = SSLContext.init.overload(
                    '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');

                // Override the init method, specifying our new TrustManager
                //TODO:1
                // SSLContext_init.implementation = function (keyManager, trustManager, secureRandom) {

                //     quiet_send('Overriding SSLContext.init() with the custom TrustManager');

                //     SSLContext_init.call(this, null, TrustManagers, null);
                // };

                /*** okhttp3.x unpinning ***/


                // Wrap the logic in a try/catch as not all applications will have
                // okhttp as part of the app.
                try {

                    var CertificatePinner = Java.use('okhttp3.CertificatePinner');

                    quiet_send('OkHTTP 3.x Found');

                    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function () {

                        quiet_send('OkHTTP 3.x check() called. Not throwing an exception.');
                    }

                } catch (err) {

                    // If we dont have a ClassNotFoundException exception, raise the
                    // problem encountered.
                    if (err.message.indexOf('ClassNotFoundException') === 0) {

                        throw new Error(err);
                    }
                    else {
                        default_exception_handler(err)
                    }
                }

                // Appcelerator Titanium PinningTrustManager

                // Wrap the logic in a try/catch as not all applications will have
                // appcelerator as part of the app.
                try {

                    var PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');

                    send('Appcelerator Titanium Found');

                    PinningTrustManager.checkServerTrusted.implementation = function () {

                        quiet_send('Appcelerator checkServerTrusted() called. Not throwing an exception.');
                    }

                } catch (err) {

                    // If we dont have a ClassNotFoundException exception, raise the
                    // problem encountered.
                    if (err.message.indexOf('ClassNotFoundException') === 0) {

                        throw new Error(err);
                    }
                    else {
                        default_exception_handler(err)
                    }
                }

                /*** okhttp unpinning ***/


                try {
                    var OkHttpClient = Java.use("com.squareup.okhttp.OkHttpClient");
                    OkHttpClient.setCertificatePinner.implementation = function (certificatePinner) {
                        // do nothing
                        quiet_send("OkHttpClient.setCertificatePinner Called!");
                        return this;
                    };

                    // Invalidate the certificate pinnet checks (if "setCertificatePinner" was called before the previous invalidation)
                    var CertificatePinner = Java.use("com.squareup.okhttp.CertificatePinner");
                    CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (p0, p1) {
                        // do nothing
                        quiet_send("okhttp Called! [Certificate]");
                        return;
                    };
                    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (p0, p1) {
                        // do nothing
                        quiet_send("okhttp Called! [List]");
                        return;
                    };
                } catch (e) {
                    quiet_send("com.squareup.okhttp not found");
                }

                /*** WebView Hooks ***/

                /* frameworks/base/core/java/android/webkit/WebViewClient.java */
                /* public void onReceivedSslError(Webview, SslErrorHandler, SslError) */
                try {
                    var WebViewClient = Java.use("android.webkit.WebViewClient");

                    WebViewClient.onReceivedSslError.implementation = function (webView, sslErrorHandler, sslError) {
                        quiet_send("WebViewClient onReceivedSslError invoke");
                        //执行proceed方法
                        sslErrorHandler.proceed();
                        return;
                    };

                    WebViewClient.onReceivedError.overload('android.webkit.WebView', 'int', 'java.lang.String', 'java.lang.String').implementation = function (a, b, c, d) {
                        quiet_send("WebViewClient onReceivedError invoked");
                        return;
                    };

                    WebViewClient.onReceivedError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError').implementation = function () {
                        quiet_send("WebViewClient onReceivedError invoked");
                        return;
                    };
                } catch (err) {
                    default_exception_handler(err)
                }

                /*** JSSE Hooks ***/

                /* libcore/luni/src/main/java/javax/net/ssl/TrustManagerFactory.java */
                /* public final TrustManager[] getTrustManager() */
                /* TrustManagerFactory.getTrustManagers maybe cause X509TrustManagerExtensions error  */
                // var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
                // TrustManagerFactory.getTrustManagers.implementation = function(){
                //     quiet_send("TrustManagerFactory getTrustManagers invoked");
                //     return TrustManagers;
                // }
                try {
                    var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
                    /* libcore/luni/src/main/java/javax/net/ssl/HttpsURLConnection.java */
                    /* public void setDefaultHostnameVerifier(HostnameVerifier) */
                    HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (hostnameVerifier) {
                        quiet_send("HttpsURLConnection.setDefaultHostnameVerifier invoked");
                        // return null;
                    };
                    /* libcore/luni/src/main/java/javax/net/ssl/HttpsURLConnection.java */
                    /* public void setSSLSocketFactory(SSLSocketFactory) */
                    HttpsURLConnection.setSSLSocketFactory.implementation = function (SSLSocketFactory) {
                        quiet_send("HttpsURLConnection.setSSLSocketFactory invoked");
                        return null;
                    };
                    /* libcore/luni/src/main/java/javax/net/ssl/HttpsURLConnection.java */
                    /* public void setHostnameVerifier(HostnameVerifier) */
                    HttpsURLConnection.setHostnameVerifier.implementation = function (hostnameVerifier) {
                        quiet_send("HttpsURLConnection.setHostnameVerifier invoked");
                        return null;
                    };
                } catch (err) {
                    default_exception_handler(err)
                }

                /*** Xutils3.x hooks ***/
                //Implement a new HostnameVerifier
                var TrustHostnameVerifier;
                try {
                    TrustHostnameVerifier = Java.registerClass({
                        name: 'org.wooyun.TrustHostnameVerifier',
                        implements: [HostnameVerifier],
                        methods: {
                            verify(hostname, session) {
                                return true;
                            }
                            // verify: [{
                            //     returnType: 'bolean',
                            //     argumentTypes: ['java.lang.String', 'javax.net.ssl.SSLSession'],
                            //     implementation(hostname, session) {
                            //         return true;
                            //     }
                            // }]
                        }
                    });

                } catch (e) {
                    //java.lang.ClassNotFoundException: Didn't find class "org.wooyun.TrustHostnameVerifier"
                    quiet_send("registerClass from hostnameVerifier >>>>>>>> " + e.message);
                }

                try {
                    var RequestParams = Java.use('org.xutils.http.RequestParams');
                    RequestParams.setSslSocketFactory.implementation = function (sslSocketFactory) {
                        sslSocketFactory = EmptySSLFactory;
                        return null;
                    }

                    RequestParams.setHostnameVerifier.implementation = function (hostnameVerifier) {
                        hostnameVerifier = TrustHostnameVerifier.$new();
                        return null;
                    }

                } catch (e) {
                    quiet_send("Xutils hooks not Found");
                }

                /*** httpclientandroidlib Hooks ***/
                try {
                    var AbstractVerifier = Java.use("ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier");
                    AbstractVerifier.verify.overload('java.lang.String', '[Ljava.lang.String', '[Ljava.lang.String', 'boolean').implementation = function () {
                        quiet_send("httpclientandroidlib Hooks");
                        return null;
                    }
                } catch (e) {
                    quiet_send("httpclientandroidlib Hooks not found");
                }

                /***
            android 7.0+ network_security_config TrustManagerImpl hook
            apache httpclient partly
            ***/
                try {

                    var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");

                    // try {
                    //     var Arrays = Java.use("java.util.Arrays");
                    //     //apache http client pinning maybe baypass
                    //     //https://github.com/google/conscrypt/blob/c88f9f55a523f128f0e4dace76a34724bfa1e88c/platform/src/main/java/org/conscrypt/TrustManagerImpl.java#471
                    //     TrustManagerImpl.checkTrusted.implementation = function (chain, authType, session, parameters, authType) {
                    //         quiet_send("TrustManagerImpl checkTrusted called");
                    //         //Generics currently result in java.lang.Object
                    //         return Arrays.asList(chain);
                    //     }
                    //
                    // } catch (e) {
                    //     quiet_send("TrustManagerImpl checkTrusted nout found");
                    // }

                    // Android 7+ TrustManagerImpl
                    TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                        quiet_send("TrustManagerImpl verifyChain called");
                        // Skip all the logic and just return the chain again :P
                        //https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2017/november/bypassing-androids-network-security-configuration/
                        // https://github.com/google/conscrypt/blob/c88f9f55a523f128f0e4dace76a34724bfa1e88c/platform/src/main/java/org/conscrypt/TrustManagerImpl.java#L650
                        return untrustedChain;
                    }
                } catch (e) {
                    quiet_send("TrustManagerImpl verifyChain not found below 7.0");
                }
                // OpenSSLSocketImpl
                try {
                    var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
                    OpenSSLSocketImpl.verifyCertificateChain.implementation = function (certRefs, authMethod) {
                        quiet_send('OpenSSLSocketImpl.verifyCertificateChain');
                    }

                    quiet_send('OpenSSLSocketImpl pinning')
                } catch (err) {
                    quiet_send('OpenSSLSocketImpl pinner not found');
                }
                // Trustkit
                try {
                    var Activity = Java.use("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier");
                    Activity.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (str) {
                        quiet_send('Trustkit.verify1: ' + str);
                        return true;
                    };
                    Activity.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (str) {
                        quiet_send('Trustkit.verify2: ' + str);
                        return true;
                    };

                    quiet_send('Trustkit pinning')
                } catch (err) {
                    quiet_send('Trustkit pinner not found')
                }

                try {
                    //cronet pinner hook
                    //weibo don't invoke

                    var netBuilder = Java.use("org.chromium.net.CronetEngine$Builder");

                    //https://developer.android.com/guide/topics/connectivity/cronet/reference/org/chromium/net/CronetEngine.Builder.html#enablePublicKeyPinningBypassForLocalTrustAnchors(boolean)
                    netBuilder.enablePublicKeyPinningBypassForLocalTrustAnchors.implementation = function (arg) {

                        //weibo not invoke
                        console.log("Enables or disables public key pinning bypass for local trust anchors = " + arg);

                        //true to enable the bypass, false to disable.
                        var ret = netBuilder.enablePublicKeyPinningBypassForLocalTrustAnchors.call(this, true);
                        return ret;
                    };

                    netBuilder.addPublicKeyPins.implementation = function (hostName, pinsSha256, includeSubdomains, expirationDate) {
                        console.log("cronet addPublicKeyPins hostName = " + hostName);

                        //var ret = netBuilder.addPublicKeyPins.call(this,hostName, pinsSha256,includeSubdomains, expirationDate);
                        //this 是调用 addPublicKeyPins 前的对象吗? Yes,CronetEngine.Builder
                        return this;
                    };

                } catch (err) {
                    console.log('[-] Cronet pinner not found')
                }
            } catch (err) {
                default_exception_handler(err)
            }
        }
        );


    }

}
function get_classname(o) {
    try {
        var c = Java.cast(o, Java.use("java.lang.Object")).getClass().toString();
        // var c = o.$className;
        return c;
    } catch (err) {
        console.log(err);
        return "<empty className>";
    }
}

function hook_trustManagerImpl() {
    Java.perform(function () {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.overload("java.util.List", "java.util.List", "java.lang.String", "boolean", "[B", "[B").implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log("TrustManagerImpl verifyChain called");
            // inspectObject(this);
            console.log("UntrustedChain:\n----------------");
            for (var i in untrustedChain) {
                console.log("classname:" + get_classname(i))
                var s = parse_certificate(i, false);
                try {
                    var alg = i.getSigAlgName();
                } catch (err) {
                    var alg = "";
                    console.log(err);
                }
                var res = "[X509Certificate] Alg: " + alg;
                console.log(res);
            }
            console.log("\n------------------\nTrustAnchorChain:\n-------------------")
            for (var i in trustAnchorChain) {
                var s = i.toString();

                console.log("[TrustAnchor] " + s);
            }
            console.log("\n---------------------\n Host: " + host);
            console.log("End verifyChain");
            // Skip all the logic and just return the chain again :P
            //https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2017/november/bypassing-androids-network-security-configuration/
            // https://github.com/google/conscrypt/blob/c88f9f55a523f128f0e4dace76a34724bfa1e88c/platform/src/main/java/org/conscrypt/TrustManagerImpl.java#L650
            return untrustedChain;
        }
    })
}
function print_stack() {
    var a = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
    console.log(a);
}
function parse_trustAnchor(a) {
    try {
        if (a == undefined || a == null) {
            return "[TrustAnchor] None";
        }
        var ca = a.getCAName();
        var nc = a.getNameConstraints();
        var ncres = "";
        for (var i in nc) {
            ncres += String.fromCharCode(i & 0xff);
        }
        return "[TrustAnchor] ca: " + ca + ", nameConstraints: " + ncres;
    } catch (err) {
        console.log("[TrustAnchor] ");
        console.log(a);
        return "[TrustAnchor] " + err.toString();
    }
}
function hook_trustManagerImpl_check() {
    try {
        // Bypass TrustManagerImpl (Android > 7) {1}
        var array_list = Java.use("java.util.ArrayList");
        var TrustManagerImpl_Activity_1 = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl_Activity_1.checkTrustedRecursive.implementation = function (certs, ocspData, tlsSctData, host, clientAuth, untrustedChain, trustAnchorChain, used) {
            console.log('[+] Bypassing TrustManagerImpl (Android > 7) checkTrustedRecursive check for: ' + host);
            if (host == "api.yallaokey101.com") {
                // var a = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
                var c = certs.length;
                var tac = trustAnchorChain.size();
                console.log("Certs: " + c.toString() + ", anchors: " + tac.toString());
                // console.log(certs);
                // console.log(trustAnchorChain);
                for (var ci = 0; ci < certs.length; ci++) {
                    console.log(parse_certificate(certs[ci]));
                }
                for (var ti = 0; ti < trustAnchorChain.size(); ti++) {
                    console.log(parse_trustAnchor(trustAnchorChain.get(ti)));
                }
            }
            var l = this.checkTrustedRecursive(certs, ocspData, tlsSctData, host, clientAuth, untrustedChain, trustAnchorChain, used);
            console.log("Res:" + l.size());
            for (var i = 0; i < l.size(); i++) {
                console.log(parse_certificate(l.get(i), true));
            }

            // console.log(a);
            return array_list.$new();
        };
    } catch (err) {
        console.log('[-] TrustManagerImpl (Android > 7) checkTrustedRecursive check not found');
        //console.log(err);
        errDict[err] = ['com.android.org.conscrypt.TrustManagerImpl', 'checkTrustedRecursive'];
    }
}
function hook_pthread_create() {
    let pthread_create = Module.findExportByName(null, "pthread_create")
    let org_pthread_create = new NativeFunction(pthread_create, "int", ["pointer", "pointer", "pointer", "pointer"])
    let my_pthread_create = new NativeCallback(function (a, b, c, d) {
        console.log("pthread_create");
        // var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
        //     .map(DebugSymbol.fromAddress)
        //     .join("\n\t");
        // console.log(backtrace);
        // let m = Process.getModuleByName("libDexHelper.so");
        // let base = m.base
        // console.log(Process.getModuleByAddress(c).name)
        // if (Process.getModuleByAddress(c).name == m.name) {
        //     console.log("pthread_create")
        //     return 0;
        // }
        return org_pthread_create(a, b, c, d)
    }, "int", ["pointer", "pointer", "pointer", "pointer"])
    Interceptor.replace(pthread_create, my_pthread_create)
}

// import { just_trust_me } from "./just_trust_me";

function decryption() {
    Java.perform(function () {
        // 代理检测绕过
        // var StringClass = Java.use("java.lang.String");

        // StringClass.contains.implementation = function (subString) {
        //     var result = this.contains(subString);
        //     if (subString == "ZHEJIANG RURAL CREDIT UNION") {
        //         result = true;
        //     }
        //     return result;
        // };



        let CryptoUtil = Java.use("com.yitong.mbank.util.security.CryptoUtil");
        CryptoUtil["genRandomKey"].implementation = function () {
            console.log(`CryptoUtil.genRandomKey is called`);
            let result = this["genRandomKey"]();
            result = "0000000000000000"    //固定密钥
            return result;
        };


        //加密请求包
        // let i = Java.choose("com.yitong.mbank.app.android.application.MyApplication$i", {

        //     onMatch: function (instance) {

        //         // str需要修改为请求内容
        //         var str = '{"payload":{"template":"9W20160922000010","ORGAN_CODE":"999000","APP_VERS":"6.0.6","deviceNO":"7c33671e6ed0ee793783a5cec3da935a","APP_DEVICE_TYPE":"Android"},"header":{"_t":1706764264945,"service":"commonService/getContractUrl"}}'


        //         // 固定密钥，无需修改
        //         var str2 = '0000000000000000'
        //         console.log("----------------------------------------------------")
        //         console.log(`text=${str}`);
        //         let result = instance["getEncryptString"](str, str2);
        //         var replaceStr = result.replace(/\x1D/g, "<GS>")
        //         console.log(`result=${replaceStr}`);
        //     },
        //     onComplete: function () {
        //     }

        // })



        let s = Java.use("com.yitong.mbank.app.android.application.MyApplication$i");
        s["getEncryptString"].implementation = function (str, str2) {
            console.log("-------------------------")

            console.log(`text before modify: str=${str}, str2=${str2}`);
            var data = str
            send({ from: "/http", payload: data, api_path: "request" }); //将dataStr发送到burpTracer.py
            // <!-- 接收burp篡改后返回的数据 ↓-->
            var op = recv("input", function (value) {
                data = value.payload
            });
            op.wait();
            let result = this["getEncryptString"](data, str2);
            console.log(`result=${result}`);
            return result;
        };

    });

}
function encrypt(str) {
    Java.choose("com.yitong.mbank.app.android.application.MyApplication$i", {

        onMatch: function (instance) {

            // str需要修改为请求内容
            // var str = '{"header":{"service":"ePaymentService/getPhoneInfo","method":"get","staticData":false,"options":[],"_t":"1709532671859"},"payload":{"PayerPhoneNo":"18879470686","PayerAcctNbr":"6230910199159586441"}}'
            // var str = '{"payload":{"template":"9W20160922000010","ORGAN_CODE":"999000","APP_VERS":"6.0.6","deviceNO":"7c33671e6ed0ee793783a5cec3da935a","APP_DEVICE_TYPE":"Android"},"header":{"_t":1706764264945,"service":"commonService/getContractUrl"}}'


            // 固定密钥，无需修改
            var str2 = '0000000000000000'
            console.log("----------------------------------------------------")
            console.log(`text=${str}`);
            let result = instance["getEncryptString"](str, str2);
            var replaceStr = result.replace(/\x1D/g, "<GS>")
            console.log("----------------------------------------")
            console.log(`result=${replaceStr}`);
        },
        onComplete: function () {
        }

    })
}
function stackTraceHere(isLog) {
    var Exception = Java.use('java.lang.Exception');
    var Log = Java.use('android.util.Log');
    var stackinfo = Log.getStackTraceString(Exception.$new())
    if (isLog) {
        console.log(stackinfo)
    } else {
        return stackinfo
    }
}
function h5_ssl_unpin() {
    /*
支付宝小程序hook脚本 alipay v10.1.75
 */

    Java.perform(function () {
        // webview 证书绑定
        // const H5WebViewClient = Java.use('com.alipay.mobile.nebulacore.web.H5WebViewClient');
        // const SslErrorHandler = Java.use("android.webkit.SslErrorHandler");
        // H5WebViewClient.onReceivedSslError.implementation = function (webview, sslHandler, sslError) {
        //     console.log('H5WebViewClient onReceivedSslError called, proceed');
        //     var handler = Java.cast(sslHandler, SslErrorHandler);
        //     handler.proceed();
        // };
        // h5小程序 log
        const H5Log = Java.use("com.alipay.mobile.nebula.util.H5Log");
        H5Log.d.overload("java.lang.String", "java.lang.String").implementation = function (tag, msg) {
            if (msg.toString().indexOf("SSL") >= 0 || tag.toString().indexOf("SSL") >= 0) {
                console.log("debug: [", tag, "] - ", msg);
                console.log(stackTraceHere(false))
            }

        };

        // disable ssl hostname check
        const AbstractVerifier = Java.use("org.apache.http.conn.ssl.AbstractVerifier");
        AbstractVerifier.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;', 'boolean').implementation = function (a, b, c, d) {
            console.log('HostnameVerifier wants to verify ', a, ' disabled');
            return;
        };

        console.log('injected');
    });
}

hardenTest();
// getFirstActivity();
// hook_activity();
// getAllActivity();
var myhook = false;
if (myhook) {
    hook_dlopen();
    // hook_replace_str();
    // hook_pthread_create();
    // hook_open();
}
var allhook = true;
if (allhook) {
    // BypassALL();
    // setTimeout(SSLUnpinning, 5000)
    // SSLUnpinning();
    // decryption();
    // just_trust_me();
}
// hook_click();
// hook_trustfactory();
// hook_keystore();
// hook_trustManagerImpl_check();
// hook_certificateFactory(true);
// hook_getUserInfo(); 
// hook_trustManagerImpl();
// h5_ssl_unpin();