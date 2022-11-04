
setImmediate(function(){

    Java.perform(function(){

        //var Log = Java.use("android.util.Log");
        function alertSend(data) {

            console.log(data["ClassName"],data["FunctionName"],data["FunctionNote"],data["Params"])
            //Log.e("msecmsp",data["ClassName"],data["FunctionName"],data["FunctionNote"],data["Params"]);
            send(data);
        }


        function sslpining(){
            
            
            // Log.e("frida-gadget-sslpining", "OHHHHHHHHHHHHHHHHHHHHHHH");
        
        
            /*
            hook list:
            1.SSLcontext
            2.okhttpcom.android.okhttp.internal.tls.OkHostnameVerifier
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
            var quiet_output = true;
    
            // Helper method to honor the quiet flag.
    
            function quiet_send(data) {
    
                if (quiet_output) {
    
                    return;
                }
    
                send(data)
                Log.e("FRIDA_GADGET", "sslpining - " + data);
            }
    
    
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
                        checkClientTrusted: function(chain, authType) {},
                        checkServerTrusted: function(chain, authType) {},
                        getAcceptedIssuers: function() {
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
    
            //send('Custom, Empty TrustManager ready');
    
            // Get a handle on the init() on the SSLContext class
            var SSLContext_init = SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
    
            // Override the init method, specifying our new TrustManager
            SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
    
                quiet_send('Overriding SSLContext.init() with the custom TrustManager');
    
                SSLContext_init.call(this, null, TrustManagers, null);
            };
    
            /*** okhttp3.x unpinning ***/
    
    
            // Wrap the logic in a try/catch as not all applications will have
            // okhttp as part of the app.
            try {
    
                var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    
                quiet_send('OkHTTP 3.x Found');
    
                CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
    
                    quiet_send('OkHTTP 3.x check() called. Not throwing an exception.');
                }
    
            } catch (err) {
    
                // If we dont have a ClassNotFoundException exception, raise the
                // problem encountered.
                if (err.message.indexOf('ClassNotFoundException') === 0) {
    
                    throw new Error(err);
                }
            }
    
    
            try {
    
                var OkHttpClient$Builder = Java.use('okhttp3.OkHttpClient$Builder');
    
                quiet_send('OkHttpClient$Builder  Found');
    
                OkHttpClient$Builder.sslSocketFactory.overload('javax.net.ssl.SSLSocketFactory', 'javax.net.ssl.X509TrustManager').implementation = function(p1,p2) {
                    return this.sslSocketFactory(p1);
                    quiet_send('OkHttpClient$Builder.sslSocketFactory(SSLSocketFactory, X509TrustManager) called. Not throwing an exception.');
                }
    
            } catch (err) {
    
                // If we dont have a ClassNotFoundException exception, raise the
                // problem encountered.
                if (err.message.indexOf('ClassNotFoundException') === 0) {
    
                    throw new Error(err);
                }
            }
    
            // Appcelerator Titanium PinningTrustManager
    
            // Wrap the logic in a try/catch as not all applications will have
            // appcelerator as part of the app.
            try {
    
                var PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');
    
                send('Appcelerator Titanium Found');
    
                PinningTrustManager.checkServerTrusted.implementation = function() {
    
                    quiet_send('Appcelerator checkServerTrusted() called. Not throwing an exception.');
                }
    
            } catch (err) {
    
                // If we dont have a ClassNotFoundException exception, raise the
                // problem encountered.
                if (err.message.indexOf('ClassNotFoundException') === 0) {
    
                    throw new Error(err);
                }
            }
    
            /*** okhttp unpinning ***/
    
    
            try {
                var OkHttpClient = Java.use("com.squareup.okhttp.OkHttpClient");
                OkHttpClient.setCertificatePinner.implementation = function(certificatePinner) {
                    // do nothing
                    quiet_send("OkHttpClient.setCertificatePinner Called!");
                    return this;
                };
    
                // Invalidate the certificate pinnet checks (if "setCertificatePinner" was called before the previous invalidation)
                var CertificatePinner = Java.use("com.squareup.okhttp.CertificatePinner");
                CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(p0, p1) {
                    // do nothing
                    quiet_send("okhttp Called! [Certificate]");
                    return;
                };
                CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(p0, p1) {
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
            var WebViewClient = Java.use("android.webkit.WebViewClient");
    
            WebViewClient.onReceivedSslError.implementation = function(webView, sslErrorHandler, sslError) {
                quiet_send("WebViewClient onReceivedSslError invoke");
                //执行proceed方法
                sslErrorHandler.proceed();
                return;
            };
    
            WebViewClient.onReceivedError.overload('android.webkit.WebView', 'int', 'java.lang.String', 'java.lang.String').implementation = function(a, b, c, d) {
                quiet_send("WebViewClient onReceivedError invoked");
                return;
            };
    
            WebViewClient.onReceivedError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError').implementation = function() {
                quiet_send("WebViewClient onReceivedError invoked");
                return;
            };
    
            /*** JSSE Hooks ***/
    
            /* libcore/luni/src/main/java/javax/net/ssl/TrustManagerFactory.java */
            /* public final TrustManager[] getTrustManager() */
            /* TrustManagerFactory.getTrustManagers maybe cause X509TrustManagerExtensions error  */
            // var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
            // TrustManagerFactory.getTrustManagers.implementation = function(){
            //     quiet_send("TrustManagerFactory getTrustManagers invoked");
            //     return TrustManagers;
            // }
    
            var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            /* libcore/luni/src/main/java/javax/net/ssl/HttpsURLConnection.java */
            /* public void setDefaultHostnameVerifier(HostnameVerifier) */
            HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier) {
                quiet_send("HttpsURLConnection.setDefaultHostnameVerifier invoked");
                return null;
            };
            /* libcore/luni/src/main/java/javax/net/ssl/HttpsURLConnection.java */
            /* public void setSSLSocketFactory(SSLSocketFactory) */
            HttpsURLConnection.setSSLSocketFactory.implementation = function(SSLSocketFactory) {
                quiet_send("HttpsURLConnection.setSSLSocketFactory invoked");
                return null;
            };
            /* libcore/luni/src/main/java/javax/net/ssl/HttpsURLConnection.java */
            /* public void setHostnameVerifier(HostnameVerifier) */
            HttpsURLConnection.setHostnameVerifier.implementation = function(hostnameVerifier) {
                quiet_send("HttpsURLConnection.setHostnameVerifier invoked");
                return null;
            };
    
    
    
            /*** Xutils3.x hooks ***/
            //Implement a new HostnameVerifier
            var TrustHostnameVerifier;
            try {
    
                TrustHostnameVerifier = Java.registerClass({
                    name: 'org.wooyun.TrustHostnameVerifier',
                    implements: [HostnameVerifier],
                    methods: {
                        verify: function(hostname, session) {
                            return true;
                        },
                    }
                });
            } catch (e) {
                //java.lang.ClassNotFoundException: Didn't find class "org.wooyun.TrustHostnameVerifier"
                quiet_send("registerClass from hostnameVerifier >>>>>>>> " + e.message);
            }
    
    
    
            try {
                HttpsURLConnection.getDefaultHostnameVerifier.implementation = function() {
                    quiet_send("HttpsURLConnection.getDefaultHostnameVerifier invoked");
                    //var hostnameVerifier = this.getDefaultHostnameVerifier().getClass().getName();
                    //quiet_send("HttpsURLConnection.getDefaultHostnameVerifier = " + hostnameVerifier);
                    return TrustHostnameVerifier.$new();
                };
            } catch (e) {
                quiet_send("HttpsURLConnection.getDefaultHostnameVerifier >>>>>>>> " + e.message);
            }
    
            // 失败了
            try {
                var OkHostnameVerifierClassName = HttpsURLConnection.getDefaultHostnameVerifier().getClass().getName();
                // OkHostnameVerifierClassName = "com.android.okhttp.internal.tls.OkHostnameVerifier"
                var OkHostnameVerifier = Java.use(OkHostnameVerifierClassName);
                OkHostnameVerifier.verify.implementation = function(p1,p2) {
                    // do nothing
                    quiet_send("OkHostnameVerifier.verify Called!" + p1);
                    return true;
                };
    
            } catch (e) {
                quiet_send("com.android.okhttp.internal.tls.OkHostnameVerifier not found");
            }
    
            try {
                var RequestParams = Java.use('org.xutils.http.RequestParams');
                RequestParams.setSslSocketFactory.implementation = function(sslSocketFactory) {
                    sslSocketFactory = EmptySSLFactory;
                    return null;
                }
    
                RequestParams.setHostnameVerifier.implementation = function(hostnameVerifier) {
                    hostnameVerifier = TrustHostnameVerifier.$new();
                    return null;
                }
    
            } catch (e) {
                quiet_send("Xutils hooks not Found");
            }
    
            /*** httpclientandroidlib Hooks ***/
            try {
                var AbstractVerifier = Java.use("ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier");
                AbstractVerifier.verify.overload('java.lang.String', '[Ljava.lang.String', '[Ljava.lang.String', 'boolean').implementation = function() {
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
    
            try {
                // Android 7+ TrustManagerImpl
                TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                    quiet_send("TrustManagerImpl verifyChain called");
                    // Skip all the logic and just return the chain again :P
                    //https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2017/november/bypassing-androids-network-security-configuration/
                    // https://github.com/google/conscrypt/blob/c88f9f55a523f128f0e4dace76a34724bfa1e88c/platform/src/main/java/org/conscrypt/TrustManagerImpl.java#L650
                    return untrustedChain;
                }
            } catch (e) {
                quiet_send("TrustManagerImpl verifyChain nout found below 7.0");
            }
            // OpenSSLSocketImpl
            try {
                var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
                OpenSSLSocketImpl.verifyCertificateChain.implementation = function(certRefs, authMethod) {
                    quiet_send('OpenSSLSocketImpl.verifyCertificateChain');
                }
    
                quiet_send('OpenSSLSocketImpl pinning')
            } catch (err) {
                quiet_send('OpenSSLSocketImpl pinner not found');
            }
            // Trustkit
            try {
                var Activity = Java.use("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier");
                Activity.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(str) {
                    quiet_send('Trustkit.verify1: ' + str);
                    return true;
                };
                Activity.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(str) {
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
                netBuilder.enablePublicKeyPinningBypassForLocalTrustAnchors.implementation = function(arg) {
    
                    //weibo not invoke
                    console.log("Enables or disables public key pinning bypass for local trust anchors = " + arg);
    
                    //true to enable the bypass, false to disable.
                    var ret = netBuilder.enablePublicKeyPinningBypassForLocalTrustAnchors.call(this, true);
                    return ret;
                };
    
                netBuilder.addPublicKeyPins.implementation = function(hostName, pinsSha256, includeSubdomains, expirationDate) {
                    console.log("cronet addPublicKeyPins hostName = " + hostName);
    
                    //var ret = netBuilder.addPublicKeyPins.call(this,hostName, pinsSha256,includeSubdomains, expirationDate);
                    //this 是调用 addPublicKeyPins 前的对象吗? Yes,CronetEngine.Builder
                    return this;
                };
    
            } catch (err) {
                console.log('[-] Cronet pinner not found')
            }
        ;
        }
        
       sslpining()



        //获取当前APP包名
        function getCurrentPackageName(){

            const ActivityThread = Java.use('android.app.ActivityThread');    
            var currentApplication = ActivityThread.currentApplication();
            var context = currentApplication.getApplicationContext();

            var packageName = context.getPackageName()

            var versionName = context.getPackageManager().getPackageInfo(packageName, 0).versionName;


            return packageName
        }

        function getCurrentVerion(){
            const ActivityThread = Java.use('android.app.ActivityThread');
            var currentApplication = ActivityThread.currentApplication();
            var context = currentApplication.getApplicationContext();
            var packageName = context.getPackageName();
            var packageInfo = context.getPackageManager().getPackageInfo(packageName, 0);


            if(packageInfo){
                const versionNameField = packageInfo.getClass().getDeclaredField("versionName");
                versionNameField.setAccessible(true);
                var versionName = versionNameField.get(packageInfo);
                return versionName
            }

            return ""

        }

        function getCurrentActivity(){
            const ActivityManager = Java.use('android.app.ActivityManager')
            const ActivityThread = Java.use('android.app.ActivityThread');
            var currentApplication = ActivityThread.currentApplication();
            var context = currentApplication.getApplicationContext();
            

        }

        function isEmptyStr(s) {
            if (s == undefined || s == null || s == '') {
                return true
            }
            return false
        }        

        function getStackTrace() {
            var Exception = Java.use("java.lang.Exception");
            var ins = Exception.$new("Exception");
            var straces = ins.getStackTrace();
            if (undefined == straces || null == straces) {
                return;
            }
            var result = "";
            for (var i = 0; i < straces.length; i++) {
                var str = "   " + straces[i].toString();
                result += str + "\r\n";
            }
            Exception.$dispose();
            return result;
        }

        function hookClassAllMethods(){

            
            var ActivityThread = Java.use("android.app.ActivityThread");
            //获取类名
            let className = arguments[0];
            //获取函数名
            let functionName = arguments[1];              
            //获取类实例,需要异常处理，有可能类不存在

            var classInstance

            try {
                classInstance = Java.use(className)  
            } catch  (error) {
                if (error.toString().indexOf("java.lang.ClassNotFoundException") != -1){
                    console.log(className,"不存在")
                }else{
                    console.log(className,"未知错误,",error)
                }
                
                return
            }



            //let classInstance = Java.use(className)  
            let functionNote = arguments[2]
            var paramPos //第几个参数特殊判断，特殊处理  device_id 的情况
            var paramValue

            if (arguments.length == 5){
                
                paramPos = arguments[3]
                paramValue = arguments[4]
            }

            //有些函数，在低版本或者高版本不存在，加上防止报错
            if (classInstance[functionName] == undefined){ 
                return 
            }
        
            let functionOverloadsCount = classInstance[functionName].overloads.length; //获取重载函数个数

            //重载所有函数
            for (var index = 0; index < functionOverloadsCount; index++){
                classInstance[functionName].overloads[index].implementation = function (){
                    
                    

                    if ("getPackageInfo" == functionName && arguments[0] == getCurrentPackageName()){
                        return this[functionName].apply(this, arguments);
                    }


                    var  currentThreadID = Process.getCurrentThreadId()  //获取当前线程ID              
                    
                    var overloadsArgumentsCount = arguments.length

                    

                    var params = "(";

                    for (var idx_arg = 0; idx_arg < overloadsArgumentsCount; idx_arg++)
                    {
                        params += (arguments[idx_arg] + ", ");
                    }
                    if (params.length > 2){
                        params = params.substring(0, (params.length -2));
                    }

                    params = params + ")";

                    //特殊处理 类似device_id 需要判断第几个参数的情况
                    if (paramPos != undefined){ 
                        
                        if(overloadsArgumentsCount >= paramPos && arguments[paramPos-1] == paramValue){
                            //需要记录
                        }else{
                            //不需要记录
                            return this[functionName].apply(this, arguments);
                        }
                    }else{
                        //需要记录
                    }
                    




                    var data = {}
                    data["CurrentThreadID"] = currentThreadID
                    data["ClassName"] = className
                    data["FunctionName"] = functionName
                    data["StackTrace"] = getStackTrace()
                    data["Params"] = params
                    data["FunctionNote"] = functionNote
                    data["TimeStamp"] = Date.parse(new Date());
                    data["MessageType"] = "Action"

                    alertSend(data)

                    var res = this[functionName].apply(this, arguments);
                    //console.log(JSON.stringify(res),res)
                    return res
                    //return this[functionName].apply(this, arguments);
                }
            }

            //console.log(functionOverloadsCount)
        }

       

        hookClassAllMethods("android.location.LocationManager","requestLocationUpdates","请求对设备的位置信息进行定期更新");
        hookClassAllMethods("android.location.LocationManager","getLastKnownLocation","获取位置信息");
        hookClassAllMethods("android.location.LocationManager","requestSingleUpdate","获取一次定位结果");
        hookClassAllMethods("android.location.LocationManager","getCurrentLocation","获取地理位置信息");            
        //hookClassAllMethods("java.net.Inet4Address","getAddress","获取IP地址");
        hookClassAllMethods("java.net.InetAddress","getHostAddress","获取IP地址");
        hookClassAllMethods("java.net.InetAddress","getByName","域名解析");

        hookClassAllMethods("java.net.NetworkInterface","getHardwareAddress","获取硬件地址");
        hookClassAllMethods("java.net.NetworkInterface","getInetAddresses");
        hookClassAllMethods("java.net.NetworkInterface","getNetworkInterfaces","获取网络接口");

        hookClassAllMethods("android.net.wifi.WifiInfo","getApMldMacAddress");
        hookClassAllMethods("android.net.wifi.WifiInfo","getSSID","获取wifi SSID");
        hookClassAllMethods("android.net.wifi.WifiInfo","getBSSID","获取wifi BSSID");
        hookClassAllMethods("android.net.wifi.WifiInfo","getMacAddress","获取Mac地址");
        hookClassAllMethods("android.net.wifi.WifiInfo","toString","获取wifi信息");
        hookClassAllMethods("android.net.wifi.WifiInfo","getIpAddress","获取 wifi ip");
 
        
        hookClassAllMethods("android.net.LinkProperties","getInterfaceName");
        hookClassAllMethods("android.net.LinkProperties","getAllInterfaceNames");
        hookClassAllMethods("android.net.LinkProperties","getAddresses");
        hookClassAllMethods("android.net.LinkProperties","getAllAddresses");
        hookClassAllMethods("android.net.LinkProperties","getLinkAddresses");
        hookClassAllMethods("android.net.LinkProperties","getAllLinkAddresses");
        hookClassAllMethods("android.net.LinkProperties","getDnsServers","获取DNS服务器");
        hookClassAllMethods("android.net.LinkProperties","toString");
          
        
        hookClassAllMethods("android.hardware.SensorManager","getDynamicSensorList");
        hookClassAllMethods("android.hardware.SensorManager","getSensorList")
        hookClassAllMethods("android.hardware.SensorManager","registerListener")
       
        
        hookClassAllMethods("android.content.ClipboardManager","getText");
        hookClassAllMethods("android.content.ClipboardManager","getPrimaryClip","获取剪切板内容");
        hookClassAllMethods("android.content.ClipboardManager","addPrimaryClipChangedListener");
        hookClassAllMethods("android.content.ClipboardManager","clearPrimaryClip");
        hookClassAllMethods("android.content.ClipboardManager","hasPrimaryClip");
        hookClassAllMethods("android.content.ClipboardManager","hasText");
        hookClassAllMethods("android.content.ClipboardManager","setText");
        hookClassAllMethods("android.content.ClipboardManager","setPrimaryClip");
                
        hookClassAllMethods("android.app.ApplicationPackageManager","getInstalledApplications");
        hookClassAllMethods("android.app.ApplicationPackageManager","getInstalledPackages");
        hookClassAllMethods("android.app.ApplicationPackageManager","queryIntentActivities");
        hookClassAllMethods("android.app.ApplicationPackageManager","queryBroadcastReceivers");
        hookClassAllMethods("android.app.ApplicationPackageManager","queryIntentServices");
        hookClassAllMethods("android.app.ApplicationPackageManager","queryIntentContentProviders");
        hookClassAllMethods("android.app.ApplicationPackageManager","getPackagesHoldingPermissions");
        hookClassAllMethods("android.app.ApplicationPackageManager","getPackageInfo","获取非自身APP包信息");
              
               
        hookClassAllMethods("android.app.ActivityManager","getRunningAppProcesses");
        hookClassAllMethods("android.app.ActivityManager","getRunningServices");
        hookClassAllMethods("android.app.ActivityManager","getRecentTasks");
        hookClassAllMethods("android.app.ActivityManager","getRunningTasks");

        

        
        hookClassAllMethods("android.telephony.TelephonyManager","getCellLocation");
        hookClassAllMethods("android.telephony.TelephonyManager","getDeviceId");
        hookClassAllMethods("android.telephony.TelephonyManager","getImei");
        hookClassAllMethods("android.telephony.TelephonyManager","getSubscriberId");
        hookClassAllMethods("android.telephony.TelephonyManager","getLine1Number");
        hookClassAllMethods("android.telephony.TelephonyManager","getMeid");
        hookClassAllMethods("android.telephony.TelephonyManager","getSimSerialNumber");
        hookClassAllMethods("android.telephony.TelephonyManager","getAllCellInfo");
        hookClassAllMethods("android.telephony.TelephonyManager","getNetworkOperatorName");
        hookClassAllMethods("android.telephony.TelephonyManager","getDeviceSoftwareVersion");
        hookClassAllMethods("android.telephony.TelephonyManager","getNetworkCountryIso");
        hookClassAllMethods("android.telephony.TelephonyManager","getNetworkOperator");
        hookClassAllMethods("android.telephony.TelephonyManager","getNetworkType");
        hookClassAllMethods("android.telephony.TelephonyManager","getSimOperator","SIM卡提供商代码");
        hookClassAllMethods("android.telephony.TelephonyManager","getSimState","获取SIM卡状态");
        hookClassAllMethods("android.telephony.TelephonyManager","getPhoneType");
        hookClassAllMethods("android.telephony.TelephonyManager","getSimOperatorName");
        
               
        
        // // https://github.com/xxzzddxzd/appSyscallScan/blob/main/scripts/Android/Privacy/Privacy_location.js

        hookClassAllMethods("android.location.Location","getAccuracy");
        hookClassAllMethods("android.location.Location","getAltitude");
        hookClassAllMethods("android.location.Location","getBearing");
        hookClassAllMethods("android.location.Location","getBearingAccuracyDegrees");
        hookClassAllMethods("android.location.Location","getElapsedRealtimeNanos");
        hookClassAllMethods("android.location.Location","getElapsedRealtimeUncertaintyNanos");
        hookClassAllMethods("android.location.Location","getExtras");
        hookClassAllMethods("android.location.Location","getLatitude");
        hookClassAllMethods("android.location.Location","getLongitude");
        hookClassAllMethods("android.location.Location","getProvider");
        hookClassAllMethods("android.location.Location","getSpeed");
        hookClassAllMethods("android.location.Location","getSpeedAccuracyMetersPerSecond");
        hookClassAllMethods("android.location.Location","getTime");
        hookClassAllMethods("android.location.Location","getVerticalAccuracyMeters");

        hookClassAllMethods("android.telephony.gsm.GsmCellLocation","getCid");
        hookClassAllMethods("android.telephony.gsm.GsmCellLocation","getLac");
        hookClassAllMethods("android.telephony.gsm.GsmCellLocation","getPsc");



        hookClassAllMethods("android.telephony.CellIdentityGsm","getArfcn","获取绝对无线频道编号");
        hookClassAllMethods("android.telephony.CellIdentityGsm","getBsic","获取基站识别码");
        hookClassAllMethods("android.telephony.CellIdentityGsm","getCid","获取基站信息 cid");
        hookClassAllMethods("android.telephony.CellIdentityGsm","getLac","获取基站信息 lac");
        hookClassAllMethods("android.telephony.CellIdentityGsm","getMcc");
        hookClassAllMethods("android.telephony.CellIdentityGsm","getMccString");
        hookClassAllMethods("android.telephony.CellIdentityGsm","getMnc");
        hookClassAllMethods("android.telephony.CellIdentityGsm","getMncString");
        hookClassAllMethods("android.telephony.CellIdentityGsm","getMobileNetworkOperator");
        hookClassAllMethods("android.telephony.CellIdentityGsm","getPsc");



        hookClassAllMethods("android.provider.Settings$System","getString","获取android_id唯一标识",2,"android_id");
        hookClassAllMethods("android.provider.Settings$Secure","getString","获取android_id唯一标识",2,"android_id");




        //蓝牙相关
        hookClassAllMethods("android.bluetooth.BluetoothDevice","getName","获取到的蓝牙设备");
        //hookClassAllMethods("android.bluetooth.BluetoothDevice","getAddress","获取到的蓝牙设备mac");
        hookClassAllMethods("android.bluetooth.BluetoothAdapter","getName","获取到的蓝牙设备");



        //申请权限
        hookClassAllMethods("android.support.v4.app.ActivityCompat","requestPermissions","检查权限");

    })



        

})