package me.liuyun.nossl

import android.content.Context
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XC_MethodReplacement
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers.findAndHookMethod
import de.robv.android.xposed.callbacks.XC_LoadPackage
import javax.net.ssl.HostnameVerifier


class MainHook : IXposedHookLoadPackage {
    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam?) {
        if (lpparam == null || lpparam.packageName != "com.able.wisdomtree") return
        try {
            findAndHookMethod("com.stub.StubApp", lpparam.classLoader, "ᵢˋ", Context::class.java, object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam?) {
                    super.afterHookedMethod(param)
                    if (param == null) return
                    val context = param.args[0] as Context

                    findAndHookMethod("com.able.wisdomtree.base.AbleApplication", context.classLoader, "getSSLContextInstance", sslHook)
                    findAndHookMethod("com.zhs.net.netr.interceptor.InterceptorUtil", context.classLoader, "getAppSslContext", sslHook)
                    findAndHookMethod("okhttp3.OkHttpClient.Builder", context.classLoader, "build", okHttpHook)
                    findAndHookMethod("com.able.wisdomtree.rsa.Base64Utils", context.classLoader, "decode", String::class.java, base64Hook)
                }
            })

        } catch (t: Throwable) {
            XposedBridge.log(t)
        }

    }

    val sslHook = object : XC_MethodReplacement() {
        @Throws(Throwable::class)
        override fun replaceHookedMethod(methodHookParam: MethodHookParam): Any? {
            XposedBridge.log("SSL hook success.")
            return null
        }
    }

    val okHttpHook = object : XC_MethodHook() {
        @Throws(Throwable::class)
        override fun beforeHookedMethod(param: MethodHookParam?) {
            super.beforeHookedMethod(param)
            try {
                val builder = param?.thisObject ?: return
                val h = builder.javaClass.getDeclaredField("hostnameVerifier")
                h.isAccessible = true
                h.set(builder, HostnameVerifier { _, _ -> true })
                h.isAccessible = false
                XposedBridge.log("OkHttp hook success.")
            } catch (t: Throwable) {
                XposedBridge.log(t)
            }
        }
    }

    val base64Hook = object : XC_MethodHook() {
        @Throws(Throwable::class)
        override fun beforeHookedMethod(param: MethodHookParam?) {
            super.beforeHookedMethod(param)
            try {
                param ?: return
                XposedBridge.log("Decode: " + param.args[0])
                // throw Exception()
            } catch (t: Throwable) {
                XposedBridge.log(t)
            }
        }
    }


}