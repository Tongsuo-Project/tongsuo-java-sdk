package net.tongsuo.crypto;

import java.security.AccessController;
import java.security.PrivilegedAction;

public final class CryptoUtils {

    public static String privilegedGetProperty(String key, String def) {
        return AccessController.doPrivileged(
                (PrivilegedAction<String>) () -> System.getProperty(key, def));
    }

    public static String privilegedGetProperty(String key) {
        return privilegedGetProperty(key, null);
    }

    public static Boolean privilegedGetBoolProperty(String key, String def) {
        return AccessController.doPrivileged(
                (PrivilegedAction<Boolean>) () -> Boolean.parseBoolean(
                        System.getProperty(key, def)));
    }

    public static Boolean privilegedGetBoolProperty(String key) {
        return privilegedGetBoolProperty(key, "false");
    }

    public static boolean isJdk8() {
        return privilegedGetProperty("java.specification.version").equals("1.8");
    }

    public static boolean isJdk11() {
        return privilegedGetProperty("java.specification.version").equals("11");
    }

    public static boolean isJdk17() {
        return privilegedGetProperty("java.specification.version").equals("17");
    }

    public static boolean isAndroid() {
        return privilegedGetProperty("java.specification.vendor").equals("Android");
    }
}
