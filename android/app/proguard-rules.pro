# R8 does not know that the Rust side reaches these by name.

# The JNI symbols are Java_dev_luksandroid_LuksNative_*. Renaming the class or
# its native methods breaks the link at load time, not at build time.
-keepclasseswithmembernames class dev.luksandroid.LuksNative {
    native <methods>;
}

# Rust constructs this by signature: LuksException(String, int).
-keep class dev.luksandroid.LuksException {
    <init>(java.lang.String, int);
}
