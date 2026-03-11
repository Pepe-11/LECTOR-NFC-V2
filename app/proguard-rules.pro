# Mantener todas las clases del SDK TapLinx de NXP
-keep class com.nxp.nfclib.** { *; }
-dontwarn com.nxp.nfclib.**

# Mantener clases de la app
-keep class com.example.desfiresdm.** { *; }

# BouncyCastle
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# Firebase
-keep class com.google.firebase.** { *; }
