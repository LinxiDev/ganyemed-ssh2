package ch.ethz.ssh2;

public interface ServerAuthenticationCallback {
   String METHOD_HOSTBASED = "hostbased";
   String METHOD_PUBLICKEY = "publickey";
   String METHOD_PASSWORD = "password";

   String initAuthentication(ServerConnection var1);

   String[] getRemainingAuthMethods(ServerConnection var1);

   AuthenticationResult authenticateWithNone(ServerConnection var1, String var2);

   AuthenticationResult authenticateWithPassword(ServerConnection var1, String var2, String var3);

   AuthenticationResult authenticateWithPublicKey(ServerConnection var1, String var2, String var3, byte[] var4, byte[] var5);
}
