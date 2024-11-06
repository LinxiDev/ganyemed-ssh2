package ch.ethz.ssh2.jsch;

public interface Argon2 extends KDF {
   int ARGON2D = 0;
   int ARGON2I = 1;
   int ARGON2ID = 2;
   int V10 = 16;
   int V13 = 19;

   void init(byte[] var1, int var2, int var3, byte[] var4, byte[] var5, int var6, int var7, int var8) throws Exception;
}
