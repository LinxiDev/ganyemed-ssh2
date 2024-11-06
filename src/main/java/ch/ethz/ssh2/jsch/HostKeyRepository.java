package ch.ethz.ssh2.jsch;

public interface HostKeyRepository {
   int OK = 0;
   int NOT_INCLUDED = 1;
   int CHANGED = 2;

   int check(String var1, byte[] var2);

   void remove(String var1, String var2);

   void remove(String var1, String var2, byte[] var3);

   String getKnownHostsRepositoryID();

   HostKey[] getHostKey();

   HostKey[] getHostKey(String var1, String var2);
}
