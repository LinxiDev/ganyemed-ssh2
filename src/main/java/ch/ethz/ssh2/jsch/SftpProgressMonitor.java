package ch.ethz.ssh2.jsch;

public interface SftpProgressMonitor {
   int PUT = 0;
   int GET = 1;
   long UNKNOWN_SIZE = -1L;

   void init(int var1, String var2, String var3, long var4);

   boolean count(long var1);

   void end();
}
