package ch.ethz.ssh2;

import java.io.IOException;

public interface ServerSessionCallback {
   Runnable requestPtyReq(ServerSession var1, PtySettings var2) throws IOException;

   Runnable requestEnv(ServerSession var1, String var2, String var3) throws IOException;

   Runnable requestShell(ServerSession var1) throws IOException;

   Runnable requestExec(ServerSession var1, String var2) throws IOException;

   Runnable requestSubsystem(ServerSession var1, String var2) throws IOException;

   void requestWindowChange(ServerSession var1, int var2, int var3, int var4, int var5) throws IOException;
}
