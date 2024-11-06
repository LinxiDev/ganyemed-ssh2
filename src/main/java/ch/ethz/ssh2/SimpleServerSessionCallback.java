package ch.ethz.ssh2;

import java.io.IOException;

public class SimpleServerSessionCallback implements ServerSessionCallback {
   public Runnable requestShell(ServerSession ss) throws IOException {
      return null;
   }

   public Runnable requestExec(ServerSession ss, String command) throws IOException {
      return null;
   }

   public Runnable requestSubsystem(ServerSession ss, String subsystem) throws IOException {
      return null;
   }

   public Runnable requestPtyReq(ServerSession ss, PtySettings pty) throws IOException {
      return null;
   }

   public Runnable requestEnv(ServerSession ss, String name, String value) throws IOException {
      return new Runnable() {
         public void run() {
         }
      };
   }

   public void requestWindowChange(ServerSession ss, int term_width_columns, int term_height_rows, int term_width_pixels, int term_height_pixels) throws IOException {
   }
}
