package ch.ethz.ssh2.channel;

import ch.ethz.ssh2.ServerSession;
import ch.ethz.ssh2.ServerSessionCallback;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class ServerSessionImpl implements ServerSession {
   Channel c;
   public ServerSessionCallback sscb;

   public ServerSessionImpl(Channel c) {
      this.c = c;
   }

   public int getState() {
      return this.c.getState();
   }

   public InputStream getStdout() {
      return this.c.getStdoutStream();
   }

   public InputStream getStderr() {
      return this.c.getStderrStream();
   }

   public OutputStream getStdin() {
      return this.c.getStdinStream();
   }

   public void close() {
      try {
         this.c.cm.closeChannel(this.c, "Closed due to server request", true);
      } catch (IOException var2) {
      }

   }

   public synchronized ServerSessionCallback getServerSessionCallback() {
      return this.sscb;
   }

   public synchronized void setServerSessionCallback(ServerSessionCallback sscb) {
      this.sscb = sscb;
   }
}
