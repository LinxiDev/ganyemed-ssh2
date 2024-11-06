package ch.ethz.ssh2;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class SCPInputStream extends BufferedInputStream {
   private Session session;
   private long remaining;

   public SCPInputStream(SCPClient client, Session session) throws IOException {
      super(session.getStdout());
      this.session = session;
      OutputStream os = new BufferedOutputStream(session.getStdin(), 512);
      os.write(0);
      os.flush();

      int c;
      String line;
      do {
         c = session.getStdout().read();
         if (c < 0) {
            throw new IOException("Remote scp terminated unexpectedly.");
         }

         line = client.receiveLine(session.getStdout());
      } while(c == 84);

      if (c != 1 && c != 2) {
         if (c == 67) {
            SCPClient.LenNamePair lnp = client.parseCLine(line);
            os.write(0);
            os.flush();
            this.remaining = lnp.length;
         } else {
            throw new IOException("Remote SCP error: " + (char)c + line);
         }
      } else {
         throw new IOException("Remote SCP error: " + line);
      }
   }

   public int read() throws IOException {
      if (this.remaining <= 0L) {
         return -1;
      } else {
         int b = super.read();
         if (b < 0) {
            throw new IOException("Remote scp terminated connection unexpectedly");
         } else {
            --this.remaining;
            return b;
         }
      }
   }

   public int read(byte[] b, int off, int len) throws IOException {
      if (this.remaining <= 0L) {
         return -1;
      } else {
         int trans = (int)this.remaining;
         if (this.remaining > (long)len) {
            trans = len;
         }

         int read = super.read(b, off, trans);
         if (read < 0) {
            throw new IOException("Remote scp terminated connection unexpectedly");
         } else {
            this.remaining -= (long)read;
            return read;
         }
      }
   }

   public void close() throws IOException {
      try {
         this.session.getStdin().write(0);
         this.session.getStdin().flush();
      } finally {
         if (this.session != null) {
            this.session.close();
         }

      }

   }
}
