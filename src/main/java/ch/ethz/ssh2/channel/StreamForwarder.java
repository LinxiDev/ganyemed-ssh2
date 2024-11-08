package ch.ethz.ssh2.channel;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class StreamForwarder extends Thread {
   OutputStream os;
   InputStream is;
   byte[] buffer = new byte[196608];
   Channel c;
   StreamForwarder sibling;
   Socket s;
   String mode;

   StreamForwarder(Channel c, StreamForwarder sibling, Socket s, InputStream is, OutputStream os, String mode) throws IOException {
      this.is = is;
      this.os = os;
      this.mode = mode;
      this.c = c;
      this.sibling = sibling;
      this.s = s;
   }

   public void run() {
      while(true) {
         try {
            int len = this.is.read(this.buffer);
            if (len > 0) {
               this.os.write(this.buffer, 0, len);
               this.os.flush();
               continue;
            }
         } catch (IOException var29) {
            IOException ignore = var29;

            try {
               this.c.cm.closeChannel(this.c, "Closed due to exception in StreamForwarder (" + this.mode + "): " + ignore.getMessage(), true);
            } catch (IOException var28) {
            }
         } finally {
            try {
               this.os.close();
            } catch (IOException var27) {
            }

            try {
               this.is.close();
            } catch (IOException var26) {
            }

            if (this.sibling != null) {
               while(this.sibling.isAlive()) {
                  try {
                     this.sibling.join();
                  } catch (InterruptedException var25) {
                  }
               }

               try {
                  this.c.cm.closeChannel(this.c, "StreamForwarder (" + this.mode + ") is cleaning up the connection", true);
               } catch (IOException var24) {
               }

               try {
                  if (this.s != null) {
                     this.s.close();
                  }
               } catch (IOException var23) {
               }
            }

         }

         return;
      }
   }
}
