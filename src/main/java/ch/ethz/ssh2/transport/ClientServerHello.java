package ch.ethz.ssh2.transport;

import ch.ethz.ssh2.util.StringEncoder;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class ClientServerHello {
   String client_line;
   String server_line;

   private ClientServerHello(String client_line, String server_line) {
      this.client_line = client_line;
      this.server_line = server_line;
   }

   public static final int readLineRN(InputStream is, byte[] buffer) throws IOException {
      int pos = 0;
      boolean need10 = false;
      int len = 0;

      while(true) {
         int c = is.read();
         if (c == -1) {
            throw new IOException("Premature connection close");
         }

         buffer[pos++] = (byte)c;
         if (c == 13) {
            need10 = true;
         } else {
            if (c == 10) {
               return len;
            }

            if (need10) {
               throw new IOException("Malformed line received, the line does not end correctly.");
            }

            ++len;
            if (pos >= buffer.length) {
               throw new IOException("The server sent a too long line: " + StringEncoder.GetString(buffer));
            }
         }
      }
   }

   public static ClientServerHello clientHello(String softwareversion, InputStream bi, OutputStream bo) throws IOException {
      return exchange(softwareversion, bi, bo, true);
   }

   public static ClientServerHello serverHello(String softwareversion, InputStream bi, OutputStream bo) throws IOException {
      return exchange(softwareversion, bi, bo, false);
   }

   private static ClientServerHello exchange(String softwareversion, InputStream bi, OutputStream bo, boolean clientMode) throws IOException {
      String localIdentifier = "SSH-2.0-" + softwareversion;
      String remoteIdentifier = null;
      bo.write(StringEncoder.GetBytes(localIdentifier + "\r\n"));
      bo.flush();
      byte[] remoteData = new byte[1024];

      for(int i = 0; i < 50; ++i) {
         int len = readLineRN(bi, remoteData);
         remoteIdentifier = StringEncoder.GetString(remoteData, 0, len);
         if (remoteIdentifier.startsWith("SSH-")) {
            break;
         }
      }

      if (!remoteIdentifier.startsWith("SSH-")) {
         throw new IOException("Malformed SSH identification string. There was no line starting with 'SSH-' amongst the first 50 lines.");
      } else if (!remoteIdentifier.startsWith("SSH-1.99-") && !remoteIdentifier.startsWith("SSH-2.0-")) {
         throw new IOException("Remote party uses incompatible protocol, it is not SSH-2 compatible.");
      } else {
         return clientMode ? new ClientServerHello(localIdentifier, remoteIdentifier) : new ClientServerHello(remoteIdentifier, localIdentifier);
      }
   }

   public byte[] getClientString() {
      return StringEncoder.GetBytes(this.client_line);
   }

   public byte[] getServerString() {
      return StringEncoder.GetBytes(this.server_line);
   }
}
