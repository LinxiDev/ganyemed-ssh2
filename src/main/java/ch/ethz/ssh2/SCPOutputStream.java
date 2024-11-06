package ch.ethz.ssh2;

import ch.ethz.ssh2.util.StringEncoder;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class SCPOutputStream extends BufferedOutputStream {
   private Session session;
   private SCPClient scp;

   public SCPOutputStream(SCPClient client, Session session, String remoteFile, long length, String mode) throws IOException {
      super(session.getStdin(), 40000);
      this.session = session;
      this.scp = client;
      InputStream is = new BufferedInputStream(session.getStdout(), 512);
      this.scp.readResponse(is);
      String cline = "C" + mode + " " + length + " " + remoteFile + "\n";
      super.write(StringEncoder.GetBytes(cline));
      this.flush();
      this.scp.readResponse(is);
   }

   public void close() throws IOException {
      try {
         this.write(0);
         this.flush();
         this.scp.readResponse(this.session.getStdout());
         this.write(StringEncoder.GetBytes("E\n"));
         this.flush();
      } finally {
         if (this.session != null) {
            this.session.close();
         }

      }

   }
}
