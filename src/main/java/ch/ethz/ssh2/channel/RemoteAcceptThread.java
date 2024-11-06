package ch.ethz.ssh2.channel;

import ch.ethz.ssh2.log.Logger;
import java.io.IOException;
import java.net.Socket;

public class RemoteAcceptThread extends Thread {
   private static final Logger log = Logger.getLogger(RemoteAcceptThread.class);
   Channel c;
   String remoteConnectedAddress;
   int remoteConnectedPort;
   String remoteOriginatorAddress;
   int remoteOriginatorPort;
   String targetAddress;
   int targetPort;
   Socket s;

   public RemoteAcceptThread(Channel c, String remoteConnectedAddress, int remoteConnectedPort, String remoteOriginatorAddress, int remoteOriginatorPort, String targetAddress, int targetPort) {
      this.c = c;
      this.remoteConnectedAddress = remoteConnectedAddress;
      this.remoteConnectedPort = remoteConnectedPort;
      this.remoteOriginatorAddress = remoteOriginatorAddress;
      this.remoteOriginatorPort = remoteOriginatorPort;
      this.targetAddress = targetAddress;
      this.targetPort = targetPort;
      log.debug("RemoteAcceptThread: " + remoteConnectedAddress + "/" + remoteConnectedPort + ", R: " + remoteOriginatorAddress + "/" + remoteOriginatorPort);
   }

   public void run() {
      try {
         this.c.cm.sendOpenConfirmation(this.c);
         this.s = new Socket(this.targetAddress, this.targetPort);
         StreamForwarder r2l = new StreamForwarder(this.c, (StreamForwarder)null, (Socket)null, this.c.getStdoutStream(), this.s.getOutputStream(), "RemoteToLocal");
         StreamForwarder l2r = new StreamForwarder(this.c, (StreamForwarder)null, (Socket)null, this.s.getInputStream(), this.c.getStdinStream(), "LocalToRemote");
         r2l.setDaemon(true);
         r2l.start();
         l2r.run();

         while(r2l.isAlive()) {
            try {
               r2l.join();
            } catch (InterruptedException var6) {
            }
         }

         this.c.cm.closeChannel(this.c, "EOF on both streams reached.", true);
         this.s.close();
      } catch (IOException var7) {
         IOException e = var7;
         log.warning("IOException in proxy code: " + var7.getMessage());

         try {
            this.c.cm.closeChannel(this.c, "IOException in proxy code (" + e.getMessage() + ")", true);
         } catch (IOException var5) {
         }

         try {
            if (this.s != null) {
               this.s.close();
            }
         } catch (IOException var4) {
         }
      }

   }
}
