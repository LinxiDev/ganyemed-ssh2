package ch.ethz.ssh2.auth;

import ch.ethz.ssh2.AuthenticationResult;
import ch.ethz.ssh2.ServerAuthenticationCallback;
import ch.ethz.ssh2.channel.ChannelManager;
import ch.ethz.ssh2.packets.PacketServiceAccept;
import ch.ethz.ssh2.packets.PacketServiceRequest;
import ch.ethz.ssh2.packets.PacketUserauthBanner;
import ch.ethz.ssh2.packets.PacketUserauthFailure;
import ch.ethz.ssh2.packets.PacketUserauthSuccess;
import ch.ethz.ssh2.packets.TypesReader;
import ch.ethz.ssh2.server.ServerConnectionState;
import ch.ethz.ssh2.transport.MessageHandler;
import java.io.IOException;

public class ServerAuthenticationManager implements MessageHandler {
   private final ServerConnectionState state;

   public ServerAuthenticationManager(ServerConnectionState state) {
      this.state = state;
      state.tm.registerMessageHandler(this, 0, 255);
   }

   private void sendresult(AuthenticationResult result) throws IOException {
      if (AuthenticationResult.SUCCESS == result) {
         PacketUserauthSuccess pus = new PacketUserauthSuccess();
         this.state.tm.sendAsynchronousMessage(pus.getPayload());
         this.state.tm.removeMessageHandler(this, 0, 255);
         this.state.tm.registerMessageHandler(this, 50, 79);
         this.state.cm = new ChannelManager(this.state);
         this.state.flag_auth_completed = true;
      } else {
         String[] remaining_methods = null;
         if (this.state.cb_auth != null) {
            remaining_methods = this.state.cb_auth.getRemainingAuthMethods(this.state.conn);
         }

         if (remaining_methods == null) {
            remaining_methods = new String[0];
         }

         PacketUserauthFailure puf = new PacketUserauthFailure(remaining_methods, AuthenticationResult.PARTIAL_SUCCESS == result);
         this.state.tm.sendAsynchronousMessage(puf.getPayload());
      }

   }

   public void handleMessage(byte[] msg, int msglen) throws IOException {
      ServerConnectionState var10000 = this.state;
      synchronized(var10000){}
      if (!this.state.flag_auth_completed) {
         if (!this.state.flag_auth_serviceRequested) {
            PacketServiceRequest psr = new PacketServiceRequest(msg, 0, msglen);
            if (!"ssh-userauth".equals(psr.getServiceName())) {
               throw new IOException("SSH protocol error, expected ssh-userauth service request");
            } else {
               PacketServiceAccept psa = new PacketServiceAccept("ssh-userauth");
               this.state.tm.sendAsynchronousMessage(psa.getPayload());
               String banner = this.state.cb_auth.initAuthentication(this.state.conn);
               if (banner != null) {
                  PacketUserauthBanner pub = new PacketUserauthBanner(banner, "en");
                  this.state.tm.sendAsynchronousMessage(pub.getPayload());
               }

               this.state.flag_auth_serviceRequested = true;
            }
         } else {
            ServerAuthenticationCallback cb = this.state.cb_auth;
            TypesReader tr = new TypesReader(msg, 0, msglen);
            int packet_type = tr.readByte();
            if (packet_type == 50) {
               String username = tr.readString("UTF-8");
               String service = tr.readString();
               String method = tr.readString();
               if (!"ssh-connection".equals(service)) {
                  this.sendresult(AuthenticationResult.FAILURE);
               } else if ("none".equals(method) && cb != null) {
                  this.sendresult(cb.authenticateWithNone(this.state.conn, username));
               } else {
                  if ("password".equals(method)) {
                     boolean flag_change_pass = tr.readBoolean();
                     if (flag_change_pass) {
                        this.sendresult(AuthenticationResult.FAILURE);
                        return;
                     }

                     String password = tr.readString("UTF-8");
                     if (cb != null) {
                        this.sendresult(cb.authenticateWithPassword(this.state.conn, username, password));
                        return;
                     }
                  }

                  this.sendresult(AuthenticationResult.FAILURE);
               }
            } else {
               throw new IOException("Unexpected authentication packet " + packet_type);
            }
         }
      }
   }
}
