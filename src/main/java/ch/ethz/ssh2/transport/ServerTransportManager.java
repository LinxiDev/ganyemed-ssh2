package ch.ethz.ssh2.transport;

import ch.ethz.ssh2.DHGexParameters;
import ch.ethz.ssh2.server.ServerConnectionState;
import java.io.IOException;
import java.net.Socket;

public class ServerTransportManager extends TransportManager {
   private final Socket sock;

   public ServerTransportManager(Socket socket) {
      this.sock = socket;
   }

   public void connect(ServerConnectionState state) throws IOException {
      state.csh = ClientServerHello.serverHello(state.softwareversion, this.sock.getInputStream(), this.sock.getOutputStream());
      TransportConnection tc = new TransportConnection(this.sock.getInputStream(), this.sock.getOutputStream(), state.generator);
      KexManager km = new ServerKexManager(state);
      super.init(tc, km);
      km.initiateKEX(state.next_cryptoWishList, (DHGexParameters)null, state.next_dsa_key, state.next_rsa_key);
      this.startReceiver();
   }

   public void close(Throwable cause, boolean useDisconnectPacket) {
      this.close(this.sock, cause, useDisconnectPacket);
   }
}
