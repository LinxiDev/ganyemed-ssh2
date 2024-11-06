package ch.ethz.ssh2.server;

import ch.ethz.ssh2.ServerAuthenticationCallback;
import ch.ethz.ssh2.ServerConnection;
import ch.ethz.ssh2.ServerConnectionCallback;
import ch.ethz.ssh2.auth.ServerAuthenticationManager;
import ch.ethz.ssh2.channel.ChannelManager;
import ch.ethz.ssh2.crypto.CryptoWishList;
import ch.ethz.ssh2.signature.DSAPrivateKey;
import ch.ethz.ssh2.signature.RSAPrivateKey;
import ch.ethz.ssh2.transport.ClientServerHello;
import ch.ethz.ssh2.transport.ServerTransportManager;
import java.net.Socket;
import java.security.SecureRandom;

public class ServerConnectionState {
   public ServerConnection conn;
   public SecureRandom generator = new SecureRandom();
   public String softwareversion;
   public ServerConnectionCallback cb_conn;
   public ServerAuthenticationCallback cb_auth;
   public CryptoWishList next_cryptoWishList = CryptoWishList.forServer();
   public DSAPrivateKey next_dsa_key;
   public RSAPrivateKey next_rsa_key;
   public Socket s;
   public ClientServerHello csh;
   public ServerTransportManager tm;
   public ServerAuthenticationManager am;
   public ChannelManager cm;
   public boolean flag_auth_serviceRequested = false;
   public boolean flag_auth_completed = false;

   public ServerConnectionState(ServerConnection conn) {
      this.conn = conn;
   }
}
