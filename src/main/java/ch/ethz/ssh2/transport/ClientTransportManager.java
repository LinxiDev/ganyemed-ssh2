package ch.ethz.ssh2.transport;

import ch.ethz.ssh2.DHGexParameters;
import ch.ethz.ssh2.ServerHostKeyVerifier;
import ch.ethz.ssh2.crypto.CryptoWishList;
import ch.ethz.ssh2.signature.DSAPrivateKey;
import ch.ethz.ssh2.signature.RSAPrivateKey;
import ch.ethz.ssh2.util.Tokenizer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.SecureRandom;

public class ClientTransportManager extends TransportManager {
   protected final Socket sock = new Socket();

   public void setTcpNoDelay(boolean state) throws IOException {
      this.sock.setTcpNoDelay(state);
   }

   public void setSoTimeout(int timeout) throws IOException {
      this.sock.setSoTimeout(timeout);
   }

   public void connect(String hostname, int port, String softwareversion, CryptoWishList cwl, ServerHostKeyVerifier verifier, DHGexParameters dhgex, int connectTimeout, SecureRandom rnd) throws IOException {
      this.connect(hostname, port, connectTimeout);
      ClientServerHello csh = ClientServerHello.clientHello(softwareversion, this.sock.getInputStream(), this.sock.getOutputStream());
      TransportConnection tc = new TransportConnection(this.sock.getInputStream(), this.sock.getOutputStream(), rnd);
      KexManager km = new ClientKexManager(this, csh, cwl, hostname, port, verifier, rnd);
      super.init(tc, km);
      km.initiateKEX(cwl, dhgex, (DSAPrivateKey)null, (RSAPrivateKey)null);
      this.startReceiver();
   }

   public void close(Throwable cause, boolean useDisconnectPacket) {
      this.close(this.sock, cause, useDisconnectPacket);
   }

   protected void connect(String hostname, int port, int connectTimeout) throws IOException {
      InetAddress addr = createInetAddress(hostname);
      this.sock.connect(new InetSocketAddress(addr, port), connectTimeout);
   }

   protected static InetAddress createInetAddress(String host) throws UnknownHostException {
      InetAddress addr = parseIPv4Address(host);
      return addr != null ? addr : InetAddress.getByName(host);
   }

   private static InetAddress parseIPv4Address(String host) throws UnknownHostException {
      if (host == null) {
         return null;
      } else {
         String[] quad = Tokenizer.parseTokens(host, '.');
         if (quad != null && quad.length == 4) {
            byte[] addr = new byte[4];

            for(int i = 0; i < 4; ++i) {
               int part = 0;
               if (quad[i].length() == 0 || quad[i].length() > 3) {
                  return null;
               }

               for(int k = 0; k < quad[i].length(); ++k) {
                  char c = quad[i].charAt(k);
                  if (c < '0' || c > '9') {
                     return null;
                  }

                  part = part * 10 + (c - 48);
               }

               if (part > 255) {
                  return null;
               }

               addr[i] = (byte)part;
            }

            return InetAddress.getByAddress(host, addr);
         } else {
            return null;
         }
      }
   }
}
