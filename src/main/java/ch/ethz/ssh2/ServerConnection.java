package ch.ethz.ssh2;

import ch.ethz.ssh2.crypto.CryptoWishList;
import ch.ethz.ssh2.crypto.PEMDecoder;
import ch.ethz.ssh2.server.ServerConnectionState;
import ch.ethz.ssh2.signature.DSAPrivateKey;
import ch.ethz.ssh2.signature.RSAPrivateKey;
import ch.ethz.ssh2.transport.ServerTransportManager;
import java.io.CharArrayWriter;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.Socket;

public class ServerConnection {
   private String softwareversion;
   private final ServerConnectionState state;

   public ServerConnection(Socket s) {
      this(s, (DSAPrivateKey)null, (RSAPrivateKey)null);
   }

   public ServerConnection(Socket s, String softwareversion) {
      this(s, (DSAPrivateKey)null, (RSAPrivateKey)null);
      this.softwareversion = softwareversion;
   }

   public ServerConnection(Socket s, DSAPrivateKey dsa_key, RSAPrivateKey rsa_key) {
      this.softwareversion = String.format("Ganymed_SSHD_%s", Version.getSpecification());
      this.state = new ServerConnectionState(this);
      this.state.s = s;
      this.state.softwareversion = this.softwareversion;
      this.state.next_dsa_key = dsa_key;
      this.state.next_rsa_key = rsa_key;
      this.fixCryptoWishList(this.state.next_cryptoWishList, this.state.next_dsa_key, this.state.next_rsa_key);
   }

   public synchronized void connect() throws IOException {
      this.connect(0);
   }

   public synchronized void connect(int timeout_milliseconds) throws IOException {
      synchronized(this.state) {
         if (this.state.cb_conn == null) {
            throw new IllegalStateException("The callback for connection events has not been set.");
         }

         if (this.state.cb_auth == null) {
            throw new IllegalStateException("The callback for authentication events has not been set.");
         }

         if (this.state.tm != null) {
            throw new IllegalStateException("The initial handshake has already been started.");
         }

         if (this.state.next_dsa_key == null && this.state.next_rsa_key == null) {
            throw new IllegalStateException("Neither a RSA nor a DSA host key has been specified!");
         }

         this.state.tm = new ServerTransportManager(this.state.s);
      }

      this.state.tm.connect(this.state);
      this.state.tm.getConnectionInfo(1);
   }

   public Socket getSocket() {
      return this.state.s;
   }

   public synchronized void forceKeyExchange() throws IOException {
      synchronized(this.state) {
         if (this.state.tm == null) {
            throw new IllegalStateException("Cannot force another key exchange, you need to start the key exchange first.");
         } else {
            this.state.tm.forceKeyExchange(this.state.next_cryptoWishList, (DHGexParameters)null, this.state.next_dsa_key, this.state.next_rsa_key);
         }
      }
   }

   public synchronized ConnectionInfo getConnectionInfo() throws IOException {
      synchronized(this.state) {
         if (this.state.tm == null) {
            throw new IllegalStateException("Cannot get details of connection, you need to start the key exchange first.");
         }
      }

      return this.state.tm.getConnectionInfo(1);
   }

   public synchronized void setDsaHostKey(DSAPrivateKey dsa_hostkey) {
      synchronized(this.state) {
         if (dsa_hostkey == null && this.state.next_dsa_key != null && this.state.tm != null) {
            throw new IllegalStateException("Cannot remove DSA hostkey after first key exchange.");
         } else {
            this.state.next_dsa_key = dsa_hostkey;
            this.fixCryptoWishList(this.state.next_cryptoWishList, this.state.next_dsa_key, this.state.next_rsa_key);
         }
      }
   }

   public synchronized void setRsaHostKey(RSAPrivateKey rsa_hostkey) {
      synchronized(this.state) {
         if (rsa_hostkey == null && this.state.next_rsa_key != null && this.state.tm != null) {
            throw new IllegalStateException("Cannot remove RSA hostkey after first key exchange.");
         } else {
            this.state.next_rsa_key = rsa_hostkey;
            this.fixCryptoWishList(this.state.next_cryptoWishList, this.state.next_dsa_key, this.state.next_rsa_key);
         }
      }
   }

   public void setPEMHostKey(char[] pemdata, String password) throws IOException {
      Object key = PEMDecoder.decode(pemdata, password);
      if (key instanceof DSAPrivateKey) {
         this.setDsaHostKey((DSAPrivateKey)key);
      }

      if (key instanceof RSAPrivateKey) {
         this.setRsaHostKey((RSAPrivateKey)key);
      }

   }

   public void setPEMHostKey(File pemFile, String password) throws IOException {
      if (pemFile == null) {
         throw new IllegalArgumentException("pemfile argument is null");
      } else {
         char[] buff = new char[256];
         CharArrayWriter cw = new CharArrayWriter();
         FileReader fr = new FileReader(pemFile);

         while(true) {
            int len = fr.read(buff);
            if (len < 0) {
               fr.close();
               this.setPEMHostKey(cw.toCharArray(), password);
               return;
            }

            cw.write(buff, 0, len);
         }
      }
   }

   private void fixCryptoWishList(CryptoWishList next_cryptoWishList, DSAPrivateKey next_dsa_key, RSAPrivateKey next_rsa_key) {
      if (next_dsa_key != null && next_rsa_key != null) {
         next_cryptoWishList.serverHostKeyAlgorithms = new String[]{"ssh-rsa", "ssh-dss"};
      } else if (next_dsa_key != null) {
         next_cryptoWishList.serverHostKeyAlgorithms = new String[]{"ssh-dss"};
      } else if (next_rsa_key != null) {
         next_cryptoWishList.serverHostKeyAlgorithms = new String[]{"ssh-rsa"};
      } else {
         next_cryptoWishList.serverHostKeyAlgorithms = new String[0];
      }

   }

   public synchronized void setServerConnectionCallback(ServerConnectionCallback cb) {
      synchronized(this.state) {
         this.state.cb_conn = cb;
      }
   }

   public synchronized void setAuthenticationCallback(ServerAuthenticationCallback cb) {
      synchronized(this.state) {
         this.state.cb_auth = cb;
      }
   }

   public void close() {
      Throwable t = new Throwable("Closed due to user request.");
      this.close(t, false);
   }

   public void close(Throwable t, boolean hard) {
      synchronized(this.state) {
         if (this.state.cm != null) {
            this.state.cm.closeAllChannels();
         }

         if (this.state.tm != null) {
            this.state.tm.close(t, !hard);
         }

      }
   }
}
