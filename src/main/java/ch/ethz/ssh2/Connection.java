package ch.ethz.ssh2;

import ch.ethz.ssh2.auth.AgentProxy;
import ch.ethz.ssh2.auth.AuthenticationManager;
import ch.ethz.ssh2.channel.ChannelManager;
import ch.ethz.ssh2.crypto.CryptoWishList;
import ch.ethz.ssh2.crypto.cipher.BlockCipherFactory;
import ch.ethz.ssh2.crypto.digest.MAC;
import ch.ethz.ssh2.packets.PacketIgnore;
import ch.ethz.ssh2.signature.DSAPrivateKey;
import ch.ethz.ssh2.signature.RSAPrivateKey;
import ch.ethz.ssh2.transport.ClientTransportManager;
import ch.ethz.ssh2.transport.HTTPProxyClientTransportManager;
import ch.ethz.ssh2.transport.KexManager;
import ch.ethz.ssh2.util.TimeoutService;
import java.io.CharArrayWriter;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class Connection {
   private String softwareversion;
   private SecureRandom generator;
   private AuthenticationManager am;
   private boolean authenticated;
   private ChannelManager cm;
   private CryptoWishList cryptoWishList;
   private DHGexParameters dhgexpara;
   private final String hostname;
   private final int port;
   private ClientTransportManager tm;
   private boolean tcpNoDelay;
   private HTTPProxyData proxy;
   private List<ConnectionMonitor> connectionMonitors;

   public static synchronized String[] getAvailableCiphers() {
      return BlockCipherFactory.getDefaultCipherList();
   }

   public static synchronized String[] getAvailableMACs() {
      return MAC.getMacList();
   }

   public static synchronized String[] getAvailableServerHostKeyAlgorithms() {
      return KexManager.getDefaultServerHostkeyAlgorithmList();
   }

   public Connection(String hostname) {
      this(hostname, 22);
   }

   public Connection(String hostname, int port) {
      this.softwareversion = String.format("Ganymed_%s", Version.getSpecification());
      this.cryptoWishList = new CryptoWishList();
      this.dhgexpara = new DHGexParameters();
      this.tcpNoDelay = false;
      this.connectionMonitors = new ArrayList();
      this.hostname = hostname;
      this.port = port;
      String[] newalgo = new String[]{"ssh-rsa", "rsa-sha2-512"};
      String[] mergedArray = new String[getAvailableServerHostKeyAlgorithms().length + newalgo.length];
      System.arraycopy(getAvailableServerHostKeyAlgorithms(), 0, mergedArray, 0, getAvailableServerHostKeyAlgorithms().length);
      System.arraycopy(newalgo, 0, mergedArray, getAvailableServerHostKeyAlgorithms().length, newalgo.length);
      this.setServerHostKeyAlgorithms(mergedArray);
   }

   public Connection(String hostname, int port, String softwareversion) {
      this.softwareversion = String.format("Ganymed_%s", Version.getSpecification());
      this.cryptoWishList = new CryptoWishList();
      this.dhgexpara = new DHGexParameters();
      this.tcpNoDelay = false;
      this.connectionMonitors = new ArrayList();
      this.hostname = hostname;
      this.port = port;
      this.softwareversion = softwareversion;
   }

   public Connection(String hostname, int port, HTTPProxyData proxy) {
      this.softwareversion = String.format("Ganymed_%s", Version.getSpecification());
      this.cryptoWishList = new CryptoWishList();
      this.dhgexpara = new DHGexParameters();
      this.tcpNoDelay = false;
      this.connectionMonitors = new ArrayList();
      this.hostname = hostname;
      this.port = port;
      this.proxy = proxy;
   }

   public Connection(String hostname, int port, String softwareversion, HTTPProxyData proxy) {
      this.softwareversion = String.format("Ganymed_%s", Version.getSpecification());
      this.cryptoWishList = new CryptoWishList();
      this.dhgexpara = new DHGexParameters();
      this.tcpNoDelay = false;
      this.connectionMonitors = new ArrayList();
      this.hostname = hostname;
      this.port = port;
      this.softwareversion = softwareversion;
      this.proxy = proxy;
   }

   /** @deprecated */
   public synchronized boolean authenticateWithDSA(String user, String pem, String password) throws IOException {
      if (this.tm == null) {
         throw new IllegalStateException("Connection is not established!");
      } else if (this.authenticated) {
         throw new IllegalStateException("Connection is already authenticated!");
      } else {
         if (this.am == null) {
            this.am = new AuthenticationManager(this.tm);
         }

         if (this.cm == null) {
            this.cm = new ChannelManager(this.tm);
         }

         if (user == null) {
            throw new IllegalArgumentException("user argument is null");
         } else if (pem == null) {
            throw new IllegalArgumentException("pem argument is null");
         } else {
            this.authenticated = this.am.authenticatePublicKey(user, pem.toCharArray(), password, this.getOrCreateSecureRND());
            return this.authenticated;
         }
      }
   }

   public synchronized boolean authenticateWithKeyboardInteractive(String user, InteractiveCallback cb) throws IOException {
      return this.authenticateWithKeyboardInteractive(user, (String[])null, cb);
   }

   public synchronized boolean authenticateWithKeyboardInteractive(String user, String[] submethods, InteractiveCallback cb) throws IOException {
      if (cb == null) {
         throw new IllegalArgumentException("Callback may not ne NULL!");
      } else if (this.tm == null) {
         throw new IllegalStateException("Connection is not established!");
      } else if (this.authenticated) {
         throw new IllegalStateException("Connection is already authenticated!");
      } else {
         if (this.am == null) {
            this.am = new AuthenticationManager(this.tm);
         }

         if (this.cm == null) {
            this.cm = new ChannelManager(this.tm);
         }

         if (user == null) {
            throw new IllegalArgumentException("user argument is null");
         } else {
            this.authenticated = this.am.authenticateInteractive(user, submethods, cb);
            return this.authenticated;
         }
      }
   }

   public synchronized boolean authenticateWithAgent(String user, AgentProxy proxy) throws IOException {
      if (this.tm == null) {
         throw new IllegalStateException("Connection is not established!");
      } else if (this.authenticated) {
         throw new IllegalStateException("Connection is already authenticated!");
      } else {
         if (this.am == null) {
            this.am = new AuthenticationManager(this.tm);
         }

         if (this.cm == null) {
            this.cm = new ChannelManager(this.tm);
         }

         if (user == null) {
            throw new IllegalArgumentException("user argument is null");
         } else {
            this.authenticated = this.am.authenticatePublicKey(user, proxy);
            return this.authenticated;
         }
      }
   }

   public synchronized boolean authenticateWithPassword(String user, String password) throws IOException {
      if (this.tm == null) {
         throw new IllegalStateException("Connection is not established!");
      } else if (this.authenticated) {
         throw new IllegalStateException("Connection is already authenticated!");
      } else {
         if (this.am == null) {
            this.am = new AuthenticationManager(this.tm);
         }

         if (this.cm == null) {
            this.cm = new ChannelManager(this.tm);
         }

         if (user == null) {
            throw new IllegalArgumentException("user argument is null");
         } else if (password == null) {
            throw new IllegalArgumentException("password argument is null");
         } else {
            this.authenticated = this.am.authenticatePassword(user, password);
            return this.authenticated;
         }
      }
   }

   public synchronized boolean authenticateWithNone(String user) throws IOException {
      if (this.tm == null) {
         throw new IllegalStateException("Connection is not established!");
      } else if (this.authenticated) {
         throw new IllegalStateException("Connection is already authenticated!");
      } else {
         if (this.am == null) {
            this.am = new AuthenticationManager(this.tm);
         }

         if (this.cm == null) {
            this.cm = new ChannelManager(this.tm);
         }

         if (user == null) {
            throw new IllegalArgumentException("user argument is null");
         } else {
            this.authenticated = this.am.authenticateNone(user);
            return this.authenticated;
         }
      }
   }

   public synchronized boolean authenticateWithPublicKey(String user, char[] pemPrivateKey, String password) throws IOException {
      if (this.tm == null) {
         throw new IllegalStateException("Connection is not established!");
      } else if (this.authenticated) {
         throw new IllegalStateException("Connection is already authenticated!");
      } else {
         if (this.am == null) {
            this.am = new AuthenticationManager(this.tm);
         }

         if (this.cm == null) {
            this.cm = new ChannelManager(this.tm);
         }

         if (user == null) {
            throw new IllegalArgumentException("user argument is null");
         } else if (pemPrivateKey == null) {
            throw new IllegalArgumentException("pemPrivateKey argument is null");
         } else {
            this.authenticated = this.am.authenticatePublicKey(user, pemPrivateKey, password, this.getOrCreateSecureRND());
            return this.authenticated;
         }
      }
   }

   public synchronized boolean authenticateWithPublicKey(String user, File pemFile, String password) throws IOException {
      if (pemFile == null) {
         throw new IllegalArgumentException("pemFile argument is null");
      } else {
         char[] buff = new char[256];
         CharArrayWriter cw = new CharArrayWriter();
         FileReader fr = new FileReader(pemFile);

         while(true) {
            int len = fr.read(buff);
            if (len < 0) {
               fr.close();
               return this.authenticateWithPublicKey(user, cw.toCharArray(), password);
            }

            cw.write(buff, 0, len);
         }
      }
   }

   public synchronized void addConnectionMonitor(ConnectionMonitor cmon) {
      if (cmon == null) {
         throw new IllegalArgumentException("cmon argument is null");
      } else {
         if (!this.connectionMonitors.contains(cmon)) {
            this.connectionMonitors.add(cmon);
            if (this.tm != null) {
               this.tm.setConnectionMonitors(this.connectionMonitors);
            }
         }

      }
   }

   public synchronized boolean removeConnectionMonitor(ConnectionMonitor cmon) {
      if (cmon == null) {
         throw new IllegalArgumentException("cmon argument is null");
      } else {
         boolean existed = this.connectionMonitors.remove(cmon);
         if (this.tm != null) {
            this.tm.setConnectionMonitors(this.connectionMonitors);
         }

         return existed;
      }
   }

   public synchronized void close() {
      Throwable t = new Throwable("Closed due to user request.");
      this.close(t, false);
   }

   public synchronized void close(Throwable t, boolean hard) {
      if (this.cm != null) {
         this.cm.closeAllChannels();
      }

      if (this.tm != null) {
         this.tm.close(t, !hard);
         this.tm = null;
      }

      this.am = null;
      this.cm = null;
      this.authenticated = false;
   }

   public synchronized ConnectionInfo connect() throws IOException {
      return this.connect((ServerHostKeyVerifier)null, 0, 0);
   }

   public synchronized ConnectionInfo connect(ServerHostKeyVerifier verifier) throws IOException {
      return this.connect(verifier, 0, 0);
   }

   public synchronized ConnectionInfo connect(ServerHostKeyVerifier verifier, int connectTimeout, int kexTimeout) throws IOException {
      if (this.tm != null) {
         throw new IOException("Connection to " + this.hostname + " is already in connected state!");
      } else if (connectTimeout < 0) {
         throw new IllegalArgumentException("connectTimeout must be non-negative!");
      } else if (kexTimeout < 0) {
         throw new IllegalArgumentException("kexTimeout must be non-negative!");
      } else {
         final class TimeoutState {
            boolean isCancelled = false;
            boolean timeoutSocketClosed = false;
         }

         final TimeoutState state = new TimeoutState();
         if (this.proxy == null) {
            this.tm = new ClientTransportManager();
         } else {
            this.tm = new HTTPProxyClientTransportManager(this.proxy);
         }

         this.tm.setSoTimeout(connectTimeout);
         this.tm.setTcpNoDelay(this.tcpNoDelay);
         this.tm.setConnectionMonitors(this.connectionMonitors);

         try {
            TimeoutService.TimeoutToken token = null;
            if (kexTimeout > 0) {
               Runnable timeoutHandler = new Runnable() {
                  public void run() {
                     synchronized(state) {
                        if (!state.isCancelled) {
                           state.timeoutSocketClosed = true;
                           Connection.this.tm.close(new SocketTimeoutException("The connect timeout expired"));
                        }
                     }
                  }
               };
               long timeoutHorizont = System.currentTimeMillis() + (long)kexTimeout;
               token = TimeoutService.addTimeoutHandler(timeoutHorizont, timeoutHandler);
            }

            this.tm.connect(this.hostname, this.port, this.softwareversion, this.cryptoWishList, verifier, this.dhgexpara, connectTimeout, this.getOrCreateSecureRND());
            ConnectionInfo ci = this.tm.getConnectionInfo(1);
            if (token != null) {
               TimeoutService.cancelTimeoutHandler(token);
               synchronized(state) {
                  if (state.timeoutSocketClosed) {
                     throw new IOException("This exception will be replaced by the one below =)");
                  }

                  state.isCancelled = true;
               }
            }

            return ci;
         } catch (SocketTimeoutException var11) {
            throw var11;
         } catch (HTTPProxyException var12) {
            throw var12;
         } catch (IOException var13) {
            this.close(var13, false);
            synchronized(state) {
               if (state.timeoutSocketClosed) {
                  throw new SocketTimeoutException(String.format("The kexTimeout (%d ms) expired.", kexTimeout));
               }
            }

            throw var13;
         }
      }
   }

   public synchronized LocalPortForwarder createLocalPortForwarder(int local_port, String host_to_connect, int port_to_connect) throws IOException {
      this.checkConnection();
      return new LocalPortForwarder(this.cm, local_port, host_to_connect, port_to_connect);
   }

   public synchronized LocalPortForwarder createLocalPortForwarder(InetSocketAddress addr, String host_to_connect, int port_to_connect) throws IOException {
      this.checkConnection();
      return new LocalPortForwarder(this.cm, addr, host_to_connect, port_to_connect);
   }

   public synchronized LocalStreamForwarder createLocalStreamForwarder(String host_to_connect, int port_to_connect) throws IOException {
      this.checkConnection();
      return new LocalStreamForwarder(this.cm, host_to_connect, port_to_connect);
   }

   public synchronized SCPClient createSCPClient() throws IOException {
      this.checkConnection();
      return new SCPClient(this);
   }

   public synchronized void forceKeyExchange() throws IOException {
      this.checkConnection();
      this.tm.forceKeyExchange(this.cryptoWishList, this.dhgexpara, (DSAPrivateKey)null, (RSAPrivateKey)null);
   }

   public synchronized String getHostname() {
      return this.hostname;
   }

   public synchronized int getPort() {
      return this.port;
   }

   public synchronized ConnectionInfo getConnectionInfo() throws IOException {
      this.checkConnection();
      return this.tm.getConnectionInfo(1);
   }

   public synchronized String[] getRemainingAuthMethods(String user) throws IOException {
      if (user == null) {
         throw new IllegalArgumentException("user argument may not be NULL!");
      } else if (this.tm == null) {
         throw new IllegalStateException("Connection is not established!");
      } else if (this.authenticated) {
         throw new IllegalStateException("Connection is already authenticated!");
      } else {
         if (this.am == null) {
            this.am = new AuthenticationManager(this.tm);
         }

         if (this.cm == null) {
            this.cm = new ChannelManager(this.tm);
         }

         return this.am.getRemainingMethods(user);
      }
   }

   public synchronized boolean isAuthenticationComplete() {
      return this.authenticated;
   }

   public synchronized boolean isAuthenticationPartialSuccess() {
      return this.am == null ? false : this.am.getPartialSuccess();
   }

   public synchronized boolean isAuthMethodAvailable(String user, String method) throws IOException {
      String[] methods = this.getRemainingAuthMethods(user);
      String[] var7 = methods;
      int var6 = methods.length;

      for(int var5 = 0; var5 < var6; ++var5) {
         String m = var7[var5];
         if (m.compareTo(method) == 0) {
            return true;
         }
      }

      return false;
   }

   private SecureRandom getOrCreateSecureRND() {
      if (this.generator == null) {
         this.generator = new SecureRandom();
      }

      return this.generator;
   }

   public synchronized Session openSession() throws IOException {
      this.checkConnection();
      return new Session(this.cm, this.getOrCreateSecureRND());
   }

   public synchronized void sendIgnorePacket() throws IOException {
      SecureRandom rnd = this.getOrCreateSecureRND();
      byte[] data = new byte[rnd.nextInt(16)];
      rnd.nextBytes(data);
      this.sendIgnorePacket(data);
   }

   public synchronized void sendIgnorePacket(byte[] data) throws IOException {
      this.checkConnection();
      PacketIgnore pi = new PacketIgnore();
      pi.setData(data);
      this.tm.sendMessage(pi.getPayload());
   }

   private String[] removeDuplicates(String[] list) {
      if (list != null && list.length >= 2) {
         String[] list2 = new String[list.length];
         int count = 0;
         String[] var7 = list;
         int var6 = list.length;

         for(int var5 = 0; var5 < var6; ++var5) {
            String element = var7[var5];
            boolean duplicate = false;

            for(int j = 0; j < count; ++j) {
               if (element == null && list2[j] == null || element != null && element.equals(list2[j])) {
                  duplicate = true;
                  break;
               }
            }

            if (!duplicate) {
               list2[count++] = element;
            }
         }

         if (count == list2.length) {
            return list2;
         } else {
            String[] tmp = new String[count];
            System.arraycopy(list2, 0, tmp, 0, count);
            return tmp;
         }
      } else {
         return list;
      }
   }

   public synchronized void setClient2ServerCiphers(String[] ciphers) {
      if (ciphers != null && ciphers.length != 0) {
         ciphers = this.removeDuplicates(ciphers);
         BlockCipherFactory.checkCipherList(ciphers);
         this.cryptoWishList.c2s_enc_algos = ciphers;
      } else {
         throw new IllegalArgumentException();
      }
   }

   public synchronized void setClient2ServerMACs(String[] macs) {
      if (macs != null && macs.length != 0) {
         macs = this.removeDuplicates(macs);
         MAC.checkMacList(macs);
         this.cryptoWishList.c2s_mac_algos = macs;
      } else {
         throw new IllegalArgumentException();
      }
   }

   public synchronized void setDHGexParameters(DHGexParameters dgp) {
      if (dgp == null) {
         throw new IllegalArgumentException();
      } else {
         this.dhgexpara = dgp;
      }
   }

   public synchronized void setServer2ClientCiphers(String[] ciphers) {
      if (ciphers != null && ciphers.length != 0) {
         ciphers = this.removeDuplicates(ciphers);
         BlockCipherFactory.checkCipherList(ciphers);
         this.cryptoWishList.s2c_enc_algos = ciphers;
      } else {
         throw new IllegalArgumentException();
      }
   }

   public synchronized void setServer2ClientMACs(String[] macs) {
      if (macs != null && macs.length != 0) {
         macs = this.removeDuplicates(macs);
         MAC.checkMacList(macs);
         this.cryptoWishList.s2c_mac_algos = macs;
      } else {
         throw new IllegalArgumentException();
      }
   }

   public synchronized void setServerHostKeyAlgorithms(String[] algos) {
      if (algos != null && algos.length != 0) {
         algos = this.removeDuplicates(algos);
         KexManager.checkServerHostkeyAlgorithmsList(algos);
         this.cryptoWishList.serverHostKeyAlgorithms = algos;
      } else {
         throw new IllegalArgumentException();
      }
   }

   public synchronized void setClientKexAlgorithms(String[] algos) {
      if (algos != null && algos.length != 0) {
         algos = this.removeDuplicates(algos);
         KexManager.checkClientKexAlgorithmList(algos);
         this.cryptoWishList.kexAlgorithms = algos;
      } else {
         throw new IllegalArgumentException();
      }
   }

   public synchronized void setTCPNoDelay(boolean enable) throws IOException {
      this.tcpNoDelay = enable;
      if (this.tm != null) {
         this.tm.setTcpNoDelay(enable);
      }

   }

   public synchronized void requestRemotePortForwarding(String bindAddress, int bindPort, String targetAddress, int targetPort) throws IOException {
      this.checkConnection();
      if (bindAddress != null && targetAddress != null && bindPort > 0 && targetPort > 0) {
         this.cm.requestGlobalForward(bindAddress, bindPort, targetAddress, targetPort);
      } else {
         throw new IllegalArgumentException();
      }
   }

   public synchronized void cancelRemotePortForwarding(int bindPort) throws IOException {
      this.checkConnection();
      this.cm.requestCancelGlobalForward(bindPort);
   }

   public synchronized void setSecureRandom(SecureRandom rnd) {
      if (rnd == null) {
         throw new IllegalArgumentException();
      } else {
         this.generator = rnd;
      }
   }

   private void checkConnection() throws IllegalStateException {
      if (this.tm == null) {
         throw new IllegalStateException("You need to establish a connection first.");
      } else if (!this.authenticated) {
         throw new IllegalStateException("The connection is not authenticated.");
      }
   }
}
