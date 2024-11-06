package ch.ethz.ssh2.transport;

import ch.ethz.ssh2.ConnectionInfo;
import ch.ethz.ssh2.DHGexParameters;
import ch.ethz.ssh2.crypto.CryptoWishList;
import ch.ethz.ssh2.crypto.KeyMaterial;
import ch.ethz.ssh2.crypto.cipher.BlockCipher;
import ch.ethz.ssh2.crypto.cipher.BlockCipherFactory;
import ch.ethz.ssh2.crypto.digest.MAC;
import ch.ethz.ssh2.log.Logger;
import ch.ethz.ssh2.packets.PacketKexInit;
import ch.ethz.ssh2.packets.PacketNewKeys;
import ch.ethz.ssh2.signature.DSAPrivateKey;
import ch.ethz.ssh2.signature.RSAPrivateKey;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.security.SecureRandom;
import java.util.Arrays;

public abstract class KexManager implements MessageHandler {
   protected static final Logger log = Logger.getLogger(KexManager.class);
   KexState kxs;
   int kexCount = 0;
   KeyMaterial km;
   byte[] sessionId;
   ClientServerHello csh;
   final Object accessLock = new Object();
   ConnectionInfo lastConnInfo = null;
   boolean connectionClosed = false;
   boolean ignore_next_kex_packet = false;
   final TransportManager tm;
   CryptoWishList nextKEXcryptoWishList;
   DHGexParameters nextKEXdhgexParameters;
   DSAPrivateKey nextKEXdsakey;
   RSAPrivateKey nextKEXrsakey;
   final SecureRandom rnd;

   public KexManager(TransportManager tm, ClientServerHello csh, CryptoWishList initialCwl, SecureRandom rnd) {
      this.tm = tm;
      this.csh = csh;
      this.nextKEXcryptoWishList = initialCwl;
      this.nextKEXdhgexParameters = new DHGexParameters();
      this.rnd = rnd;
   }

   public ConnectionInfo getOrWaitForConnectionInfo(int minKexCount) throws IOException {
      synchronized(this.accessLock) {
         while(this.lastConnInfo == null || this.lastConnInfo.keyExchangeCounter < minKexCount) {
            if (this.connectionClosed) {
               throw new IOException("Key exchange was not finished, connection is closed.", this.tm.getReasonClosedCause());
            }

            try {
               this.accessLock.wait();
            } catch (InterruptedException var4) {
               throw new InterruptedIOException(var4.getMessage());
            }
         }

         return this.lastConnInfo;
      }
   }

   private String getFirstMatch(String[] client, String[] server) throws NegotiateException {
      if (client != null && server != null) {
         if (client.length == 0) {
            return null;
         } else {
            for(int i = 0; i < client.length; ++i) {
               for(int j = 0; j < server.length; ++j) {
                  if (client[i].equals(server[j])) {
                     return client[i];
                  }
               }
            }

            throw new NegotiateException();
         }
      } else {
         throw new IllegalArgumentException();
      }
   }

   private boolean compareFirstOfNameList(String[] a, String[] b) {
      if (a != null && b != null) {
         if (a.length == 0 && b.length == 0) {
            return true;
         } else {
            return a.length != 0 && b.length != 0 ? a[0].equals(b[0]) : false;
         }
      } else {
         throw new IllegalArgumentException();
      }
   }

   private boolean isGuessOK(KexParameters cpar, KexParameters spar) {
      if (cpar != null && spar != null) {
         if (!this.compareFirstOfNameList(cpar.kex_algorithms, spar.kex_algorithms)) {
            return false;
         } else {
            return this.compareFirstOfNameList(cpar.server_host_key_algorithms, spar.server_host_key_algorithms);
         }
      } else {
         throw new IllegalArgumentException();
      }
   }

   protected NegotiatedParameters mergeKexParameters(KexParameters client, KexParameters server) {
      NegotiatedParameters np = new NegotiatedParameters();

      try {
         np.kex_algo = this.getFirstMatch(client.kex_algorithms, server.kex_algorithms);
         log.info("kex_algo=" + np.kex_algo);
         np.server_host_key_algo = this.getFirstMatch(client.server_host_key_algorithms, server.server_host_key_algorithms);
         log.info("server_host_key_algo=" + np.server_host_key_algo);
         np.enc_algo_client_to_server = this.getFirstMatch(client.encryption_algorithms_client_to_server, server.encryption_algorithms_client_to_server);
         np.enc_algo_server_to_client = this.getFirstMatch(client.encryption_algorithms_server_to_client, server.encryption_algorithms_server_to_client);
         log.info("enc_algo_client_to_server=" + np.enc_algo_client_to_server);
         log.info("enc_algo_server_to_client=" + np.enc_algo_server_to_client);
         np.mac_algo_client_to_server = this.getFirstMatch(client.mac_algorithms_client_to_server, server.mac_algorithms_client_to_server);
         np.mac_algo_server_to_client = this.getFirstMatch(client.mac_algorithms_server_to_client, server.mac_algorithms_server_to_client);
         log.info("mac_algo_client_to_server=" + np.mac_algo_client_to_server);
         log.info("mac_algo_server_to_client=" + np.mac_algo_server_to_client);
         np.comp_algo_client_to_server = this.getFirstMatch(client.compression_algorithms_client_to_server, server.compression_algorithms_client_to_server);
         np.comp_algo_server_to_client = this.getFirstMatch(client.compression_algorithms_server_to_client, server.compression_algorithms_server_to_client);
         log.info("comp_algo_client_to_server=" + np.comp_algo_client_to_server);
         log.info("comp_algo_server_to_client=" + np.comp_algo_server_to_client);
      } catch (NegotiateException var7) {
         var7.printStackTrace();
         return null;
      }

      try {
         np.lang_client_to_server = this.getFirstMatch(client.languages_client_to_server, server.languages_client_to_server);
      } catch (NegotiateException var6) {
         np.lang_client_to_server = null;
      }

      try {
         np.lang_server_to_client = this.getFirstMatch(client.languages_server_to_client, server.languages_server_to_client);
      } catch (NegotiateException var5) {
         np.lang_server_to_client = null;
      }

      if (this.isGuessOK(client, server)) {
         np.guessOK = true;
      }

      return np;
   }

   public synchronized void initiateKEX(CryptoWishList cwl, DHGexParameters dhgex, DSAPrivateKey dsa, RSAPrivateKey rsa) throws IOException {
      this.nextKEXcryptoWishList = cwl;
      this.nextKEXdhgexParameters = dhgex;
      this.nextKEXdsakey = dsa;
      this.nextKEXrsakey = rsa;
      if (this.kxs == null) {
         this.kxs = new KexState();
         this.kxs.local_dsa_key = dsa;
         this.kxs.local_rsa_key = rsa;
         this.kxs.dhgexParameters = this.nextKEXdhgexParameters;
         this.kxs.localKEX = new PacketKexInit(this.nextKEXcryptoWishList, this.rnd);
         this.tm.sendKexMessage(this.kxs.localKEX.getPayload());
      }

   }

   private boolean establishKeyMaterial() {
      try {
         int mac_cs_key_len = MAC.getKeyLen(this.kxs.np.mac_algo_client_to_server);
         int enc_cs_key_len = BlockCipherFactory.getKeySize(this.kxs.np.enc_algo_client_to_server);
         int enc_cs_block_len = BlockCipherFactory.getBlockSize(this.kxs.np.enc_algo_client_to_server);
         int mac_sc_key_len = MAC.getKeyLen(this.kxs.np.mac_algo_server_to_client);
         int enc_sc_key_len = BlockCipherFactory.getKeySize(this.kxs.np.enc_algo_server_to_client);
         int enc_sc_block_len = BlockCipherFactory.getBlockSize(this.kxs.np.enc_algo_server_to_client);
         String hash = this.kxs.dhx != null ? this.kxs.dhx.getHashFunction() : "SHA1";
         this.km = KeyMaterial.create(hash, this.kxs.H, this.kxs.K, this.sessionId, enc_cs_key_len, enc_cs_block_len, mac_cs_key_len, enc_sc_key_len, enc_sc_block_len, mac_sc_key_len);
         return true;
      } catch (IllegalArgumentException var8) {
         return false;
      }
   }

   protected void finishKex(boolean clientMode) throws IOException {
      if (this.sessionId == null) {
         this.sessionId = this.kxs.H;
      }

      this.establishKeyMaterial();
      PacketNewKeys ign = new PacketNewKeys();
      this.tm.sendKexMessage(ign.getPayload());

      BlockCipher cbc;
      MAC mac;
      try {
         cbc = BlockCipherFactory.createCipher(clientMode ? this.kxs.np.enc_algo_client_to_server : this.kxs.np.enc_algo_server_to_client, true, clientMode ? this.km.enc_key_client_to_server : this.km.enc_key_server_to_client, clientMode ? this.km.initial_iv_client_to_server : this.km.initial_iv_server_to_client);
         mac = new MAC(clientMode ? this.kxs.np.mac_algo_client_to_server : this.kxs.np.mac_algo_server_to_client, clientMode ? this.km.integrity_key_client_to_server : this.km.integrity_key_server_to_client);
      } catch (IllegalArgumentException var6) {
         throw new IOException("Fatal error during MAC startup!");
      }

      this.tm.changeSendCipher(cbc, mac);
      this.tm.kexFinished();
   }

   public static final String[] getDefaultServerHostkeyAlgorithmList() {
      return new String[]{"ssh-rsa", "ssh-dss", "rsa-sha2-256", "rsa-sha2-512"};
   }

   public static final void checkServerHostkeyAlgorithmsList(String[] algos) {
      for(int i = 0; i < algos.length; ++i) {
         if (!"ssh-rsa".equals(algos[i]) && !"ssh-dss".equals(algos[i]) && !"rsa-sha2-256".equals(algos[i]) && !"rsa-sha2-512".equals(algos[i])) {
            throw new IllegalArgumentException("Unknown server host key algorithm '" + algos[i] + "'");
         }
      }

   }

   public static final String[] getDefaultClientKexAlgorithmList() {
      return new String[]{"diffie-hellman-group14-sha256", "diffie-hellman-group16-sha512", "diffie-hellman-group18-sha512", "diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1"};
   }

   public static final void checkClientKexAlgorithmList(String[] algos) {
      String[] defaultAlgos = getDefaultClientKexAlgorithmList();
      Arrays.sort(defaultAlgos);
      String[] var5 = algos;
      int var4 = algos.length;

      for(int var3 = 0; var3 < var4; ++var3) {
         String algo = var5[var3];
         if (Arrays.binarySearch(defaultAlgos, algo) < 0) {
            throw new IllegalArgumentException("Unknown KEX method " + algo);
         }
      }

   }

   public static final String[] getDefaultServerKexAlgorithmList() {
      return new String[]{"diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"};
   }
}
