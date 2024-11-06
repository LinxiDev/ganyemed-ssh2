package ch.ethz.ssh2.transport;

import ch.ethz.ssh2.ConnectionInfo;
import ch.ethz.ssh2.auth.ServerAuthenticationManager;
import ch.ethz.ssh2.crypto.cipher.BlockCipher;
import ch.ethz.ssh2.crypto.cipher.BlockCipherFactory;
import ch.ethz.ssh2.crypto.dh.DhExchange;
import ch.ethz.ssh2.crypto.digest.MAC;
import ch.ethz.ssh2.packets.PacketKexDHInit;
import ch.ethz.ssh2.packets.PacketKexDHReply;
import ch.ethz.ssh2.packets.PacketKexInit;
import ch.ethz.ssh2.server.ServerConnectionState;
import ch.ethz.ssh2.signature.DSASHA1Verify;
import ch.ethz.ssh2.signature.DSASignature;
import ch.ethz.ssh2.signature.RSASHA1Verify;
import ch.ethz.ssh2.signature.RSASignature;
import java.io.IOException;

public class ServerKexManager extends KexManager {
   private final ServerConnectionState state;
   private boolean authenticationStarted = false;

   public ServerKexManager(ServerConnectionState state) {
      super(state.tm, state.csh, state.next_cryptoWishList, state.generator);
      this.state = state;
   }

   public void handleMessage(byte[] msg, int msglen) throws IOException {
      if (msg == null) {
         synchronized(this.accessLock) {
            this.connectionClosed = true;
            this.accessLock.notifyAll();
         }
      } else if (this.kxs == null && msg[0] != 20) {
         throw new IOException("Unexpected KEX message (type " + msg[0] + ")");
      } else if (this.ignore_next_kex_packet) {
         this.ignore_next_kex_packet = false;
      } else if (msg[0] == 20) {
         if (this.kxs != null && this.kxs.state != 0) {
            throw new IOException("Unexpected SSH_MSG_KEXINIT message during on-going kex exchange!");
         } else {
            PacketKexInit kip;
            if (this.kxs == null) {
               this.kxs = new KexState();
               this.kxs.local_dsa_key = this.nextKEXdsakey;
               this.kxs.local_rsa_key = this.nextKEXrsakey;
               this.kxs.dhgexParameters = this.nextKEXdhgexParameters;
               kip = new PacketKexInit(this.nextKEXcryptoWishList, this.rnd);
               this.kxs.localKEX = kip;
               this.tm.sendKexMessage(kip.getPayload());
            }

            kip = new PacketKexInit(msg, 0, msglen);
            this.kxs.remoteKEX = kip;
            this.kxs.np = this.mergeKexParameters(this.kxs.remoteKEX.getKexParameters(), this.kxs.localKEX.getKexParameters());
            if (this.kxs.np == null) {
               throw new IOException("Cannot negotiate, proposals do not match.");
            } else {
               if (this.kxs.remoteKEX.isFirst_kex_packet_follows() && !this.kxs.np.guessOK) {
                  this.ignore_next_kex_packet = true;
               }

               if (!this.kxs.np.kex_algo.equals("diffie-hellman-group1-sha1") && !this.kxs.np.kex_algo.equals("diffie-hellman-group14-sha1")) {
                  throw new IllegalStateException("Unkown KEX method!");
               } else {
                  this.kxs.dhx = new DhExchange("SHA1");
                  if (this.kxs.np.kex_algo.equals("diffie-hellman-group1-sha1")) {
                     this.kxs.dhx.serverInit(1, this.rnd);
                  } else {
                     this.kxs.dhx.serverInit(14, this.rnd);
                  }

                  this.kxs.state = 1;
               }
            }
         }
      } else if (msg[0] == 21) {
         if (this.km == null) {
            throw new IOException("Peer sent SSH_MSG_NEWKEYS, but I have no key material ready!");
         } else {
            BlockCipher cbc;
            MAC mac;
            try {
               cbc = BlockCipherFactory.createCipher(this.kxs.np.enc_algo_client_to_server, false, this.km.enc_key_client_to_server, this.km.initial_iv_client_to_server);
               mac = new MAC(this.kxs.np.mac_algo_client_to_server, this.km.integrity_key_client_to_server);
            } catch (IllegalArgumentException var10) {
               throw new IOException("Fatal error during MAC startup!");
            }

            this.tm.changeRecvCipher(cbc, mac);
            ConnectionInfo sci = new ConnectionInfo();
            ++this.kexCount;
            sci.keyExchangeAlgorithm = this.kxs.np.kex_algo;
            sci.keyExchangeCounter = this.kexCount;
            sci.clientToServerCryptoAlgorithm = this.kxs.np.enc_algo_client_to_server;
            sci.serverToClientCryptoAlgorithm = this.kxs.np.enc_algo_server_to_client;
            sci.clientToServerMACAlgorithm = this.kxs.np.mac_algo_client_to_server;
            sci.serverToClientMACAlgorithm = this.kxs.np.mac_algo_server_to_client;
            sci.serverHostKeyAlgorithm = this.kxs.np.server_host_key_algo;
            sci.serverHostKey = this.kxs.remote_hostkey;
            synchronized(this.accessLock) {
               this.lastConnInfo = sci;
               this.accessLock.notifyAll();
            }

            this.kxs = null;
         }
      } else if (this.kxs != null && this.kxs.state != 0) {
         if ((this.kxs.np.kex_algo.equals("diffie-hellman-group1-sha1") || this.kxs.np.kex_algo.equals("diffie-hellman-group14-sha1")) && this.kxs.state == 1) {
            PacketKexDHInit dhi = new PacketKexDHInit(msg, 0, msglen);
            this.kxs.dhx.setE(dhi.getE());
            byte[] hostKey = null;
            if (this.kxs.np.server_host_key_algo.equals("ssh-rsa")) {
               hostKey = RSASHA1Verify.encodeSSHRSAPublicKey(this.kxs.local_rsa_key.getPublicKey());
            }

            if (this.kxs.np.server_host_key_algo.equals("ssh-dss")) {
               hostKey = DSASHA1Verify.encodeSSHDSAPublicKey(this.kxs.local_dsa_key.getPublicKey());
            }

            try {
               this.kxs.H = this.kxs.dhx.calculateH(this.csh.getClientString(), this.csh.getServerString(), this.kxs.remoteKEX.getPayload(), this.kxs.localKEX.getPayload(), hostKey);
            } catch (IllegalArgumentException var11) {
               throw new IOException("KEX error.", var11);
            }

            this.kxs.K = this.kxs.dhx.getK();
            byte[] signature = null;
            if (this.kxs.np.server_host_key_algo.equals("ssh-rsa")) {
               RSASignature rs = RSASHA1Verify.generateSignature(this.kxs.H, this.kxs.local_rsa_key);
               signature = RSASHA1Verify.encodeSSHRSASignature(rs);
            }

            if (this.kxs.np.server_host_key_algo.equals("ssh-dss")) {
               DSASignature ds = DSASHA1Verify.generateSignature(this.kxs.H, this.kxs.local_dsa_key, this.rnd);
               signature = DSASHA1Verify.encodeSSHDSASignature(ds);
            }

            PacketKexDHReply dhr = new PacketKexDHReply(hostKey, this.kxs.dhx.getF(), signature);
            this.tm.sendKexMessage(dhr.getPayload());
            this.finishKex(false);
            this.kxs.state = -1;
            if (!this.authenticationStarted) {
               this.authenticationStarted = true;
               this.state.am = new ServerAuthenticationManager(this.state);
            }

         } else {
            throw new IllegalStateException("Unkown KEX method! (" + this.kxs.np.kex_algo + ")");
         }
      } else {
         throw new IOException("Unexpected Kex submessage!");
      }
   }
}
