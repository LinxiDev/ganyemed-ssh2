package ch.ethz.ssh2.transport;

import ch.ethz.ssh2.ConnectionInfo;
import ch.ethz.ssh2.ServerHostKeyVerifier;
import ch.ethz.ssh2.crypto.CryptoWishList;
import ch.ethz.ssh2.crypto.cipher.BlockCipher;
import ch.ethz.ssh2.crypto.cipher.BlockCipherFactory;
import ch.ethz.ssh2.crypto.dh.DhExchange;
import ch.ethz.ssh2.crypto.dh.DhGroupExchange;
import ch.ethz.ssh2.crypto.digest.MAC;
import ch.ethz.ssh2.packets.PacketKexDHInit;
import ch.ethz.ssh2.packets.PacketKexDHReply;
import ch.ethz.ssh2.packets.PacketKexDhGexGroup;
import ch.ethz.ssh2.packets.PacketKexDhGexInit;
import ch.ethz.ssh2.packets.PacketKexDhGexReply;
import ch.ethz.ssh2.packets.PacketKexDhGexRequest;
import ch.ethz.ssh2.packets.PacketKexDhGexRequestOld;
import ch.ethz.ssh2.packets.PacketKexInit;
import ch.ethz.ssh2.signature.DSAPublicKey;
import ch.ethz.ssh2.signature.DSASHA1Verify;
import ch.ethz.ssh2.signature.DSASignature;
import ch.ethz.ssh2.signature.RSAPublicKey;
import ch.ethz.ssh2.signature.RSASHA1Verify;
import ch.ethz.ssh2.signature.RSASignature;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class ClientKexManager extends KexManager {
   ServerHostKeyVerifier verifier;
   final String hostname;
   final int port;

   public ClientKexManager(TransportManager tm, ClientServerHello csh, CryptoWishList initialCwl, String hostname, int port, ServerHostKeyVerifier keyVerifier, SecureRandom rnd) {
      super(tm, csh, initialCwl, rnd);
      this.hostname = hostname;
      this.port = port;
      this.verifier = keyVerifier;
   }

   protected boolean verifySignature(byte[] sig, byte[] hostkey) throws IOException, NoSuchAlgorithmException {
      RSASignature rs;
      RSAPublicKey rpk;
      if (this.kxs.np.server_host_key_algo.equals("ssh-rsa")) {
         rs = RSASHA1Verify.decodeSSHRSASignature(sig);
         rpk = RSASHA1Verify.decodeSSHRSAPublicKey(hostkey);
         log.debug("Verifying ssh-rsa signature");
         return RSASHA1Verify.verifySignature(this.kxs.H, rs, rpk, "SHA-1");
      } else if (this.kxs.np.server_host_key_algo.equals("ssh-dss")) {
         DSASignature ds = DSASHA1Verify.decodeSSHDSASignature(sig);
         DSAPublicKey dpk = DSASHA1Verify.decodeSSHDSAPublicKey(hostkey);
         log.debug("Verifying ssh-dss signature");
         return DSASHA1Verify.verifySignature(this.kxs.H, ds, dpk);
      } else if (this.kxs.np.server_host_key_algo.equals("rsa-sha2-256")) {
         rs = RSASHA1Verify.decodeSSHRSASignature(sig);
         rpk = RSASHA1Verify.decodeSSHRSAPublicKey(hostkey);
         return RSASHA1Verify.verifySignature(this.kxs.H, rs, rpk, "SHA-256");
      } else if (this.kxs.np.server_host_key_algo.equals("rsa-sha2-512")) {
         rs = RSASHA1Verify.decodeSSHRSASignature(sig);
         rpk = RSASHA1Verify.decodeSSHRSAPublicKey(hostkey);
         return RSASHA1Verify.verifySignature(this.kxs.H, rs, rpk, "SHA-512");
      } else {
         throw new IOException("Unknown server host key algorithm '" + this.kxs.np.server_host_key_algo + "'");
      }
   }

   public synchronized void handleMessage(byte[] msg, int msglen) throws IOException {
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
               this.kxs.dhgexParameters = this.nextKEXdhgexParameters;
               kip = new PacketKexInit(this.nextKEXcryptoWishList, this.rnd);
               this.kxs.localKEX = kip;
               this.tm.sendKexMessage(kip.getPayload());
            }

            kip = new PacketKexInit(msg, 0, msglen);
            this.kxs.remoteKEX = kip;
            this.kxs.np = this.mergeKexParameters(this.kxs.localKEX.getKexParameters(), this.kxs.remoteKEX.getKexParameters());
            if (this.kxs.np == null) {
               throw new IOException("Cannot negotiate, proposals do not match.");
            } else {
               if (this.kxs.remoteKEX.isFirst_kex_packet_follows() && !this.kxs.np.guessOK) {
                  this.ignore_next_kex_packet = true;
               }

               if (this.kxs.np.kex_algo.equals("diffie-hellman-group-exchange-sha1")) {
                  if (this.kxs.dhgexParameters.getMin_group_len() == 0) {
                     PacketKexDhGexRequestOld dhgexreq = new PacketKexDhGexRequestOld(this.kxs.dhgexParameters);
                     this.tm.sendKexMessage(dhgexreq.getPayload());
                  } else {
                     PacketKexDhGexRequest dhgexreq = new PacketKexDhGexRequest(this.kxs.dhgexParameters);
                     this.tm.sendKexMessage(dhgexreq.getPayload());
                  }

                  this.kxs.state = 1;
               } else if (this.kxs.np.kex_algo.equals("diffie-hellman-group1-sha1")) {
                  this.sendKexDhInit("SHA1", 1);
               } else if (this.kxs.np.kex_algo.equals("diffie-hellman-group14-sha1")) {
                  this.sendKexDhInit("SHA1", 14);
               } else if (this.kxs.np.kex_algo.equals("diffie-hellman-group14-sha256")) {
                  this.sendKexDhInit("SHA2-256", 14);
               } else if (this.kxs.np.kex_algo.equals("diffie-hellman-group16-sha512")) {
                  this.sendKexDhInit("SHA2-512", 16);
               } else if (this.kxs.np.kex_algo.equals("diffie-hellman-group18-sha512")) {
                  this.sendKexDhInit("SHA2-512", 18);
               } else {
                  throw new IllegalStateException("Unkown KEX method!");
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
               cbc = BlockCipherFactory.createCipher(this.kxs.np.enc_algo_server_to_client, false, this.km.enc_key_server_to_client, this.km.initial_iv_server_to_client);
               mac = new MAC(this.kxs.np.mac_algo_server_to_client, this.km.integrity_key_server_to_client);
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
         boolean res;
         if (this.kxs.np.kex_algo.equals("diffie-hellman-group-exchange-sha1")) {
            if (this.kxs.state == 1) {
               PacketKexDhGexGroup dhgexgrp = new PacketKexDhGexGroup(msg, 0, msglen);
               this.kxs.dhgx = new DhGroupExchange(dhgexgrp.getP(), dhgexgrp.getG());
               this.kxs.dhgx.init(this.rnd);
               PacketKexDhGexInit dhgexinit = new PacketKexDhGexInit(this.kxs.dhgx.getE());
               this.tm.sendKexMessage(dhgexinit.getPayload());
               this.kxs.state = 2;
            } else if (this.kxs.state == 2) {
               PacketKexDhGexReply dhgexrpl = new PacketKexDhGexReply(msg, 0, msglen);
               this.kxs.remote_hostkey = dhgexrpl.getHostKey();
               if (this.verifier != null) {
                  res = false;

                  try {
                     res = this.verifier.verifyServerHostKey(this.hostname, this.port, this.kxs.np.server_host_key_algo, this.kxs.remote_hostkey);
                  } catch (Exception var13) {
                     throw new IOException("The server hostkey was not accepted by the verifier callback.", var13);
                  }

                  if (!res) {
                     throw new IOException("The server hostkey was not accepted by the verifier callback");
                  }
               }

               this.kxs.dhgx.setF(dhgexrpl.getF());

               try {
                  this.kxs.H = this.kxs.dhgx.calculateH(this.csh.getClientString(), this.csh.getServerString(), this.kxs.localKEX.getPayload(), this.kxs.remoteKEX.getPayload(), dhgexrpl.getHostKey(), this.kxs.dhgexParameters);
               } catch (IllegalArgumentException var12) {
                  throw new IOException("KEX error.", var12);
               }

               res = false;

               try {
                  res = this.verifySignature(dhgexrpl.getSignature(), this.kxs.remote_hostkey);
               } catch (IOException | NoSuchAlgorithmException var11) {
                  var11.printStackTrace();
               }

               if (!res) {
                  throw new IOException("Hostkey signature sent by remote is wrong!");
               } else {
                  this.kxs.K = this.kxs.dhgx.getK();
                  this.finishKex(true);
                  this.kxs.state = -1;
               }
            } else {
               throw new IllegalStateException("Illegal State in KEX Exchange!");
            }
         } else if ((this.kxs.np.kex_algo.equals("diffie-hellman-group1-sha1") || this.kxs.np.kex_algo.equals("diffie-hellman-group14-sha1") || this.kxs.np.kex_algo.equals("diffie-hellman-group14-sha256") || this.kxs.np.kex_algo.equals("diffie-hellman-group16-sha512") || this.kxs.np.kex_algo.equals("diffie-hellman-group18-sha512")) && this.kxs.state == 1) {
            PacketKexDHReply dhr = new PacketKexDHReply(msg, 0, msglen);
            this.kxs.remote_hostkey = dhr.getHostKey();
            if (this.verifier != null) {
               res = false;

               try {
                  res = this.verifier.verifyServerHostKey(this.hostname, this.port, this.kxs.np.server_host_key_algo, this.kxs.remote_hostkey);
               } catch (Exception var16) {
                  throw new IOException("The server hostkey was not accepted by the verifier callback.", var16);
               }

               if (!res) {
                  throw new IOException("The server hostkey was not accepted by the verifier callback");
               }
            }

            this.kxs.dhx.setF(dhr.getF());

            try {
               this.kxs.H = this.kxs.dhx.calculateH(this.csh.getClientString(), this.csh.getServerString(), this.kxs.localKEX.getPayload(), this.kxs.remoteKEX.getPayload(), dhr.getHostKey());
            } catch (IllegalArgumentException var15) {
               throw new IOException("KEX error.", var15);
            }

            res = false;

            try {
               res = this.verifySignature(dhr.getSignature(), this.kxs.remote_hostkey);
            } catch (IOException | NoSuchAlgorithmException var14) {
               var14.printStackTrace();
            }

            if (!res) {
               throw new IOException("Hostkey signature sent by remote is wrong!");
            } else {
               this.kxs.K = this.kxs.dhx.getK();
               this.finishKex(true);
               this.kxs.state = -1;
            }
         } else {
            throw new IllegalStateException("Unkown KEX method! (" + this.kxs.np.kex_algo + ")");
         }
      } else {
         throw new IOException("Unexpected Kex submessage!");
      }
   }

   private void sendKexDhInit(String hash, int group) throws IOException {
      this.kxs.dhx = new DhExchange(hash);
      this.kxs.dhx.clientInit(group, this.rnd);
      PacketKexDHInit kp = new PacketKexDHInit(this.kxs.dhx.getE());
      this.tm.sendKexMessage(kp.getPayload());
      this.kxs.state = 1;
   }
}
