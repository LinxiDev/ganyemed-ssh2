package ch.ethz.ssh2.auth;

import ch.ethz.ssh2.InteractiveCallback;
import ch.ethz.ssh2.crypto.PEMDecoder;
import ch.ethz.ssh2.packets.PacketServiceRequest;
import ch.ethz.ssh2.packets.PacketUserauthBanner;
import ch.ethz.ssh2.packets.PacketUserauthFailure;
import ch.ethz.ssh2.packets.PacketUserauthInfoRequest;
import ch.ethz.ssh2.packets.PacketUserauthInfoResponse;
import ch.ethz.ssh2.packets.PacketUserauthRequestInteractive;
import ch.ethz.ssh2.packets.PacketUserauthRequestNone;
import ch.ethz.ssh2.packets.PacketUserauthRequestPassword;
import ch.ethz.ssh2.packets.PacketUserauthRequestPublicKey;
import ch.ethz.ssh2.packets.TypesWriter;
import ch.ethz.ssh2.signature.DSAPrivateKey;
import ch.ethz.ssh2.signature.DSASHA1Verify;
import ch.ethz.ssh2.signature.DSASignature;
import ch.ethz.ssh2.signature.RSAPrivateKey;
import ch.ethz.ssh2.signature.RSASHA1Verify;
import ch.ethz.ssh2.signature.RSASignature;
import ch.ethz.ssh2.transport.ClientTransportManager;
import ch.ethz.ssh2.transport.MessageHandler;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class AuthenticationManager implements MessageHandler {
   private ClientTransportManager tm;

   private final List<byte[]> packets = (List)new ArrayList<>();

   private boolean connectionClosed = false;

   private String banner;

   private String[] remainingMethods = new String[0];

   private boolean isPartialSuccess = false;

   private boolean authenticated = false;

   private boolean initDone = false;

   public AuthenticationManager(ClientTransportManager tm) {
      this.tm = tm;
   }

   boolean methodPossible(String methName) {
      if (this.remainingMethods == null)
         return false;
      byte b;
      int i;
      String[] arrayOfString;
      for (i = (arrayOfString = this.remainingMethods).length, b = 0; b < i; ) {
         String remainingMethod = arrayOfString[b];
         if (remainingMethod.compareTo(methName) == 0)
            return true;
         b++;
      }
      return false;
   }

   byte[] deQueue() throws IOException {
      synchronized (this.packets) {
         while (this.packets.size() == 0) {
            if (this.connectionClosed)
               throw new IOException("The connection is closed.", this.tm
                       .getReasonClosedCause());
            try {
               this.packets.wait();
            } catch (InterruptedException e) {
               throw new InterruptedIOException(e.getMessage());
            }
         }
         byte[] res = this.packets.get(0);
         this.packets.remove(0);
         return res;
      }
   }

   byte[] getNextMessage() throws IOException {
      while (true) {
         byte[] msg = deQueue();
         if (msg[0] != 53)
            return msg;
         PacketUserauthBanner sb = new PacketUserauthBanner(msg, 0, msg.length);
         this.banner = sb.getBanner();
      }
   }

   public String[] getRemainingMethods(String user) throws IOException {
      initialize(user);
      return this.remainingMethods;
   }

   public String getBanner() {
      return this.banner;
   }

   public boolean getPartialSuccess() {
      return this.isPartialSuccess;
   }

   private boolean initialize(String user) throws IOException {
      if (!this.initDone) {
         this.tm.registerMessageHandler(this, 0, 255);
         PacketServiceRequest sr = new PacketServiceRequest("ssh-userauth");
         this.tm.sendMessage(sr.getPayload());
         byte[] msg = getNextMessage();
         PacketUserauthRequestNone urn = new PacketUserauthRequestNone("ssh-connection", user);
         this.tm.sendMessage(urn.getPayload());
         msg = getNextMessage();
         this.initDone = true;
         if (msg[0] == 52) {
            this.authenticated = true;
            this.tm.removeMessageHandler(this, 0, 255);
            return true;
         }
         if (msg[0] == 51) {
            PacketUserauthFailure puf = new PacketUserauthFailure(msg, 0, msg.length);
            this.remainingMethods = puf.getAuthThatCanContinue();
            this.isPartialSuccess = puf.isPartialSuccess();
            return false;
         }
         throw new IOException("Unexpected SSH message (type " + msg[0] + ")");
      }
      return this.authenticated;
   }

   public boolean authenticatePublicKey(String user, AgentProxy proxy) throws IOException {
      initialize(user);
      for (AgentIdentity identity : proxy.getIdentities()) {
         boolean success = authenticatePublicKey(user, identity);
         if (success)
            return true;
      }
      return false;
   }

   boolean authenticatePublicKey(String user, AgentIdentity identity) throws IOException {
      if (!methodPossible("publickey"))
         throw new IOException("Authentication method publickey not supported by the server at this stage.");
      byte[] pubKeyBlob = identity.getPublicKeyBlob();
      if (pubKeyBlob == null)
         return false;
      TypesWriter tw = new TypesWriter();
      byte[] H = this.tm.getSessionIdentifier();
      tw.writeString(H, 0, H.length);
      tw.writeByte(50);
      tw.writeString(user);
      tw.writeString("ssh-connection");
      tw.writeString("publickey");
      tw.writeBoolean(true);
      tw.writeString(identity.getAlgName());
      tw.writeString(pubKeyBlob, 0, pubKeyBlob.length);
      byte[] msg = tw.getBytes();
      byte[] response = identity.sign(msg);
      PacketUserauthRequestPublicKey ua = new PacketUserauthRequestPublicKey(
              "ssh-connection", user, identity.getAlgName(), pubKeyBlob, response);
      this.tm.sendMessage(ua.getPayload());
      byte[] ar = getNextMessage();
      if (ar[0] == 52) {
         this.authenticated = true;
         this.tm.removeMessageHandler(this, 0, 255);
         return true;
      }
      if (ar[0] == 51) {
         PacketUserauthFailure puf = new PacketUserauthFailure(ar, 0, ar.length);
         this.remainingMethods = puf.getAuthThatCanContinue();
         this.isPartialSuccess = puf.isPartialSuccess();
         return false;
      }
      throw new IOException("Unexpected SSH message (type " + ar[0] + ")");
   }

   public boolean authenticatePublicKey(String user, char[] PEMPrivateKey, String password, SecureRandom rnd) throws IOException {
      try {
         initialize(user);
         if (!methodPossible("publickey"))
            throw new IOException("Authentication method publickey not supported by the server at this stage.");
         Object key = PEMDecoder.decode(PEMPrivateKey, password);
         if (key instanceof DSAPrivateKey) {
            DSAPrivateKey pk = (DSAPrivateKey)key;
            byte[] pk_enc = DSASHA1Verify.encodeSSHDSAPublicKey(pk.getPublicKey());
            TypesWriter tw = new TypesWriter();
            byte[] H = this.tm.getSessionIdentifier();
            tw.writeString(H, 0, H.length);
            tw.writeByte(50);
            tw.writeString(user);
            tw.writeString("ssh-connection");
            tw.writeString("publickey");
            tw.writeBoolean(true);
            tw.writeString("ssh-dss");
            tw.writeString(pk_enc, 0, pk_enc.length);
            byte[] msg = tw.getBytes();
            DSASignature ds = DSASHA1Verify.generateSignature(msg, pk, rnd);
            byte[] ds_enc = DSASHA1Verify.encodeSSHDSASignature(ds);
            PacketUserauthRequestPublicKey ua = new PacketUserauthRequestPublicKey("ssh-connection", user,
                    "ssh-dss", pk_enc, ds_enc);
            this.tm.sendMessage(ua.getPayload());
         } else if (key instanceof RSAPrivateKey) {
            RSAPrivateKey pk = (RSAPrivateKey)key;
            byte[] pk_enc = RSASHA1Verify.encodeSSHRSAPublicKey(pk.getPublicKey());
            TypesWriter tw = new TypesWriter();
            byte[] H = this.tm.getSessionIdentifier();
            tw.writeString(H, 0, H.length);
            tw.writeByte(50);
            tw.writeString(user);
            tw.writeString("ssh-connection");
            tw.writeString("publickey");
            tw.writeBoolean(true);
            tw.writeString("ssh-rsa");
            tw.writeString(pk_enc, 0, pk_enc.length);
            byte[] msg = tw.getBytes();
            RSASignature ds = RSASHA1Verify.generateSignature(msg, pk);
            byte[] rsa_sig_enc = RSASHA1Verify.encodeSSHRSASignature(ds);
            PacketUserauthRequestPublicKey ua = new PacketUserauthRequestPublicKey("ssh-connection", user,
                    "ssh-rsa", pk_enc, rsa_sig_enc);
            this.tm.sendMessage(ua.getPayload());
         } else {
            throw new IOException("Unknown private key type returned by the PEM decoder.");
         }
         byte[] ar = getNextMessage();
         if (ar[0] == 52) {
            this.authenticated = true;
            this.tm.removeMessageHandler(this, 0, 255);
            return true;
         }
         if (ar[0] == 51) {
            PacketUserauthFailure puf = new PacketUserauthFailure(ar, 0, ar.length);
            this.remainingMethods = puf.getAuthThatCanContinue();
            this.isPartialSuccess = puf.isPartialSuccess();
            return false;
         }
         throw new IOException("Unexpected SSH message (type " + ar[0] + ")");
      } catch (IOException e) {
         this.tm.close(e);
         throw new IOException("Publickey authentication failed.", e);
      }
   }

   public boolean authenticateNone(String user) throws IOException {
      try {
         initialize(user);
         return this.authenticated;
      } catch (IOException e) {
         this.tm.close(e);
         throw new IOException("None authentication failed.", e);
      }
   }

   public boolean authenticatePassword(String user, String pass) throws IOException {
      try {
         initialize(user);
         if (!methodPossible("password"))
            throw new IOException("Authentication method password not supported by the server at this stage.");
         PacketUserauthRequestPassword ua = new PacketUserauthRequestPassword("ssh-connection", user, pass);
         this.tm.sendMessage(ua.getPayload());
         byte[] ar = getNextMessage();
         if (ar[0] == 52) {
            this.authenticated = true;
            this.tm.removeMessageHandler(this, 0, 255);
            return true;
         }
         if (ar[0] == 51) {
            PacketUserauthFailure puf = new PacketUserauthFailure(ar, 0, ar.length);
            this.remainingMethods = puf.getAuthThatCanContinue();
            this.isPartialSuccess = puf.isPartialSuccess();
            return false;
         }
         throw new IOException("Unexpected SSH message (type " + ar[0] + ")");
      } catch (IOException e) {
         this.tm.close(e);
         throw new IOException("Password authentication failed.", e);
      }
   }

   public boolean authenticateInteractive(String user, String[] submethods, InteractiveCallback cb) throws IOException {
      try {
         byte[] ar;
         initialize(user);
         if (!methodPossible("keyboard-interactive"))
            throw new IOException(
                    "Authentication method keyboard-interactive not supported by the server at this stage.");
         if (submethods == null)
            submethods = new String[0];
         PacketUserauthRequestInteractive ua = new PacketUserauthRequestInteractive("ssh-connection", user,
                 submethods);
         this.tm.sendMessage(ua.getPayload());
         while (true) {
            ar = getNextMessage();
            if (ar[0] == 52) {
               this.authenticated = true;
               this.tm.removeMessageHandler(this, 0, 255);
               return true;
            }
            if (ar[0] == 51) {
               PacketUserauthFailure puf = new PacketUserauthFailure(ar, 0, ar.length);
               this.remainingMethods = puf.getAuthThatCanContinue();
               this.isPartialSuccess = puf.isPartialSuccess();
               return false;
            }
            if (ar[0] == 60) {
               String[] responses;
               PacketUserauthInfoRequest pui = new PacketUserauthInfoRequest(ar, 0, ar.length);
               try {
                  responses = cb.replyToChallenge(pui.getName(), pui.getInstruction(), pui.getNumPrompts(), pui
                          .getPrompt(), pui.getEcho());
               } catch (Exception e) {
                  throw new IOException("Exception in callback.", e);
               }
               if (responses == null)
                  throw new IOException("Your callback may not return NULL!");
               PacketUserauthInfoResponse puir = new PacketUserauthInfoResponse(responses);
               this.tm.sendMessage(puir.getPayload());
               continue;
            }
            break;
         }
         throw new IOException("Unexpected SSH message (type " + ar[0] + ")");
      } catch (IOException e) {
         this.tm.close(e);
         throw new IOException("Keyboard-interactive authentication failed.", e);
      }
   }

   public void handleMessage(byte[] msg, int msglen) throws IOException {
      synchronized (this.packets) {
         if (msg == null) {
            this.connectionClosed = true;
         } else {
            byte[] tmp = new byte[msglen];
            System.arraycopy(msg, 0, tmp, 0, msglen);
            this.packets.add(tmp);
         }
         this.packets.notifyAll();
         if (this.packets.size() > 5) {
            this.connectionClosed = true;
            throw new IOException("Error, peer is flooding us with authentication packets.");
         }
      }
   }
}
