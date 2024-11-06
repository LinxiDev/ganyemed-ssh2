package ch.ethz.ssh2.jsch;

import java.util.Vector;

class AgentProxy {
   private static final byte SSH_AGENTC_REQUEST_RSA_IDENTITIES = 1;
   private static final byte SSH_AGENT_RSA_IDENTITIES_ANSWER = 2;
   private static final byte SSH_AGENTC_RSA_CHALLENGE = 3;
   private static final byte SSH_AGENT_RSA_RESPONSE = 4;
   private static final byte SSH_AGENT_FAILURE = 5;
   private static final byte SSH_AGENT_SUCCESS = 6;
   private static final byte SSH_AGENTC_ADD_RSA_IDENTITY = 7;
   private static final byte SSH_AGENTC_REMOVE_RSA_IDENTITY = 8;
   private static final byte SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES = 9;
   private static final byte SSH2_AGENTC_REQUEST_IDENTITIES = 11;
   private static final byte SSH2_AGENT_IDENTITIES_ANSWER = 12;
   private static final byte SSH2_AGENTC_SIGN_REQUEST = 13;
   private static final byte SSH2_AGENT_SIGN_RESPONSE = 14;
   private static final byte SSH2_AGENTC_ADD_IDENTITY = 17;
   private static final byte SSH2_AGENTC_REMOVE_IDENTITY = 18;
   private static final byte SSH2_AGENTC_REMOVE_ALL_IDENTITIES = 19;
   private static final byte SSH_AGENTC_ADD_SMARTCARD_KEY = 20;
   private static final byte SSH_AGENTC_REMOVE_SMARTCARD_KEY = 21;
   private static final byte SSH_AGENTC_LOCK = 22;
   private static final byte SSH_AGENTC_UNLOCK = 23;
   private static final byte SSH_AGENTC_ADD_RSA_ID_CONSTRAINED = 24;
   private static final byte SSH2_AGENTC_ADD_ID_CONSTRAINED = 25;
   private static final byte SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED = 26;
   private static final byte SSH_AGENT_CONSTRAIN_LIFETIME = 1;
   private static final byte SSH_AGENT_CONSTRAIN_CONFIRM = 2;
   private static final byte SSH2_AGENT_FAILURE = 30;
   private static final byte SSH_COM_AGENT2_FAILURE = 102;
   private static final int SSH_AGENT_RSA_SHA2_256 = 2;
   private static final int SSH_AGENT_RSA_SHA2_512 = 4;
   private static final int MAX_AGENT_IDENTITIES = 2048;
   private final byte[] buf = new byte[1024];
   private final Buffer buffer;
   private AgentConnector connector;

   AgentProxy(AgentConnector connector) {
      this.buffer = new Buffer(this.buf);
      this.connector = connector;
   }

   synchronized Vector<Identity> getIdentities() {
      Vector<Identity> identities = new Vector();
      int required_size = 5;
      this.buffer.reset();
      this.buffer.checkFreeSize(required_size);
      this.buffer.putInt(required_size - 4);
      this.buffer.putByte((byte)11);

      try {
         this.connector.query(this.buffer);
      } catch (AgentProxyException var8) {
         this.buffer.rewind();
         this.buffer.putByte((byte)5);
         return identities;
      }

      int rcode = this.buffer.getByte();
      if (rcode != 12) {
         return identities;
      } else {
         int count = this.buffer.getInt();
         if (count > 0 && count <= 2048) {
            for(int i = 0; i < count; ++i) {
               byte[] blob = this.buffer.getString();
               String comment = Util.byte2str(this.buffer.getString());
               identities.add(new AgentIdentity(this, blob, comment));
            }

            return identities;
         } else {
            return identities;
         }
      }
   }

   synchronized byte[] sign(byte[] blob, byte[] data, String alg) {
      int flags = 0;
      if (alg != null) {
         if (alg.equals("rsa-sha2-256")) {
            flags = 2;
         } else if (alg.equals("rsa-sha2-512")) {
            flags = 4;
         }
      }

      int required_size = 17 + blob.length + data.length;
      this.buffer.reset();
      this.buffer.checkFreeSize(required_size);
      this.buffer.putInt(required_size - 4);
      this.buffer.putByte((byte)13);
      this.buffer.putString(blob);
      this.buffer.putString(data);
      this.buffer.putInt(flags);

      try {
         this.connector.query(this.buffer);
      } catch (AgentProxyException var7) {
         this.buffer.rewind();
         this.buffer.putByte((byte)5);
      }

      int rcode = this.buffer.getByte();
      return rcode != 14 ? null : this.buffer.getString();
   }

   synchronized boolean removeIdentity(byte[] blob) {
      int required_size = 9 + blob.length;
      this.buffer.reset();
      this.buffer.checkFreeSize(required_size);
      this.buffer.putInt(required_size - 4);
      this.buffer.putByte((byte)18);
      this.buffer.putString(blob);

      try {
         this.connector.query(this.buffer);
      } catch (AgentProxyException var4) {
         this.buffer.rewind();
         this.buffer.putByte((byte)5);
      }

      int rcode = this.buffer.getByte();
      return rcode == 6;
   }

   synchronized void removeAllIdentities() {
      int required_size = 5;
      this.buffer.reset();
      this.buffer.checkFreeSize(required_size);
      this.buffer.putInt(required_size - 4);
      this.buffer.putByte((byte)19);

      try {
         this.connector.query(this.buffer);
      } catch (AgentProxyException var3) {
         this.buffer.rewind();
         this.buffer.putByte((byte)5);
      }

   }

   synchronized boolean addIdentity(byte[] identity) {
      int required_size = 5 + identity.length;
      this.buffer.reset();
      this.buffer.checkFreeSize(required_size);
      this.buffer.putInt(required_size - 4);
      this.buffer.putByte((byte)17);
      this.buffer.putByte(identity);

      try {
         this.connector.query(this.buffer);
      } catch (AgentProxyException var4) {
         this.buffer.rewind();
         this.buffer.putByte((byte)5);
      }

      int rcode = this.buffer.getByte();
      return rcode == 6;
   }

   synchronized boolean isRunning() {
      int required_size = 5;
      this.buffer.reset();
      this.buffer.checkFreeSize(required_size);
      this.buffer.putInt(required_size - 4);
      this.buffer.putByte((byte)11);

      try {
         this.connector.query(this.buffer);
      } catch (AgentProxyException var3) {
         return false;
      }

      int rcode = this.buffer.getByte();
      return rcode == 12;
   }

   synchronized AgentConnector getConnector() {
      return this.connector;
   }
}
