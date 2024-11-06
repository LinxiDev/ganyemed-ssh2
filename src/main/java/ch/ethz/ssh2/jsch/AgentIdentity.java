package ch.ethz.ssh2.jsch;

class AgentIdentity implements Identity {
   private AgentProxy agent;
   private byte[] blob;
   private String comment;
   private String algname;

   AgentIdentity(AgentProxy agent, byte[] blob, String comment) {
      this.agent = agent;
      this.blob = blob;
      this.comment = comment;
      this.algname = Util.byte2str((new Buffer(blob)).getString());
   }

   public boolean setPassphrase(byte[] passphrase) throws JSchException {
      return true;
   }

   public byte[] getPublicKeyBlob() {
      return this.blob;
   }

   public byte[] getSignature(byte[] data) {
      return this.agent.sign(this.blob, data, (String)null);
   }

   public byte[] getSignature(byte[] data, String alg) {
      return this.agent.sign(this.blob, data, alg);
   }

   public String getAlgName() {
      return this.algname;
   }

   public String getName() {
      return this.comment;
   }

   public boolean isEncrypted() {
      return false;
   }

   public void clear() {
   }
}
