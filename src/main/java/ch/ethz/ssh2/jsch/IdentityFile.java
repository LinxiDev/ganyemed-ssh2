package ch.ethz.ssh2.jsch;

class IdentityFile implements Identity {
   private KeyPair kpair;
   private String identity;

   static IdentityFile newInstance(String prvfile, String pubfile) throws Exception {
      KeyPair kpair = KeyPair.load(prvfile, pubfile);
      return new IdentityFile(prvfile, kpair);
   }

   static IdentityFile newInstance(String name, byte[] prvkey, byte[] pubkey) throws Exception {
      KeyPair kpair = KeyPair.load(prvkey, pubkey);
      return new IdentityFile(name, kpair);
   }

   private IdentityFile(String name, KeyPair kpair) {
      this.identity = name;
      this.kpair = kpair;
   }

   public boolean setPassphrase(byte[] passphrase) throws JSchException {
      return this.kpair.decrypt(passphrase);
   }

   public byte[] getPublicKeyBlob() {
      return this.kpair.getPublicKeyBlob();
   }

   public byte[] getSignature(byte[] data) {
      return this.kpair.getSignature(data);
   }

   public byte[] getSignature(byte[] data, String alg) {
      return this.kpair.getSignature(data, alg);
   }

   public String getAlgName() {
      return this.kpair.getKeyTypeString();
   }

   public String getName() {
      return this.identity;
   }

   public boolean isEncrypted() {
      return this.kpair.isEncrypted();
   }

   public void clear() {
      this.kpair.dispose();
      this.kpair = null;
   }

   public KeyPair getKeyPair() {
      return this.kpair;
   }
}
