package ch.ethz.ssh2.jsch;

import java.util.Arrays;

public abstract class KeyPairEdDSA extends KeyPair {
   private byte[] pub_array;
   private byte[] prv_array;

   KeyPairEdDSA(byte[] pub_array, byte[] prv_array) {
      this.pub_array = pub_array;
      this.prv_array = prv_array;
   }

   abstract String getSshName();

   abstract String getJceName();

   void generate(int key_size) throws Exception {
      try {
         Class<? extends KeyPairGenEdDSA> c = Class.forName(Util.getConfig("keypairgen.eddsa")).asSubclass(KeyPairGenEdDSA.class);
         KeyPairGenEdDSA keypairgen = (KeyPairGenEdDSA)c.getDeclaredConstructor().newInstance();
         keypairgen.init(this.getJceName(), this.getKeySize());
         this.pub_array = keypairgen.getPub();
         this.prv_array = keypairgen.getPrv();
         keypairgen = null;
      } catch (NoClassDefFoundError | Exception var4) {
         throw new Exception(var4.toString(), var4);
      }
   }

   byte[] getBegin() {
      throw new UnsupportedOperationException();
   }

   byte[] getEnd() {
      throw new UnsupportedOperationException();
   }

   byte[] getPrivateKey() {
      throw new UnsupportedOperationException();
   }

   boolean parse(byte[] plain) {
      Buffer buf;
      if (this.vendor != 2 && this.vendor != 5) {
         if (this.vendor == 4) {
            try {
               buf = new Buffer(plain);
               int checkInt1 = buf.getInt();
               int checkInt2 = buf.getInt();
               if (checkInt1 != checkInt2) {
                  throw new Exception("check failed");
               } else {
                  String keyType = Util.byte2str(buf.getString());
                  this.pub_array = buf.getString();
                  byte[] tmp = buf.getString();
                  this.prv_array = Arrays.copyOf(tmp, this.getKeySize());
                  this.publicKeyComment = Util.byte2str(buf.getString());
                  return true;
               }
            } catch (Exception var7) {
               var7.printStackTrace();
               return false;
            }
         } else if (this.vendor == 3) {
            try {
               Class<? extends KeyPairGenEdDSA> c = Class.forName(Util.getConfig("keypairgen_fromprivate.eddsa")).asSubclass(KeyPairGenEdDSA.class);
               KeyPairGenEdDSA keypairgen = (KeyPairGenEdDSA)c.getDeclaredConstructor().newInstance();
               keypairgen.init(this.getJceName(), plain);
               this.pub_array = keypairgen.getPub();
               this.prv_array = keypairgen.getPrv();
               return true;
            } catch (NoClassDefFoundError | Exception var8) {
               var8.printStackTrace();
               return false;
            }
         } else {
            return false;
         }
      } else {
         buf = new Buffer(plain);
         buf.skip(plain.length);

         try {
            byte[][] tmp = buf.getBytes(1, "");
            this.prv_array = tmp[0];
            return true;
         } catch (Exception var9) {
            var9.printStackTrace();
            return false;
         }
      }
   }

   public byte[] getPublicKeyBlob() {
      byte[] foo = super.getPublicKeyBlob();
      if (foo != null) {
         return foo;
      } else if (this.pub_array == null) {
         return null;
      } else {
         byte[][] tmp = new byte[][]{this.getKeyTypeName(), this.pub_array};
         return Buffer.fromBytes(tmp).buffer;
      }
   }

   byte[] getKeyTypeName() {
      return Util.str2byte(this.getSshName());
   }

   public byte[] getSignature(byte[] data) {
      return this.getSignature(data, this.getSshName());
   }

   public byte[] getSignature(byte[] data, String alg) {
      try {
         Class<? extends SignatureEdDSA> c = Class.forName(Util.getConfig(alg)).asSubclass(SignatureEdDSA.class);
         SignatureEdDSA eddsa = (SignatureEdDSA)c.getDeclaredConstructor().newInstance();
         eddsa.init();
         eddsa.setPrvKey(this.prv_array);
         eddsa.update(data);
         byte[] sig = eddsa.sign();
         byte[][] tmp = new byte[][]{Util.str2byte(alg), sig};
         return Buffer.fromBytes(tmp).buffer;
      } catch (NoClassDefFoundError | Exception var7) {
         var7.printStackTrace();
         return null;
      }
   }

   public Signature getVerifier() {
      return this.getVerifier(this.getSshName());
   }

   public Signature getVerifier(String alg) {
      try {
         Class<? extends SignatureEdDSA> c = Class.forName(Util.getConfig(alg)).asSubclass(SignatureEdDSA.class);
         SignatureEdDSA eddsa = (SignatureEdDSA)c.getDeclaredConstructor().newInstance();
         eddsa.init();
         if (this.pub_array == null && this.getPublicKeyBlob() != null) {
            Buffer buf = new Buffer(this.getPublicKeyBlob());
            buf.getString();
            this.pub_array = buf.getString();
         }

         eddsa.setPubKey(this.pub_array);
         return eddsa;
      } catch (NoClassDefFoundError | Exception var5) {
         var5.printStackTrace();
         return null;
      }
   }

   public byte[] forSSHAgent() throws Exception {
      if (this.isEncrypted()) {
         throw new Exception("key is encrypted.");
      } else {
         Buffer buf = new Buffer();
         buf.putString(this.getKeyTypeName());
         buf.putString(this.pub_array);
         byte[] tmp = new byte[this.prv_array.length + this.pub_array.length];
         System.arraycopy(this.prv_array, 0, tmp, 0, this.prv_array.length);
         System.arraycopy(this.pub_array, 0, tmp, this.prv_array.length, this.pub_array.length);
         buf.putString(tmp);
         buf.putString(Util.str2byte(this.publicKeyComment));
         byte[] result = new byte[buf.getLength()];
         buf.getByte(result, 0, result.length);
         return result;
      }
   }

   public void dispose() {
      super.dispose();
      Util.bzero(this.prv_array);
   }
}
