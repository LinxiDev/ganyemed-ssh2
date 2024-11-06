package ch.ethz.ssh2.jsch;

import java.math.BigInteger;

class KeyPairRSA extends KeyPair {
   private byte[] n_array;

   private byte[] pub_array;

   private byte[] prv_array;

   private byte[] p_array;

   private byte[] q_array;

   private byte[] ep_array;

   private byte[] eq_array;

   private byte[] c_array;

   private int key_size = 1024;

   KeyPairRSA() {
      this((byte[])null, (byte[])null, (byte[])null);
   }

   KeyPairRSA(byte[] n_array, byte[] pub_array, byte[] prv_array) {
      this.n_array = n_array;
      this.pub_array = pub_array;
      this.prv_array = prv_array;
      if (n_array != null)
         this.key_size = (new BigInteger(n_array)).bitLength();
   }

   void generate(int key_size) throws Exception {
      this.key_size = key_size;
      try {
         Class<? extends KeyPairGenRSA> c =
                 Class.forName(Util.getConfig("keypairgen.rsa")).asSubclass(KeyPairGenRSA.class);
         KeyPairGenRSA keypairgen = c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
         keypairgen.init(key_size);
         this.pub_array = keypairgen.getE();
         this.prv_array = keypairgen.getD();
         this.n_array = keypairgen.getN();
         this.p_array = keypairgen.getP();
         this.q_array = keypairgen.getQ();
         this.ep_array = keypairgen.getEP();
         this.eq_array = keypairgen.getEQ();
         this.c_array = keypairgen.getC();
         keypairgen = null;
      } catch (Exception e) {
         throw new Exception(e.toString(), e);
      }
   }

   private static final byte[] begin = Util.str2byte("-----BEGIN RSA PRIVATE KEY-----");

   private static final byte[] end = Util.str2byte("-----END RSA PRIVATE KEY-----");

   byte[] getBegin() {
      return begin;
   }

   byte[] getEnd() {
      return end;
   }

   byte[] getPrivateKey() {
      int content = 1 + countLength(1) + 1 +
              1 + countLength(this.n_array.length) + this.n_array.length +
              1 + countLength(this.pub_array.length) + this.pub_array.length +
              1 + countLength(this.prv_array.length) + this.prv_array.length +
              1 + countLength(this.p_array.length) + this.p_array.length +
              1 + countLength(this.q_array.length) + this.q_array.length +
              1 + countLength(this.ep_array.length) + this.ep_array.length +
              1 + countLength(this.eq_array.length) + this.eq_array.length +
              1 + countLength(this.c_array.length) + this.c_array.length;
      int total = 1 + countLength(content) + content;
      byte[] plain = new byte[total];
      int index = 0;
      index = writeSEQUENCE(plain, index, content);
      index = writeINTEGER(plain, index, new byte[1]);
      index = writeINTEGER(plain, index, this.n_array);
      index = writeINTEGER(plain, index, this.pub_array);
      index = writeINTEGER(plain, index, this.prv_array);
      index = writeINTEGER(plain, index, this.p_array);
      index = writeINTEGER(plain, index, this.q_array);
      index = writeINTEGER(plain, index, this.ep_array);
      index = writeINTEGER(plain, index, this.eq_array);
      index = writeINTEGER(plain, index, this.c_array);
      return plain;
   }

   boolean parse(byte[] plain) {
      try {
         int index = 0;
         int length = 0;
         if (this.vendor == 2 || this.vendor == 5) {
            Buffer buf = new Buffer(plain);
            buf.skip(plain.length);
            try {
               byte[][] tmp = buf.getBytes(4, "");
               this.prv_array = tmp[0];
               this.p_array = tmp[1];
               this.q_array = tmp[2];
               this.c_array = tmp[3];
            } catch (Exception e) {
               e.printStackTrace();
               return false;
            }
            getEPArray();
            getEQArray();
            return true;
         }
         if (this.vendor == 1) {
            if (plain[index] != 48) {
               Buffer buf = new Buffer(plain);
               this.pub_array = buf.getMPIntBits();
               this.prv_array = buf.getMPIntBits();
               this.n_array = buf.getMPIntBits();
               byte[] u_array = buf.getMPIntBits();
               this.p_array = buf.getMPIntBits();
               this.q_array = buf.getMPIntBits();
               if (this.n_array != null)
                  this.key_size = (new BigInteger(this.n_array)).bitLength();
               getEPArray();
               getEQArray();
               getCArray();
               return true;
            }
            return false;
         }
         if (this.vendor == 4) {
            Buffer prvKEyBuffer = new Buffer(plain);
            int checkInt1 = prvKEyBuffer.getInt();
            int checkInt2 = prvKEyBuffer.getInt();
            if (checkInt1 != checkInt2)
               throw new Exception("check failed");
            String keyType = Util.byte2str(prvKEyBuffer.getString());
            this.n_array = prvKEyBuffer.getMPInt();
            this.pub_array = prvKEyBuffer.getMPInt();
            this.prv_array = prvKEyBuffer.getMPInt();
            this.c_array = prvKEyBuffer.getMPInt();
            this.p_array = prvKEyBuffer.getMPInt();
            this.q_array = prvKEyBuffer.getMPInt();
            if (this.n_array != null)
               this.key_size = (new BigInteger(this.n_array)).bitLength();
            this.publicKeyComment = Util.byte2str(prvKEyBuffer.getString());
            getEPArray();
            getEQArray();
            return true;
         }
         index++;
         length = plain[index++] & 0xFF;
         if ((length & 0x80) != 0) {
            int foo = length & 0x7F;
            length = 0;
            while (foo-- > 0)
               length = (length << 8) + (plain[index++] & 0xFF);
         }
         if (plain[index] != 2)
            return false;
         index++;
         length = plain[index++] & 0xFF;
         if ((length & 0x80) != 0) {
            int foo = length & 0x7F;
            length = 0;
            while (foo-- > 0)
               length = (length << 8) + (plain[index++] & 0xFF);
         }
         index += length;
         index++;
         length = plain[index++] & 0xFF;
         if ((length & 0x80) != 0) {
            int foo = length & 0x7F;
            length = 0;
            while (foo-- > 0)
               length = (length << 8) + (plain[index++] & 0xFF);
         }
         this.n_array = new byte[length];
         System.arraycopy(plain, index, this.n_array, 0, length);
         index += length;
         index++;
         length = plain[index++] & 0xFF;
         if ((length & 0x80) != 0) {
            int foo = length & 0x7F;
            length = 0;
            while (foo-- > 0)
               length = (length << 8) + (plain[index++] & 0xFF);
         }
         this.pub_array = new byte[length];
         System.arraycopy(plain, index, this.pub_array, 0, length);
         index += length;
         index++;
         length = plain[index++] & 0xFF;
         if ((length & 0x80) != 0) {
            int foo = length & 0x7F;
            length = 0;
            while (foo-- > 0)
               length = (length << 8) + (plain[index++] & 0xFF);
         }
         this.prv_array = new byte[length];
         System.arraycopy(plain, index, this.prv_array, 0, length);
         index += length;
         index++;
         length = plain[index++] & 0xFF;
         if ((length & 0x80) != 0) {
            int foo = length & 0x7F;
            length = 0;
            while (foo-- > 0)
               length = (length << 8) + (plain[index++] & 0xFF);
         }
         this.p_array = new byte[length];
         System.arraycopy(plain, index, this.p_array, 0, length);
         index += length;
         index++;
         length = plain[index++] & 0xFF;
         if ((length & 0x80) != 0) {
            int foo = length & 0x7F;
            length = 0;
            while (foo-- > 0)
               length = (length << 8) + (plain[index++] & 0xFF);
         }
         this.q_array = new byte[length];
         System.arraycopy(plain, index, this.q_array, 0, length);
         index += length;
         index++;
         length = plain[index++] & 0xFF;
         if ((length & 0x80) != 0) {
            int foo = length & 0x7F;
            length = 0;
            while (foo-- > 0)
               length = (length << 8) + (plain[index++] & 0xFF);
         }
         this.ep_array = new byte[length];
         System.arraycopy(plain, index, this.ep_array, 0, length);
         index += length;
         index++;
         length = plain[index++] & 0xFF;
         if ((length & 0x80) != 0) {
            int foo = length & 0x7F;
            length = 0;
            while (foo-- > 0)
               length = (length << 8) + (plain[index++] & 0xFF);
         }
         this.eq_array = new byte[length];
         System.arraycopy(plain, index, this.eq_array, 0, length);
         index += length;
         index++;
         length = plain[index++] & 0xFF;
         if ((length & 0x80) != 0) {
            int foo = length & 0x7F;
            length = 0;
            while (foo-- > 0)
               length = (length << 8) + (plain[index++] & 0xFF);
         }
         this.c_array = new byte[length];
         System.arraycopy(plain, index, this.c_array, 0, length);
         index += length;
         if (this.n_array != null)
            this.key_size = (new BigInteger(this.n_array)).bitLength();
      } catch (Exception e) {
         e.printStackTrace();
         return false;
      }
      return true;
   }

   public byte[] getPublicKeyBlob() {
      byte[] foo = super.getPublicKeyBlob();
      if (foo != null)
         return foo;
      if (this.pub_array == null)
         return null;
      byte[][] tmp = new byte[3][];
      tmp[0] = sshrsa;
      tmp[1] = this.pub_array;
      tmp[2] = this.n_array;
      return (Buffer.fromBytes(tmp)).buffer;
   }

   private static final byte[] sshrsa = Util.str2byte("ssh-rsa");

   byte[] getKeyTypeName() {
      return sshrsa;
   }

   public int getKeyType() {
      return 2;
   }

   public int getKeySize() {
      return this.key_size;
   }

   public byte[] getSignature(byte[] data) {
      return getSignature(data, "ssh-rsa");
   }

   public byte[] getSignature(byte[] data, String alg) {
      try {
         Class<? extends SignatureRSA> c =
                 Class.forName(Util.getConfig(alg)).asSubclass(SignatureRSA.class);
         SignatureRSA rsa = c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
         rsa.init();
         rsa.setPrvKey(this.prv_array, this.n_array);
         rsa.update(data);
         byte[] sig = rsa.sign();
         byte[][] tmp = new byte[2][];
         tmp[0] = Util.str2byte(alg);
         tmp[1] = sig;
         return (Buffer.fromBytes(tmp)).buffer;
      } catch (Exception e) {
         e.printStackTrace();
         return null;
      }
   }

   public Signature getVerifier() {
      return getVerifier("ssh-rsa");
   }

   public Signature getVerifier(String alg) {
      try {
         Class<? extends SignatureRSA> c =
                 Class.forName(Util.getConfig(alg)).asSubclass(SignatureRSA.class);
         SignatureRSA rsa = c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
         rsa.init();
         if (this.pub_array == null && this.n_array == null && getPublicKeyBlob() != null) {
            Buffer buf = new Buffer(getPublicKeyBlob());
            buf.getString();
            this.pub_array = buf.getString();
            this.n_array = buf.getString();
         }
         rsa.setPubKey(this.pub_array, this.n_array);
         return rsa;
      } catch (Exception e) {
         e.printStackTrace();
         return null;
      }
   }

   static KeyPair fromSSHAgent(Buffer buf) throws Exception {
      byte[][] tmp = buf.getBytes(8, "invalid key format");
      byte[] n_array = tmp[1];
      byte[] pub_array = tmp[2];
      byte[] prv_array = tmp[3];
      KeyPairRSA kpair = new KeyPairRSA(n_array, pub_array, prv_array);
      kpair.c_array = tmp[4];
      kpair.p_array = tmp[5];
      kpair.q_array = tmp[6];
      kpair.publicKeyComment = Util.byte2str(tmp[7]);
      kpair.vendor = 0;
      return kpair;
   }

   public byte[] forSSHAgent() throws Exception {
      if (isEncrypted())
         throw new Exception("key is encrypted.");
      Buffer buf = new Buffer();
      buf.putString(sshrsa);
      buf.putString(this.n_array);
      buf.putString(this.pub_array);
      buf.putString(this.prv_array);
      buf.putString(getCArray());
      buf.putString(this.p_array);
      buf.putString(this.q_array);
      buf.putString(Util.str2byte(this.publicKeyComment));
      byte[] result = new byte[buf.getLength()];
      buf.getByte(result, 0, result.length);
      return result;
   }

   private byte[] getEPArray() {
      if (this.ep_array == null)
         this.ep_array = (new BigInteger(this.prv_array)).mod((new BigInteger(this.p_array)).subtract(BigInteger.ONE))
                 .toByteArray();
      return this.ep_array;
   }

   private byte[] getEQArray() {
      if (this.eq_array == null)
         this.eq_array = (new BigInteger(this.prv_array)).mod((new BigInteger(this.q_array)).subtract(BigInteger.ONE))
                 .toByteArray();
      return this.eq_array;
   }

   private byte[] getCArray() {
      if (this.c_array == null)
         this.c_array = (new BigInteger(this.q_array)).modInverse(new BigInteger(this.p_array)).toByteArray();
      return this.c_array;
   }

   public void dispose() {
      super.dispose();
      Util.bzero(this.prv_array);
   }
}
