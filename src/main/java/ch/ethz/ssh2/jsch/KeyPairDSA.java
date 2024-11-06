package ch.ethz.ssh2.jsch;

import java.math.BigInteger;

class KeyPairDSA extends KeyPair {
   private byte[] P_array;

   private byte[] Q_array;

   private byte[] G_array;

   private byte[] pub_array;

   private byte[] prv_array;

   private int key_size = 1024;

   KeyPairDSA() {
      this((byte[])null, (byte[])null, (byte[])null, (byte[])null, (byte[])null);
   }

   KeyPairDSA(byte[] P_array, byte[] Q_array, byte[] G_array, byte[] pub_array, byte[] prv_array) {
      this.P_array = P_array;
      this.Q_array = Q_array;
      this.G_array = G_array;
      this.pub_array = pub_array;
      this.prv_array = prv_array;
      if (P_array != null)
         this.key_size = (new BigInteger(P_array)).bitLength();
   }

   void generate(int key_size) throws JSchException {
      this.key_size = key_size;
      try {
         Class<? extends KeyPairGenDSA> c =
                 Class.forName(Util.getConfig("keypairgen.dsa")).asSubclass(KeyPairGenDSA.class);
         KeyPairGenDSA keypairgen = c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
         keypairgen.init(key_size);
         this.P_array = keypairgen.getP();
         this.Q_array = keypairgen.getQ();
         this.G_array = keypairgen.getG();
         this.pub_array = keypairgen.getY();
         this.prv_array = keypairgen.getX();
         keypairgen = null;
      } catch (Exception e) {
         throw new JSchException(e.toString(), e);
      }
   }

   private static final byte[] begin = Util.str2byte("-----BEGIN DSA PRIVATE KEY-----");

   private static final byte[] end = Util.str2byte("-----END DSA PRIVATE KEY-----");

   byte[] getBegin() {
      return begin;
   }

   byte[] getEnd() {
      return end;
   }

   byte[] getPrivateKey() {
      int content = 1 + countLength(1) + 1 +
              1 + countLength(this.P_array.length) + this.P_array.length +
              1 + countLength(this.Q_array.length) + this.Q_array.length +
              1 + countLength(this.G_array.length) + this.G_array.length +
              1 + countLength(this.pub_array.length) + this.pub_array.length +
              1 + countLength(this.prv_array.length) + this.prv_array.length;
      int total = 1 + countLength(content) + content;
      byte[] plain = new byte[total];
      int index = 0;
      index = writeSEQUENCE(plain, index, content);
      index = writeINTEGER(plain, index, new byte[1]);
      index = writeINTEGER(plain, index, this.P_array);
      index = writeINTEGER(plain, index, this.Q_array);
      index = writeINTEGER(plain, index, this.G_array);
      index = writeINTEGER(plain, index, this.pub_array);
      index = writeINTEGER(plain, index, this.prv_array);
      return plain;
   }

   boolean parse(byte[] plain) {
      try {
         if (this.vendor == 1) {
            if (plain[0] != 48) {
               Buffer buf = new Buffer(plain);
               buf.getInt();
               this.P_array = buf.getMPIntBits();
               this.G_array = buf.getMPIntBits();
               this.Q_array = buf.getMPIntBits();
               this.pub_array = buf.getMPIntBits();
               this.prv_array = buf.getMPIntBits();
               if (this.P_array != null)
                  this.key_size = (new BigInteger(this.P_array)).bitLength();
               return true;
            }
            return false;
         }
         if (this.vendor == 2 || this.vendor == 5) {
            Buffer buf = new Buffer(plain);
            buf.skip(plain.length);
            try {
               byte[][] tmp = buf.getBytes(1, "");
               this.prv_array = tmp[0];
            } catch (Exception e) {
               e.printStackTrace();
               return false;
            }
            return true;
         }
         if (this.vendor == 4) {
            Buffer prvKEyBuffer = new Buffer(plain);
            int checkInt1 = prvKEyBuffer.getInt();
            int checkInt2 = prvKEyBuffer.getInt();
            if (checkInt1 != checkInt2)
               throw new JSchException("check failed");
            String keyType = Util.byte2str(prvKEyBuffer.getString());
            this.P_array = prvKEyBuffer.getMPInt();
            this.Q_array = prvKEyBuffer.getMPInt();
            this.G_array = prvKEyBuffer.getMPInt();
            this.pub_array = prvKEyBuffer.getMPInt();
            this.prv_array = prvKEyBuffer.getMPInt();
            this.publicKeyComment = Util.byte2str(prvKEyBuffer.getString());
            return true;
         }
         int index = 0;
         int length = 0;
         if (plain[index] != 48)
            return false;
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
         this.P_array = new byte[length];
         System.arraycopy(plain, index, this.P_array, 0, length);
         index += length;
         index++;
         length = plain[index++] & 0xFF;
         if ((length & 0x80) != 0) {
            int foo = length & 0x7F;
            length = 0;
            while (foo-- > 0)
               length = (length << 8) + (plain[index++] & 0xFF);
         }
         this.Q_array = new byte[length];
         System.arraycopy(plain, index, this.Q_array, 0, length);
         index += length;
         index++;
         length = plain[index++] & 0xFF;
         if ((length & 0x80) != 0) {
            int foo = length & 0x7F;
            length = 0;
            while (foo-- > 0)
               length = (length << 8) + (plain[index++] & 0xFF);
         }
         this.G_array = new byte[length];
         System.arraycopy(plain, index, this.G_array, 0, length);
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
         if (this.P_array != null)
            this.key_size = (new BigInteger(this.P_array)).bitLength();
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
      if (this.P_array == null)
         return null;
      byte[][] tmp = new byte[5][];
      tmp[0] = sshdss;
      tmp[1] = this.P_array;
      tmp[2] = this.Q_array;
      tmp[3] = this.G_array;
      tmp[4] = this.pub_array;
      return (Buffer.fromBytes(tmp)).buffer;
   }

   private static final byte[] sshdss = Util.str2byte("ssh-dss");

   byte[] getKeyTypeName() {
      return sshdss;
   }

   public int getKeyType() {
      return 1;
   }

   public int getKeySize() {
      return this.key_size;
   }

   public byte[] getSignature(byte[] data) {
      try {
         Class<? extends SignatureDSA> c =
                 Class.forName(Util.getConfig("signature.dss")).asSubclass(SignatureDSA.class);
         SignatureDSA dsa = c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
         dsa.init();
         dsa.setPrvKey(this.prv_array, this.P_array, this.Q_array, this.G_array);
         dsa.update(data);
         byte[] sig = dsa.sign();
         byte[][] tmp = new byte[2][];
         tmp[0] = sshdss;
         tmp[1] = sig;
         return (Buffer.fromBytes(tmp)).buffer;
      } catch (Exception e) {
         e.printStackTrace();
         return null;
      }
   }

   public byte[] getSignature(byte[] data, String alg) {
      return getSignature(data);
   }

   public Signature getVerifier() {
      try {
         Class<? extends SignatureDSA> c =
                 Class.forName(Util.getConfig("signature.dss")).asSubclass(SignatureDSA.class);
         SignatureDSA dsa = c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
         dsa.init();
         if (this.pub_array == null && this.P_array == null && getPublicKeyBlob() != null) {
            Buffer buf = new Buffer(getPublicKeyBlob());
            buf.getString();
            this.P_array = buf.getString();
            this.Q_array = buf.getString();
            this.G_array = buf.getString();
            this.pub_array = buf.getString();
         }
         dsa.setPubKey(this.pub_array, this.P_array, this.Q_array, this.G_array);
         return dsa;
      } catch (Exception e) {
         e.printStackTrace();
         return null;
      }
   }

   public Signature getVerifier(String alg) {
      return getVerifier();
   }

   static KeyPair fromSSHAgent(Buffer buf) throws Exception {
      byte[][] tmp = buf.getBytes(7, "invalid key format");
      byte[] P_array = tmp[1];
      byte[] Q_array = tmp[2];
      byte[] G_array = tmp[3];
      byte[] pub_array = tmp[4];
      byte[] prv_array = tmp[5];
      KeyPairDSA kpair = new KeyPairDSA(P_array, Q_array, G_array, pub_array, prv_array);
      kpair.publicKeyComment = Util.byte2str(tmp[6]);
      kpair.vendor = 0;
      return kpair;
   }

   public byte[] forSSHAgent() throws JSchException {
      if (isEncrypted())
         throw new JSchException("key is encrypted.");
      Buffer buf = new Buffer();
      buf.putString(sshdss);
      buf.putString(this.P_array);
      buf.putString(this.Q_array);
      buf.putString(this.G_array);
      buf.putString(this.pub_array);
      buf.putString(this.prv_array);
      buf.putString(Util.str2byte(this.publicKeyComment));
      byte[] result = new byte[buf.getLength()];
      buf.getByte(result, 0, result.length);
      return result;
   }

   public void dispose() {
      super.dispose();
      Util.bzero(this.prv_array);
   }
}
