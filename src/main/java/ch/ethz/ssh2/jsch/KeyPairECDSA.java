package ch.ethz.ssh2.jsch;

import java.util.Arrays;

class KeyPairECDSA extends KeyPair {
   private static byte[][] oids = new byte[][] { { 6, 8, 42, -122, 72,
           -50, 61, 3, 1, 7 }, { 6, 5, 43, -127, 4,
           34 }, { 6, 5, 43, -127, 4,
           35 } };

   private static String[] names = new String[] { "nistp256", "nistp384", "nistp521" };

   private byte[] name = Util.str2byte(names[0]);

   private byte[] r_array;

   private byte[] s_array;

   private byte[] prv_array;

   private int key_size = 256;

   KeyPairECDSA() {
      this((byte[])null, (byte[])null, (byte[])null, (byte[])null);
   }

   KeyPairECDSA(byte[] pubkey) {
      this((byte[])null, (byte[])null, (byte[])null, (byte[])null);
      if (pubkey != null) {
         byte[] name = new byte[8];
         System.arraycopy(pubkey, 11, name, 0, 8);
         if (Util.array_equals(name, Util.str2byte("nistp384"))) {
            this.key_size = 384;
            this.name = name;
         }
         if (Util.array_equals(name, Util.str2byte("nistp521"))) {
            this.key_size = 521;
            this.name = name;
         }
      }
   }

   KeyPairECDSA(byte[] name, byte[] r_array, byte[] s_array, byte[] prv_array) {
      if (name != null)
         this.name = name;
      this.r_array = r_array;
      this.s_array = s_array;
      this.prv_array = prv_array;
      if (prv_array != null)
         this.key_size = (prv_array.length >= 64) ? 521 : ((prv_array.length >= 48) ? 384 : 256);
   }

   void generate(int key_size) throws JSchException {
      this.key_size = key_size;
      try {
         Class<? extends KeyPairGenECDSA> c = Class.forName(Util.getConfig("keypairgen.ecdsa"))
                 .asSubclass(KeyPairGenECDSA.class);
         KeyPairGenECDSA keypairgen = c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
         keypairgen.init(key_size);
         this.prv_array = keypairgen.getD();
         this.r_array = keypairgen.getR();
         this.s_array = keypairgen.getS();
         this.name = Util.str2byte(names[(this.prv_array.length >= 64) ? 2 : ((this.prv_array.length >= 48) ? 1 : 0)]);
         keypairgen = null;
      } catch (Exception e) {
         throw new JSchException(e.toString(), e);
      }
   }

   private static final byte[] begin = Util.str2byte("-----BEGIN EC PRIVATE KEY-----");

   private static final byte[] end = Util.str2byte("-----END EC PRIVATE KEY-----");

   byte[] getBegin() {
      return begin;
   }

   byte[] getEnd() {
      return end;
   }

   byte[] getPrivateKey() {
      byte[] tmp = new byte[1];
      tmp[0] = 1;
      byte[] oid = oids[(this.r_array.length >= 64) ? 2 : ((this.r_array.length >= 48) ? 1 : 0)];
      byte[] point = toPoint(this.r_array, this.s_array);
      int bar = ((point.length + 1 & 0x80) == 0) ? 3 : 4;
      byte[] foo = new byte[point.length + bar];
      System.arraycopy(point, 0, foo, bar, point.length);
      foo[0] = 3;
      if (bar == 3) {
         foo[1] = (byte)(point.length + 1);
      } else {
         foo[1] = -127;
         foo[2] = (byte)(point.length + 1);
      }
      point = foo;
      int content = 1 + countLength(tmp.length) + tmp.length + 1 + countLength(this.prv_array.length) + this.prv_array.length +
              1 + countLength(oid.length) + oid.length + 1 + countLength(point.length) + point.length;
      int total = 1 + countLength(content) + content;
      byte[] plain = new byte[total];
      int index = 0;
      index = writeSEQUENCE(plain, index, content);
      index = writeINTEGER(plain, index, tmp);
      index = writeOCTETSTRING(plain, index, this.prv_array);
      index = writeDATA(plain, (byte)-96, index, oid);
      index = writeDATA(plain, (byte)-95, index, point);
      return plain;
   }

   boolean parse(byte[] plain) {
      try {
         if (this.vendor == 1)
            return false;
         if (this.vendor == 2 || this.vendor == 5) {
            Buffer buf = new Buffer(plain);
            buf.skip(plain.length);
            try {
               byte[][] arrayOfByte = buf.getBytes(1, "");
               this.prv_array = arrayOfByte[0];
               this.key_size = (this.prv_array.length >= 64) ? 521 : ((this.prv_array.length >= 48) ? 384 : 256);
            } catch (Exception e) {
               e.printStackTrace();
               return false;
            }
            return true;
         }
         if (this.vendor == 4) {
            Buffer prvKeyBuffer = new Buffer(plain);
            int checkInt1 = prvKeyBuffer.getInt();
            int checkInt2 = prvKeyBuffer.getInt();
            if (checkInt1 != checkInt2)
               throw new JSchException("check failed");
            String keyType = Util.byte2str(prvKeyBuffer.getString());
            this.name = prvKeyBuffer.getString();
            if (!Arrays.<String>asList(names).contains(Util.byte2str(this.name)))
               throw new IllegalArgumentException("unknown curve name " + Util.byte2str(this.name));
            int keyLen = prvKeyBuffer.getInt();
            int x04 = prvKeyBuffer.getByte();
            byte[] x = new byte[(keyLen - 1) / 2];
            byte[] y = new byte[(keyLen - 1) / 2];
            prvKeyBuffer.getByte(x);
            prvKeyBuffer.getByte(y);
            this.prv_array = prvKeyBuffer.getString();
            this.publicKeyComment = Util.byte2str(prvKeyBuffer.getString());
            this.r_array = x;
            this.s_array = y;
            this.key_size = (x.length >= 64) ? 521 : ((x.length >= 48) ? 384 : 256);
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
         byte[] oid_array = new byte[length];
         System.arraycopy(plain, index, oid_array, 0, length);
         index += length;
         for (int i = 0; i < oids.length; i++) {
            if (Util.array_equals(oids[i], oid_array)) {
               this.name = Util.str2byte(names[i]);
               break;
            }
         }
         index++;
         length = plain[index++] & 0xFF;
         if ((length & 0x80) != 0) {
            int foo = length & 0x7F;
            length = 0;
            while (foo-- > 0)
               length = (length << 8) + (plain[index++] & 0xFF);
         }
         byte[] Q_array = new byte[length];
         System.arraycopy(plain, index, Q_array, 0, length);
         index += length;
         byte[][] tmp = fromPoint(Q_array);
         this.r_array = tmp[0];
         this.s_array = tmp[1];
         if (this.prv_array != null)
            this.key_size = (this.prv_array.length >= 64) ? 521 : ((this.prv_array.length >= 48) ? 384 : 256);
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
      if (this.r_array == null)
         return null;
      byte[][] tmp = new byte[3][];
      tmp[0] = Util.str2byte("ecdsa-sha2-" + Util.byte2str(this.name));
      tmp[1] = this.name;
      tmp[2] = new byte[1 + this.r_array.length + this.s_array.length];
      tmp[2][0] = 4;
      System.arraycopy(this.r_array, 0, tmp[2], 1, this.r_array.length);
      System.arraycopy(this.s_array, 0, tmp[2], 1 + this.r_array.length, this.s_array.length);
      return (Buffer.fromBytes(tmp)).buffer;
   }

   byte[] getKeyTypeName() {
      return Util.str2byte("ecdsa-sha2-" + Util.byte2str(this.name));
   }

   public int getKeyType() {
      return 3;
   }

   public int getKeySize() {
      return this.key_size;
   }

   public byte[] getSignature(byte[] data) {
      try {
         Class<? extends SignatureECDSA> c =
                 Class.forName(Util.getConfig("ecdsa-sha2-" + Util.byte2str(this.name)))
                         .asSubclass(SignatureECDSA.class);
         SignatureECDSA ecdsa = c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
         ecdsa.init();
         ecdsa.setPrvKey(this.prv_array);
         ecdsa.update(data);
         byte[] sig = ecdsa.sign();
         byte[][] tmp = new byte[2][];
         tmp[0] = Util.str2byte("ecdsa-sha2-" + Util.byte2str(this.name));
         tmp[1] = sig;
         return (Buffer.fromBytes(tmp)).buffer;
      } catch (Exception e) {
         e.printStackTrace();
         return null;
      }
   }

   public byte[] getSignature(byte[] data, String al) {
      return getSignature(data);
   }

   public Signature getVerifier() {
      try {
         Class<? extends SignatureECDSA> c = Class.forName(Util.getConfig("ecdsa-sha2-" + Util.byte2str(this.name)))
                 .asSubclass(SignatureECDSA.class);
         SignatureECDSA ecdsa = c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
         ecdsa.init();
         if (this.r_array == null && this.s_array == null && getPublicKeyBlob() != null) {
            Buffer buf = new Buffer(getPublicKeyBlob());
            buf.getString();
            buf.getString();
            byte[][] tmp = fromPoint(buf.getString());
            this.r_array = tmp[0];
            this.s_array = tmp[1];
         }
         ecdsa.setPubKey(this.r_array, this.s_array);
         return ecdsa;
      } catch (Exception e) {
         e.printStackTrace();
         return null;
      }
   }

   public Signature getVerifier(String alg) {
      return getVerifier();
   }

   static KeyPair fromSSHAgent(Buffer buf) throws Exception {
      byte[][] tmp = buf.getBytes(5, "invalid key format");
      byte[] name = tmp[1];
      byte[][] foo = fromPoint(tmp[2]);
      byte[] r_array = foo[0];
      byte[] s_array = foo[1];
      byte[] prv_array = tmp[3];
      KeyPairECDSA kpair = new KeyPairECDSA(name, r_array, s_array, prv_array);
      kpair.publicKeyComment = Util.byte2str(tmp[4]);
      kpair.vendor = 0;
      return kpair;
   }

   public byte[] forSSHAgent() throws JSchException {
      if (isEncrypted())
         throw new JSchException("key is encrypted.");
      Buffer buf = new Buffer();
      buf.putString(Util.str2byte("ecdsa-sha2-" + Util.byte2str(this.name)));
      buf.putString(this.name);
      buf.putString(toPoint(this.r_array, this.s_array));
      buf.putString(this.prv_array);
      buf.putString(Util.str2byte(this.publicKeyComment));
      byte[] result = new byte[buf.getLength()];
      buf.getByte(result, 0, result.length);
      return result;
   }

   static byte[] toPoint(byte[] r_array, byte[] s_array) {
      byte[] tmp = new byte[1 + r_array.length + s_array.length];
      tmp[0] = 4;
      System.arraycopy(r_array, 0, tmp, 1, r_array.length);
      System.arraycopy(s_array, 0, tmp, 1 + r_array.length, s_array.length);
      return tmp;
   }

   static byte[][] fromPoint(byte[] point) {
      int i = 0;
      while (point[i] != 4)
         i++;
      i++;
      byte[][] tmp = new byte[2][];
      byte[] r_array = new byte[(point.length - i) / 2];
      byte[] s_array = new byte[(point.length - i) / 2];
      System.arraycopy(point, i, r_array, 0, r_array.length);
      System.arraycopy(point, i + r_array.length, s_array, 0, s_array.length);
      tmp[0] = r_array;
      tmp[1] = s_array;
      return tmp;
   }

   public void dispose() {
      super.dispose();
      Util.bzero(this.prv_array);
   }
}
