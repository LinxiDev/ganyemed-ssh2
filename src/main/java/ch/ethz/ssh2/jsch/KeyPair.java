package ch.ethz.ssh2.jsch;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;

public abstract class KeyPair {
   public static final int DEFERRED = -1;

   public static final int ERROR = 0;

   public static final int DSA = 1;

   public static final int RSA = 2;

   public static final int ECDSA = 3;

   public static final int UNKNOWN = 4;

   public static final int ED25519 = 5;

   public static final int ED448 = 6;

   static final int VENDOR_OPENSSH = 0;

   static final int VENDOR_FSECURE = 1;

   static final int VENDOR_PUTTY = 2;

   static final int VENDOR_PKCS8 = 3;

   static final int VENDOR_OPENSSH_V1 = 4;

   static final int VENDOR_PUTTY_V3 = 5;

   int vendor = 0;

   private static final byte[] AUTH_MAGIC = Util.str2byte("openssh-key-v1\000");

   private static final byte[] cr = Util.str2byte("\n");

   static Hashtable<String, String> config = new Hashtable<>();

   public static KeyPair genKeyPair(int type) throws Exception {
      return genKeyPair(type, 1024);
   }

   public static KeyPair genKeyPair(int type, int key_size) throws Exception {
      KeyPair kpair = null;
      if (type == 1) {
         kpair = new KeyPairDSA();
      } else if (type == 2) {
         kpair = new KeyPairRSA();
      } else if (type == 3) {
         kpair = new KeyPairECDSA();
      } else if (type == 5) {
         kpair = new KeyPairEd25519();
      } else if (type == 6) {
         kpair = new KeyPairEd448();
      }
      if (kpair != null)
         kpair.generate(key_size);
      return kpair;
   }

   abstract void generate(int paramInt) throws Exception;

   abstract byte[] getBegin();

   abstract byte[] getEnd();

   public abstract int getKeySize();

   public abstract byte[] getSignature(byte[] paramArrayOfbyte);

   public abstract byte[] getSignature(byte[] paramArrayOfbyte, String paramString);

   public abstract Signature getVerifier();

   public abstract Signature getVerifier(String paramString);

   public abstract byte[] forSSHAgent() throws Exception;

   public String getPublicKeyComment() {
      return this.publicKeyComment;
   }

   public void setPublicKeyComment(String publicKeyComment) {
      this.publicKeyComment = publicKeyComment;
   }

   protected String publicKeyComment = "no comment";

   protected Cipher cipher;

   private KDF kdf;

   private HASH sha1;

   private HASH hash;

   private Random random;

   private byte[] passphrase;

   static byte[][] header = new byte[][] { Util.str2byte("Proc-Type: 4,ENCRYPTED"), Util.str2byte("DEK-Info: DES-EDE3-CBC,") };

   abstract byte[] getPrivateKey();

   public void writePrivateKey(OutputStream out) {
      writePrivateKey(out, (byte[])null);
   }

   public void writePrivateKey(OutputStream out, byte[] passphrase) {
      if (passphrase == null)
         passphrase = this.passphrase;
      byte[] plain = getPrivateKey();
      byte[][] _iv = new byte[1][];
      byte[] encoded = encrypt(plain, _iv, passphrase);
      if (encoded != plain)
         Util.bzero(plain);
      byte[] iv = _iv[0];
      byte[] prv = Util.toBase64(encoded, 0, encoded.length, true);
      try {
         out.write(getBegin());
         out.write(cr);
         if (passphrase != null) {
            out.write(header[0]);
            out.write(cr);
            out.write(header[1]);
            for (int j = 0; j < iv.length; j++) {
               out.write(b2a((byte)(iv[j] >>> 4 & 0xF)));
               out.write(b2a((byte)(iv[j] & 0xF)));
            }
            out.write(cr);
            out.write(cr);
         }
         int i = 0;
         while (i < prv.length) {
            if (i + 64 < prv.length) {
               out.write(prv, i, 64);
               out.write(cr);
               i += 64;
               continue;
            }
            out.write(prv, i, prv.length - i);
            out.write(cr);
            break;
         }
         out.write(getEnd());
         out.write(cr);
      } catch (Exception e) {
         e.printStackTrace();
      }
   }

   private static byte[] space = Util.str2byte(" ");

   abstract byte[] getKeyTypeName();

   public abstract int getKeyType();

   public String getKeyTypeString() {
      return Util.byte2str(getKeyTypeName());
   }

   public byte[] getPublicKeyBlob() {
      return this.publickeyblob;
   }

   public void writePublicKey(OutputStream out, String comment) {
      byte[] pubblob = getPublicKeyBlob();
      byte[] pub = Util.toBase64(pubblob, 0, pubblob.length, true);
      try {
         out.write(getKeyTypeName());
         out.write(space);
         out.write(pub, 0, pub.length);
         out.write(space);
         out.write(Util.str2byte(comment));
         out.write(cr);
      } catch (Exception e) {
         e.printStackTrace();
      }
   }

   public void writePublicKey(String name, String comment) throws FileNotFoundException, IOException {
      Exception exception1 = null, exception2 = null;
   }

   public void writeSECSHPublicKey(OutputStream out, String comment) {
      byte[] pubblob = getPublicKeyBlob();
      byte[] pub = Util.toBase64(pubblob, 0, pubblob.length, true);
      try {
         out.write(Util.str2byte("---- BEGIN SSH2 PUBLIC KEY ----"));
         out.write(cr);
         out.write(Util.str2byte("Comment: \"" + comment + "\""));
         out.write(cr);
         int index = 0;
         while (index < pub.length) {
            int len = 70;
            if (pub.length - index < len)
               len = pub.length - index;
            out.write(pub, index, len);
            out.write(cr);
            index += len;
         }
         out.write(Util.str2byte("---- END SSH2 PUBLIC KEY ----"));
         out.write(cr);
      } catch (Exception e) {
         e.printStackTrace();
      }
   }

   public void writeSECSHPublicKey(String name, String comment) throws FileNotFoundException, IOException {
      Exception exception1 = null, exception2 = null;
   }

   public void writePrivateKey(String name) throws FileNotFoundException, IOException {
      writePrivateKey(name, (byte[])null);
   }

   public void writePrivateKey(String name, byte[] passphrase) throws FileNotFoundException, IOException {
      Exception exception1 = null, exception2 = null;
   }

   public String getFingerPrint() {
      if (this.hash == null)
         this.hash = genHash();
      byte[] kblob = getPublicKeyBlob();
      if (kblob == null)
         return null;
      return Util.getFingerPrint(this.hash, kblob, false, true);
   }

   private byte[] encrypt(byte[] plain, byte[][] _iv, byte[] passphrase) {
      if (passphrase == null)
         return plain;
      if (this.cipher == null)
         this.cipher = genCipher();
      byte[] iv = _iv[0] = new byte[this.cipher.getIVSize()];
      if (this.random == null)
         this.random = genRandom();
      this.random.fill(iv, 0, iv.length);
      byte[] key = genKey(passphrase, iv);
      byte[] encoded = plain;
      int bsize = this.cipher.getIVSize();
      byte[] foo = new byte[(encoded.length / bsize + 1) * bsize];
      System.arraycopy(encoded, 0, foo, 0, encoded.length);
      int padding = bsize - encoded.length % bsize;
      for (int i = foo.length - 1; foo.length - padding <= i; i--)
         foo[i] = (byte)padding;
      encoded = foo;
      try {
         this.cipher.init(0, key, iv);
         this.cipher.update(encoded, 0, encoded.length, encoded, 0);
      } catch (Exception e) {
         e.printStackTrace();
      }
      Util.bzero(key);
      return encoded;
   }

   abstract boolean parse(byte[] paramArrayOfbyte);

   private byte[] decrypt(byte[] data, byte[] passphrase, byte[] iv) {
      try {
         byte[] key = genKey(passphrase, iv);
         this.cipher.init(1, key, iv);
         Util.bzero(key);
         byte[] plain = new byte[data.length];
         this.cipher.update(data, 0, data.length, plain, 0);
         return plain;
      } catch (Exception e) {
         e.printStackTrace();
         return null;
      }
   }

   int writeSEQUENCE(byte[] buf, int index, int len) {
      buf[index++] = 48;
      index = writeLength(buf, index, len);
      return index;
   }

   int writeINTEGER(byte[] buf, int index, byte[] data) {
      buf[index++] = 2;
      index = writeLength(buf, index, data.length);
      System.arraycopy(data, 0, buf, index, data.length);
      index += data.length;
      return index;
   }

   int writeOCTETSTRING(byte[] buf, int index, byte[] data) {
      buf[index++] = 4;
      index = writeLength(buf, index, data.length);
      System.arraycopy(data, 0, buf, index, data.length);
      index += data.length;
      return index;
   }

   int writeDATA(byte[] buf, byte n, int index, byte[] data) {
      buf[index++] = n;
      index = writeLength(buf, index, data.length);
      System.arraycopy(data, 0, buf, index, data.length);
      index += data.length;
      return index;
   }

   int countLength(int len) {
      int i = 1;
      if (len <= 127)
         return i;
      while (len > 0) {
         len >>>= 8;
         i++;
      }
      return i;
   }

   int writeLength(byte[] data, int index, int len) {
      int i = countLength(len) - 1;
      if (i == 0) {
         data[index++] = (byte)len;
         return index;
      }
      data[index++] = (byte)(0x80 | i);
      int j = index + i;
      while (i > 0) {
         data[index + i - 1] = (byte)(len & 0xFF);
         len >>>= 8;
         i--;
      }
      return j;
   }

   private Random genRandom() {
      if (this.random == null)
         try {
            Class<? extends Random> c =
                    Class.forName(Util.getConfig("random")).asSubclass(Random.class);
            this.random = c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
         } catch (Exception e) {
            e.printStackTrace();
         }
      return this.random;
   }

   private HASH genHash() {
      try {
         Class<? extends HASH> c = Class.forName(Util.getConfig("md5")).asSubclass(HASH.class);
         this.hash = c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
         this.hash.init();
      } catch (Exception e) {
         e.printStackTrace();
      }
      return this.hash;
   }

   private Cipher genCipher() {
      try {
         Class<? extends Cipher> c =
                 Class.forName(Util.getConfig("3des-cbc")).asSubclass(Cipher.class);
         this.cipher = c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
      } catch (Exception e) {
         e.printStackTrace();
      }
      return this.cipher;
   }

   synchronized byte[] genKey(byte[] passphrase, byte[] iv) {
      if (this.cipher == null)
         this.cipher = genCipher();
      if (this.hash == null)
         this.hash = genHash();
      byte[] key = new byte[this.cipher.getBlockSize()];
      int hsize = this.hash.getBlockSize();
      byte[] hn = new byte[key.length / hsize * hsize + ((key.length % hsize == 0) ? 0 : hsize)];
      try {
         byte[] tmp = null;
         if (this.vendor == 0) {
            for (int index = 0; index + hsize <= hn.length; ) {
               if (tmp != null)
                  this.hash.update(tmp, 0, tmp.length);
               this.hash.update(passphrase, 0, passphrase.length);
               this.hash.update(iv, 0, (iv.length > 8) ? 8 : iv.length);
               tmp = this.hash.digest();
               System.arraycopy(tmp, 0, hn, index, tmp.length);
               index += tmp.length;
            }
            System.arraycopy(hn, 0, key, 0, key.length);
         } else if (this.vendor == 4) {
            tmp = this.kdf.getKey(passphrase, this.cipher.getBlockSize() + this.cipher.getIVSize());
            System.arraycopy(tmp, 0, key, 0, key.length);
            System.arraycopy(tmp, key.length, iv, 0, iv.length);
            Util.bzero(tmp);
         } else if (this.vendor == 1) {
            for (int index = 0; index + hsize <= hn.length; ) {
               if (tmp != null)
                  this.hash.update(tmp, 0, tmp.length);
               this.hash.update(passphrase, 0, passphrase.length);
               tmp = this.hash.digest();
               System.arraycopy(tmp, 0, hn, index, tmp.length);
               index += tmp.length;
            }
            System.arraycopy(hn, 0, key, 0, key.length);
         } else if (this.vendor == 2) {
            byte[] i = new byte[4];
            this.sha1.update(i, 0, i.length);
            this.sha1.update(passphrase, 0, passphrase.length);
            tmp = this.sha1.digest();
            System.arraycopy(tmp, 0, key, 0, tmp.length);
            Util.bzero(tmp);
            i[3] = 1;
            this.sha1.update(i, 0, i.length);
            this.sha1.update(passphrase, 0, passphrase.length);
            tmp = this.sha1.digest();
            System.arraycopy(tmp, 0, key, tmp.length, key.length - tmp.length);
            Util.bzero(tmp);
         } else if (this.vendor == 5) {
            tmp = this.kdf.getKey(passphrase, this.cipher.getBlockSize() + this.cipher.getIVSize() + 32);
            System.arraycopy(tmp, 0, key, 0, key.length);
            System.arraycopy(tmp, key.length, iv, 0, iv.length);
            Util.bzero(tmp);
         }
      } catch (Exception e) {
         e.printStackTrace();
      }
      return key;
   }

   @Deprecated
   public void setPassphrase(String passphrase) {
      if (passphrase == null || passphrase.length() == 0) {
         setPassphrase((byte[])null);
      } else {
         setPassphrase(Util.str2byte(passphrase));
      }
   }

   @Deprecated
   public void setPassphrase(byte[] passphrase) {
      if (passphrase != null && passphrase.length == 0)
         passphrase = null;
      this.passphrase = passphrase;
   }

   protected boolean encrypted = false;

   protected byte[] data = null;

   private byte[] iv = null;

   private byte[] publickeyblob = null;

   public boolean isEncrypted() {
      return this.encrypted;
   }

   public boolean decrypt(String _passphrase) {
      if (_passphrase == null || _passphrase.length() == 0)
         return !this.encrypted;
      return decrypt(Util.str2byte(_passphrase));
   }

   public boolean decrypt(byte[] _passphrase) {
      if (!this.encrypted)
         return true;
      if (_passphrase == null)
         return !this.encrypted;
      byte[] bar = new byte[_passphrase.length];
      System.arraycopy(_passphrase, 0, bar, 0, bar.length);
      _passphrase = bar;
      byte[] foo = null;
      try {
         foo = decrypt(this.data, _passphrase, this.iv);
         if (parse(foo)) {
            this.encrypted = false;
            Util.bzero(this.data);
         }
      } finally {
         Util.bzero(_passphrase);
         Util.bzero(foo);
      }
      return !this.encrypted;
   }

   public static KeyPair load(String prvkey) throws Exception {
      String pubkey = String.valueOf(prvkey) + ".pub";
      if (!(new File(pubkey)).exists())
         pubkey = null;
      return load(prvkey, pubkey);
   }

   public static KeyPair load(String prvfile, String pubfile) throws Exception {
      byte[] prvkey = null;
      byte[] pubkey = null;
      try {
         prvkey = Util.fromFile(prvfile);
      } catch (IOException e) {
         throw new Exception(e.toString(), e);
      } catch (Throwable e) {
          throw new RuntimeException(e);
      }
       String _pubfile = pubfile;
      if (pubfile == null)
         _pubfile = String.valueOf(prvfile) + ".pub";
      try {
         pubkey = Util.fromFile(_pubfile);
      } catch (Throwable e) {
         if (pubfile != null)
            throw new Exception(e.toString(), e);
      }
      try {
         return load(prvkey, pubkey);
      } finally {
         Util.bzero(prvkey);
      }
   }

   public static KeyPair load(byte[] prvkey, byte[] pubkey) throws Exception {
      byte[] iv = new byte[8];
      boolean encrypted = true;
      byte[] data = null;
      byte[] publickeyblob = null;
      int type = 0;
      int vendor = 0;
      String publicKeyComment = "";
      Cipher cipher = null;
      if (pubkey == null && prvkey != null &&
              prvkey.length > 11 && prvkey[0] == 0 && prvkey[1] == 0 && prvkey[2] == 0)
         if (prvkey[3] == 7 || prvkey[3] == 9 || prvkey[3] == 11 || prvkey[3] == 19) {
            Buffer buf = new Buffer(prvkey);
            buf.skip(prvkey.length);
            String _type = Util.byte2str(buf.getString());
            buf.rewind();
            KeyPair kpair = null;
            if (_type.equals("ssh-rsa")) {
               kpair = KeyPairRSA.fromSSHAgent(buf);
            } else if (_type.equals("ssh-dss")) {
               kpair = KeyPairDSA.fromSSHAgent(buf);
            } else if (_type.equals("ecdsa-sha2-nistp256") || _type.equals("ecdsa-sha2-nistp384") ||
                    _type.equals("ecdsa-sha2-nistp521")) {
               kpair = KeyPairECDSA.fromSSHAgent(buf);
            } else if (_type.equals("ssh-ed25519")) {
               kpair = KeyPairEd25519.fromSSHAgent(buf);
            } else if (_type.equals("ssh-ed448")) {
               kpair = KeyPairEd448.fromSSHAgent(buf);
            } else {
               throw new Exception("privatekey: invalid key " + _type);
            }
            return kpair;
         }
      try {
         byte[] buf = prvkey;
         if (buf != null) {
            KeyPair ppk = loadPPK(buf);
            if (ppk != null)
               return ppk;
         }
         int len = (buf != null) ? buf.length : 0;
         int i = 0;
         while (i < len && (
                 buf[i] != 45 || i + 4 >= len || buf[i + 1] != 45 || buf[i + 2] != 45 ||
                         buf[i + 3] != 45 || buf[i + 4] != 45))
            i++;
         while (i < len) {
            if (buf[i] == 66 && i + 3 < len && buf[i + 1] == 69 && buf[i + 2] == 71 &&
                    buf[i + 3] == 73) {
               i += 6;
               if (i + 2 >= len)
                  throw new Exception("invalid privatekey");
               if (buf[i] == 68 && buf[i + 1] == 83 && buf[i + 2] == 65) {
                  type = 1;
               } else if (buf[i] == 82 && buf[i + 1] == 83 && buf[i + 2] == 65) {
                  type = 2;
               } else if (buf[i] == 69 && buf[i + 1] == 67) {
                  type = 3;
               } else if (buf[i] == 83 && buf[i + 1] == 83 && buf[i + 2] == 72) {
                  type = 4;
                  vendor = 1;
               } else if (i + 6 < len && buf[i] == 80 && buf[i + 1] == 82 && buf[i + 2] == 73 &&
                       buf[i + 3] == 86 && buf[i + 4] == 65 && buf[i + 5] == 84 && buf[i + 6] == 69) {
                  type = 4;
                  vendor = 3;
                  encrypted = false;
                  i += 3;
               } else if (i + 8 < len && buf[i] == 69 && buf[i + 1] == 78 && buf[i + 2] == 67 &&
                       buf[i + 3] == 82 && buf[i + 4] == 89 && buf[i + 5] == 80 && buf[i + 6] == 84 &&
                       buf[i + 7] == 69 && buf[i + 8] == 68) {
                  type = 4;
                  vendor = 3;
                  i += 5;
               } else if (isOpenSSHPrivateKey(buf, i, len)) {
                  type = 4;
                  vendor = 4;
               } else {
                  throw new Exception("invalid privatekey");
               }
               i += 3;
               continue;
            }
            if (buf[i] == 65 && i + 7 < len && buf[i + 1] == 69 && buf[i + 2] == 83 &&
                    buf[i + 3] == 45 && buf[i + 4] == 50 && buf[i + 5] == 53 && buf[i + 6] == 54 &&
                    buf[i + 7] == 45) {
               i += 8;
               if (Util.checkCipher(Util.getConfig("aes256-cbc"))) {
                  Class<? extends Cipher> c =
                          Class.forName(Util.getConfig("aes256-cbc")).asSubclass(Cipher.class);
                  cipher = c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
                  iv = new byte[cipher.getIVSize()];
                  continue;
               }
               throw new Exception("privatekey: aes256-cbc is not available");
            }
            if (buf[i] == 65 && i + 7 < len && buf[i + 1] == 69 && buf[i + 2] == 83 &&
                    buf[i + 3] == 45 && buf[i + 4] == 49 && buf[i + 5] == 57 && buf[i + 6] == 50 &&
                    buf[i + 7] == 45) {
               i += 8;
               if (Util.checkCipher(Util.getConfig("aes192-cbc"))) {
                  Class<? extends Cipher> c =
                          Class.forName(Util.getConfig("aes192-cbc")).asSubclass(Cipher.class);
                  cipher = c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
                  iv = new byte[cipher.getIVSize()];
                  continue;
               }
               throw new Exception("privatekey: aes192-cbc is not available");
            }
            if (buf[i] == 65 && i + 7 < len && buf[i + 1] == 69 && buf[i + 2] == 83 &&
                    buf[i + 3] == 45 && buf[i + 4] == 49 && buf[i + 5] == 50 && buf[i + 6] == 56 &&
                    buf[i + 7] == 45) {
               i += 8;
               if (Util.checkCipher(Util.getConfig("aes128-cbc"))) {
                  Class<? extends Cipher> c =
                          Class.forName(Util.getConfig("aes128-cbc")).asSubclass(Cipher.class);
                  cipher = c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
                  iv = new byte[cipher.getIVSize()];
                  continue;
               }
               throw new Exception("privatekey: aes128-cbc is not available");
            }
            if (buf[i] == 67 && i + 3 < len && buf[i + 1] == 66 && buf[i + 2] == 67 &&
                    buf[i + 3] == 44) {
               i += 4;
               for (int ii = 0; ii < iv.length; ii++)
                  iv[ii] = (byte)((a2b(buf[i++]) << 4 & 0xF0) + (a2b(buf[i++]) & 0xF));
               continue;
            }
            if (buf[i] == 13 && i + 1 < buf.length && buf[i + 1] == 10) {
               i++;
               continue;
            }
            if (buf[i] == 10 && i + 1 < buf.length) {
               if (buf[i + 1] == 10) {
                  i += 2;
                  break;
               }
               if (buf[i + 1] == 13 && i + 2 < buf.length && buf[i + 2] == 10) {
                  i += 3;
                  break;
               }
               boolean inheader = false;
               for (int j = i + 1; j < buf.length &&
                       buf[j] != 10; j++) {
                  if (buf[j] == 58) {
                     inheader = true;
                     break;
                  }
               }
               if (!inheader) {
                  i++;
                  if (vendor != 3)
                     encrypted = false;
                  break;
               }
            }
            i++;
         }
         if (buf != null) {
            if (type == 0)
               throw new Exception("invalid privatekey");
            int start = i;
            while (i < len &&
                    buf[i] != 45)
               i++;
            if (len - i == 0 || i - start == 0)
               throw new Exception("invalid privatekey");
            byte[] tmp = new byte[i - start];
            System.arraycopy(buf, start, tmp, 0, tmp.length);
            byte[] _buf = tmp;
            start = 0;
            i = 0;
            int _len = _buf.length;
            while (i < _len) {
               if (_buf[i] == 10) {
                  boolean xd = (i > 0 && _buf[i - 1] == 13);
                  System.arraycopy(_buf, i + 1, _buf, i - (xd ? 1 : 0), _len - i + 1);
                  if (xd) {
                     _len--;
                     i--;
                  }
                  _len--;
                  continue;
               }
               if (_buf[i] == 45)
                  break;
               i++;
            }
            if (i - start > 0)
               data = Util.fromBase64(_buf, start, i - start);
            Util.bzero(_buf);
         }
         if (vendor == 4)
            return loadOpenSSHKeyv1(data);
         if (data != null && data.length > 4 &&
                 data[0] == 63 && data[1] == 111 && data[2] == -7 &&
                 data[3] == -21) {
            Buffer _buf = new Buffer(data);
            _buf.getInt();
            _buf.getInt();
            byte[] _type = _buf.getString();
            String _cipher = Util.byte2str(_buf.getString());
            if (_cipher.equals("3des-cbc")) {
               _buf.getInt();
               byte[] foo = new byte[data.length - _buf.getOffSet()];
               _buf.getByte(foo);
               data = foo;
               encrypted = true;
               throw new Exception(
                       "cipher " + _cipher + " is not supported for this privatekey format");
            }
            if (_cipher.equals("none")) {
               _buf.getInt();
               _buf.getInt();
               encrypted = false;
               byte[] foo = new byte[data.length - _buf.getOffSet()];
               _buf.getByte(foo);
               data = foo;
            } else {
               throw new Exception(
                       "cipher " + _cipher + " is not supported for this privatekey format");
            }
         }
         if (pubkey != null)
            try {
               buf = pubkey;
               len = buf.length;
               if (buf.length > 4 &&
                       buf[0] == 45 && buf[1] == 45 && buf[2] == 45 && buf[3] == 45) {
                  boolean valid = true;
                  i = 0;
                  do {
                     i++;
                  } while (buf.length > i && buf[i] != 10);
                  if (buf.length <= i)
                     valid = false;
                  while (valid) {
                     if (buf[i] == 10) {
                        boolean inheader = false;
                        for (int j = i + 1; j < buf.length &&
                                buf[j] != 10; j++) {
                           if (buf[j] == 58) {
                              inheader = true;
                              break;
                           }
                        }
                        if (!inheader) {
                           i++;
                           break;
                        }
                     }
                     i++;
                  }
                  if (buf.length <= i)
                     valid = false;
                  int start = i;
                  while (valid && i < len) {
                     if (buf[i] == 10) {
                        System.arraycopy(buf, i + 1, buf, i, len - i - 1);
                        len--;
                        continue;
                     }
                     if (buf[i] == 45)
                        break;
                     i++;
                  }
                  if (valid) {
                     publickeyblob = Util.fromBase64(buf, start, i - start);
                     if (prvkey == null || type == 4)
                        if (publickeyblob[8] == 100) {
                           type = 1;
                        } else if (publickeyblob[8] == 114) {
                           type = 2;
                        }
                  }
               } else if (buf[0] == 115 && buf[1] == 115 && buf[2] == 104 && buf[3] == 45) {
                  if (prvkey == null && buf.length > 7)
                     if (buf[4] == 100) {
                        type = 1;
                     } else if (buf[4] == 114) {
                        type = 2;
                     } else if (buf[4] == 101 && buf[6] == 50) {
                        type = 5;
                     } else if (buf[4] == 101 && buf[6] == 52) {
                        type = 6;
                     }
                  i = 0;
                  while (i < len &&
                          buf[i] != 32)
                     i++;
                  i++;
                  if (i < len) {
                     int start = i;
                     while (i < len &&
                             buf[i] != 32)
                        i++;
                     publickeyblob = Util.fromBase64(buf, start, i - start);
                  }
                  if (i++ < len) {
                     int start = i;
                     while (i < len &&
                             buf[i] != 10)
                        i++;
                     if (i > 0 && buf[i - 1] == 13)
                        i--;
                     if (start < i)
                        publicKeyComment = Util.byte2str(buf, start, i - start);
                  }
               } else if (buf[0] == 101 && buf[1] == 99 && buf[2] == 100 && buf[3] == 115) {
                  if (prvkey == null && buf.length > 7)
                     type = 3;
                  i = 0;
                  while (i < len &&
                          buf[i] != 32)
                     i++;
                  i++;
                  if (i < len) {
                     int start = i;
                     while (i < len &&
                             buf[i] != 32)
                        i++;
                     publickeyblob = Util.fromBase64(buf, start, i - start);
                  }
                  if (i++ < len) {
                     int start = i;
                     while (i < len &&
                             buf[i] != 10)
                        i++;
                     if (i > 0 && buf[i - 1] == 13)
                        i--;
                     if (start < i)
                        publicKeyComment = Util.byte2str(buf, start, i - start);
                  }
               }
            } catch (Exception ee) {
               ee.printStackTrace();
            }
         KeyPair kpair = null;
         if (type == 1) {
            kpair = new KeyPairDSA();
         } else if (type == 2) {
            kpair = new KeyPairRSA();
         } else if (type == 3) {
            kpair = new KeyPairECDSA(pubkey);
         } else if (type == 5) {
            kpair = new KeyPairEd25519(pubkey, null);
         } else if (type == 6) {
            kpair = new KeyPairEd448(pubkey, null);
         } else if (vendor == 3) {
            kpair = new KeyPairPKCS8();
         }
         if (kpair != null) {
            kpair.encrypted = encrypted;
            kpair.publickeyblob = publickeyblob;
            kpair.vendor = vendor;
            kpair.publicKeyComment = publicKeyComment;
            kpair.cipher = cipher;
            if (encrypted) {
               kpair.encrypted = true;
               kpair.iv = iv;
               kpair.data = data;
            } else if (kpair.parse(data)) {
               kpair.encrypted = false;
            } else {
               throw new Exception("invalid privatekey");
            }
         }
         return kpair;
      } catch (Exception|NoClassDefFoundError e) {
         Util.bzero(data);
         if (e instanceof Exception)
            throw (Exception)e;
         throw new Exception(e.toString(), e);
      }
   }

   static KeyPair loadOpenSSHKeyv1(byte[] data) throws Exception {
      if (data == null)
         throw new Exception("invalid privatekey");
      Buffer buffer = new Buffer(data);
      byte[] magic = new byte[AUTH_MAGIC.length];
      buffer.getByte(magic);
      if (!Util.arraysequals(AUTH_MAGIC, magic))
         throw new Exception("Invalid openssh v1 format.");
      String cipherName = Util.byte2str(buffer.getString());
      String kdfName = Util.byte2str(buffer.getString());
      byte[] kdfOptions = buffer.getString();
      int nrKeys = buffer.getInt();
      if (nrKeys != 1)
         throw new Exception("We don't support having more than 1 key in the file (yet).");
      byte[] publickeyblob = buffer.getString();
      KeyPair kpair = parsePubkeyBlob(publickeyblob, null);
      kpair.encrypted = !"none".equals(cipherName);
      kpair.publickeyblob = publickeyblob;
      kpair.vendor = 4;
      kpair.publicKeyComment = "";
      kpair.data = buffer.getString();
      try {
         if (!kpair.encrypted) {
            if (!kpair.parse(kpair.data))
               throw new Exception("invalid privatekey");
            Util.bzero(kpair.data);
         } else {
            if (Util.checkCipher(Util.getConfig(cipherName))) {
               try {
                  Class<? extends Cipher> c =
                          Class.forName(Util.getConfig(cipherName)).asSubclass(Cipher.class);
                  kpair.cipher = c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
                  kpair.iv = new byte[kpair.cipher.getIVSize()];
               } catch (Exception|NoClassDefFoundError e) {
                  throw new Exception("cipher " + cipherName + " is not available", e);
               }
            } else {
               throw new Exception("cipher " + cipherName + " is not available");
            }
            try {
               Buffer kdfOpts = new Buffer(kdfOptions);
               byte[] salt = kdfOpts.getString();
               int rounds = kdfOpts.getInt();
               Class<? extends BCrypt> c =
                       Class.forName(Util.getConfig(kdfName)).asSubclass(BCrypt.class);
               BCrypt bcrypt = c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
               bcrypt.init(salt, rounds);
               kpair.kdf = bcrypt;
            } catch (Exception|NoClassDefFoundError e) {
               throw new Exception("kdf " + kdfName + " is not available", e);
            }
         }
         return kpair;
      } catch (Exception e) {
         Util.bzero(kpair.data);
         throw e;
      }
   }

   private static boolean isOpenSSHPrivateKey(byte[] buf, int i, int len) {
      String ident = "OPENSSH PRIVATE KEY-----";
      return (i + ident.length() < len &&
              ident.equals(Util.byte2str(Arrays.copyOfRange(buf, i, i + ident.length()))));
   }

   private static byte a2b(byte c) {
      if (48 <= c && c <= 57)
         return (byte)(c - 48);
      return (byte)(c - 97 + 10);
   }

   private static byte b2a(byte c) {
      if (c >= 0 && c <= 9)
         return (byte)(c + 48);
      return (byte)(c - 10 + 65);
   }

   public void dispose() {
      Util.bzero(this.passphrase);
   }

   public void finalize() {
      dispose();
   }

   static KeyPair loadPPK(byte[] buf) throws Exception {
      int ppkVersion;
      byte[] pubkey = null;
      byte[] prvkey = null;
      byte[] _prvkey = null;
      int lines = 0;
      Buffer buffer = new Buffer(buf);
      Map<String, String> v = new HashMap<>();
      do {

      } while (parseHeader(buffer, v));
      String typ = v.get("PuTTY-User-Key-File-2");
      if (typ == null) {
         typ = v.get("PuTTY-User-Key-File-3");
         if (typ == null)
            return null;
         ppkVersion = 5;
      } else {
         ppkVersion = 2;
      }
      try {
         lines = Integer.parseInt(v.get("Public-Lines"));
         pubkey = parseLines(buffer, lines);
         do {

         } while (parseHeader(buffer, v));
         lines = Integer.parseInt(v.get("Private-Lines"));
         _prvkey = parseLines(buffer, lines);
         do {

         } while (parseHeader(buffer, v));
         prvkey = Util.fromBase64(_prvkey, 0, _prvkey.length);
         pubkey = Util.fromBase64(pubkey, 0, pubkey.length);
         KeyPair kpair = parsePubkeyBlob(pubkey, typ);
         kpair.encrypted = !((String)v.get("Encryption")).equals("none");
         kpair.publickeyblob = pubkey;
         kpair.vendor = ppkVersion;
         kpair.publicKeyComment = v.get("Comment");
         if (kpair.encrypted) {
            if (Util.checkCipher(Util.getConfig("aes256-cbc"))) {
               try {
                  Class<? extends Cipher> c =
                          Class.forName(Util.getConfig("aes256-cbc")).asSubclass(Cipher.class);
                  kpair.cipher = c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
                  kpair.iv = new byte[kpair.cipher.getIVSize()];
               } catch (Exception|NoClassDefFoundError e) {
                  throw new Exception("The cipher 'aes256-cbc' is required, but it is not available.",
                          e);
               }
            } else {
               throw new Exception("The cipher 'aes256-cbc' is required, but it is not available.");
            }
            if (ppkVersion == 2) {
               try {
                  Class<? extends HASH> c = Class.forName(Util.getConfig("sha-1")).asSubclass(HASH.class);
                  HASH sha1 = c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
                  sha1.init();
                  kpair.sha1 = sha1;
               } catch (Exception|NoClassDefFoundError e) {
                  throw new Exception("'sha-1' is required, but it is not available.", e);
               }
            } else {
               int argonType;
               String argonTypeStr = v.get("Key-Derivation");
               String saltStr = v.get("Argon2-Salt");
               if (argonTypeStr == null || saltStr == null || (
                       saltStr != null && saltStr.length() % 2 != 0))
                  throw new Exception("Invalid argon2 params.");
               String str1;
               switch ((str1 = argonTypeStr).hashCode()) {
                  case -1530598888:
                     if (str1.equals("Argon2id")) {
                        argonType = 2;
                        break;
                     }
                  case 920457159:
                     if (str1.equals("Argon2d")) {
                        argonType = 0;
                        break;
                     }
                  case 920457164:
                     if (str1.equals("Argon2i")) {
                        argonType = 1;
                        break;
                     }
                  default:
                     throw new Exception("Invalid argon2 params.");
               }
               try {
                  int memory = Integer.parseInt(v.get("Argon2-Memory"));
                  int passes = Integer.parseInt(v.get("Argon2-Passes"));
                  int parallelism = Integer.parseInt(v.get("Argon2-Parallelism"));
                  byte[] salt = new byte[saltStr.length() / 2];
                  for (int i = 0; i < salt.length; i++) {
                     int j = i * 2;
                     salt[i] = (byte)Integer.parseInt(saltStr.substring(j, j + 2), 16);
                  }
                  Class<? extends Argon2> c =
                          Class.forName(Util.getConfig("argon2")).asSubclass(Argon2.class);
                  Argon2 argon2 = c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
                  argon2.init(salt, passes, argonType, new byte[0], new byte[0], memory, parallelism,
                          19);
                  kpair.kdf = argon2;
               } catch (NumberFormatException e) {
                  throw new Exception("Invalid argon2 params.", e);
               } catch (Exception|NoClassDefFoundError e) {
                  throw new Exception("'argon2' is required, but it is not available.", e);
               }
            }
            kpair.data = prvkey;
         } else {
            kpair.data = prvkey;
            if (!kpair.parse(prvkey))
               throw new Exception("invalid privatekey");
            Util.bzero(prvkey);
         }
         return kpair;
      } catch (Exception e) {
         Util.bzero(prvkey);
         throw e;
      } finally {
         Util.bzero(_prvkey);
      }
   }

   private static KeyPair parsePubkeyBlob(byte[] pubkeyblob, String typ) throws Exception {
      Buffer _buf = new Buffer(pubkeyblob);
      _buf.skip(pubkeyblob.length);
      String pubkeyType = Util.byte2str(_buf.getString());
      if (typ == null || typ.equals("")) {
         typ = pubkeyType;
      } else if (!typ.equals(pubkeyType)) {
         throw new Exception(
                 "pubkeyblob type [" + pubkeyType + "] does not match expected type [" + typ + "]");
      }
      if (typ.equals("ssh-rsa")) {
         byte[] pub_array = new byte[_buf.getInt()];
         _buf.getByte(pub_array);
         byte[] n_array = new byte[_buf.getInt()];
         _buf.getByte(n_array);
         return new KeyPairRSA(n_array, pub_array, null);
      }
      if (typ.equals("ssh-dss")) {
         byte[] p_array = new byte[_buf.getInt()];
         _buf.getByte(p_array);
         byte[] q_array = new byte[_buf.getInt()];
         _buf.getByte(q_array);
         byte[] g_array = new byte[_buf.getInt()];
         _buf.getByte(g_array);
         byte[] y_array = new byte[_buf.getInt()];
         _buf.getByte(y_array);
         return new KeyPairDSA(p_array, q_array, g_array, y_array, null);
      }
      if (typ.equals("ecdsa-sha2-nistp256") || typ.equals("ecdsa-sha2-nistp384") ||
              typ.equals("ecdsa-sha2-nistp521")) {
         byte[] name = _buf.getString();
         int len = _buf.getInt();
         int x04 = _buf.getByte();
         byte[] r_array = new byte[(len - 1) / 2];
         byte[] s_array = new byte[(len - 1) / 2];
         _buf.getByte(r_array);
         _buf.getByte(s_array);
         return new KeyPairECDSA(name, r_array, s_array, null);
      }
      if (typ.equals("ssh-ed25519") || typ.equals("ssh-ed448")) {
         byte[] pub_array = new byte[_buf.getInt()];
         _buf.getByte(pub_array);
         if (typ.equals("ssh-ed25519"))
            return new KeyPairEd25519(pub_array, null);
         return new KeyPairEd448(pub_array, null);
      }
      throw new Exception("key type " + typ + " is not supported");
   }

   private static byte[] parseLines(Buffer buffer, int lines) {
      byte[] buf = buffer.buffer;
      int index = buffer.index;
      byte[] data = null;
      int i = index;
      while (lines-- > 0) {
         while (buf.length > i) {
            byte c = buf[i++];
            if (c == 13 || c == 10) {
               int len = i - index - 1;
               if (data == null) {
                  data = new byte[len];
                  System.arraycopy(buf, index, data, 0, len);
                  break;
               }
               if (len > 0) {
                  byte[] tmp = new byte[data.length + len];
                  System.arraycopy(data, 0, tmp, 0, data.length);
                  System.arraycopy(buf, index, tmp, data.length, len);
                  Util.bzero(data);
                  data = tmp;
               }
               break;
            }
         }
         if (i < buf.length && buf[i] == 10)
            i++;
         index = i;
      }
      if (data != null)
         buffer.index = index;
      return data;
   }

   private static boolean parseHeader(Buffer buffer, Map<String, String> v) {
      byte[] buf = buffer.buffer;
      int index = buffer.index;
      String key = null;
      String value = null;
      int i;
      for (i = index; i < buf.length; i++) {
         if (buf[i] == 13 || buf[i] == 10) {
            if (i + 1 < buf.length && buf[i + 1] == 10)
               i++;
            break;
         }
         if (buf[i] == 58) {
            key = Util.byte2str(buf, index, i - index);
            i++;
            if (i < buf.length && buf[i] == 32)
               i++;
            index = i;
            break;
         }
      }
      if (key == null)
         return false;
      for (i = index; i < buf.length; i++) {
         if (buf[i] == 13 || buf[i] == 10) {
            value = Util.byte2str(buf, index, i - index);
            i++;
            if (i < buf.length && buf[i] == 10)
               i++;
            index = i;
            break;
         }
      }
      if (value != null) {
         v.put(key, value);
         buffer.index = index;
      }
      return (key != null && value != null);
   }

   void copy(KeyPair kpair) {
      this.publickeyblob = kpair.publickeyblob;
      this.vendor = kpair.vendor;
      this.publicKeyComment = kpair.publicKeyComment;
      this.cipher = kpair.cipher;
   }

   static class ASN1Exception extends Exception {
      private static final long serialVersionUID = -1L;
   }

   static class ASN1 {
      byte[] buf;

      int start;

      int length;

      ASN1(byte[] buf) throws KeyPair.ASN1Exception {
         this(buf, 0, buf.length);
      }

      ASN1(byte[] buf, int start, int length) throws KeyPair.ASN1Exception {
         this.buf = buf;
         this.start = start;
         this.length = length;
         if (start + length > buf.length)
            throw new KeyPair.ASN1Exception();
      }

      int getType() {
         return this.buf[this.start] & 0xFF;
      }

      boolean isSEQUENCE() {
         return (getType() == 48);
      }

      boolean isINTEGER() {
         return (getType() == 2);
      }

      boolean isOBJECT() {
         return (getType() == 6);
      }

      boolean isOCTETSTRING() {
         return (getType() == 4);
      }

      boolean isNULL() {
         return (getType() == 5);
      }

      boolean isBITSTRING() {
         return (getType() == 3);
      }

      boolean isCONTEXTPRIMITIVE(int tag) {
         if ((tag & 0xFFFFFF00) != 0 || (tag & 0x60) != 0)
            throw new IllegalArgumentException();
         return (getType() == ((tag | 0x80) & 0xFF));
      }

      boolean isCONTEXTCONSTRUCTED(int tag) {
         if ((tag & 0xFFFFFF00) != 0 || (tag & 0x40) != 0)
            throw new IllegalArgumentException();
         return (getType() == ((tag | 0xA0) & 0xFF));
      }

      private int getLength(int[] indexp) {
         int index = indexp[0];
         int length = this.buf[index++] & 0xFF;
         if ((length & 0x80) != 0) {
            int foo = length & 0x7F;
            length = 0;
            while (foo-- > 0)
               length = (length << 8) + (this.buf[index++] & 0xFF);
         }
         indexp[0] = index;
         return length;
      }

      byte[] getContent() {
         int[] indexp = new int[1];
         indexp[0] = this.start + 1;
         int length = getLength(indexp);
         int index = indexp[0];
         byte[] tmp = new byte[length];
         System.arraycopy(this.buf, index, tmp, 0, tmp.length);
         return tmp;
      }

      ASN1[] getContents() throws KeyPair.ASN1Exception {
         int typ = this.buf[this.start];
         int[] indexp = new int[1];
         indexp[0] = this.start + 1;
         int length = getLength(indexp);
         if (typ == 5)
            return new ASN1[0];
         int index = indexp[0];
         List<ASN1> values = new ArrayList<>();
         while (length > 0) {
            index++;
            length--;
            int tmp = index;
            indexp[0] = index;
            int l = getLength(indexp);
            index = indexp[0];
            length -= index - tmp;
            values.add(new ASN1(this.buf, tmp - 1, 1 + index - tmp + l));
            index += l;
            length -= l;
         }
         ASN1[] result = new ASN1[values.size()];
         values.toArray(result);
         return result;
      }
   }
}
