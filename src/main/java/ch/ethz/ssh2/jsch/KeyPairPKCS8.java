package ch.ethz.ssh2.jsch;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

class KeyPairPKCS8 extends KeyPair {
   private static final byte[] rsaEncryption = new byte[] { 42, -122, 72, -122,
           -9, 13, 1, 1, 1 };

   private static final byte[] dsaEncryption = new byte[] { 42, -122, 72, -50, 56, 4, 1 };

   private static final byte[] ecPublicKey = new byte[] { 42, -122, 72, -50, 61, 2, 1 };

   private static final byte[] ed25519 = new byte[] { 43, 101, 112 };

   private static final byte[] ed448 = new byte[] { 43, 101, 113 };

   private static final byte[] secp256r1 = new byte[] { 42, -122, 72, -50,
           61, 3, 1, 7 };

   private static final byte[] secp384r1 = new byte[] { 43, -127, 4, 34 };

   private static final byte[] secp521r1 = new byte[] { 43, -127, 4, 35 };

   private static final byte[] pbes2 = new byte[] { 42, -122, 72, -122,
           -9, 13, 1, 5, 13 };

   private static final byte[] pbkdf2 = new byte[] { 42, -122, 72, -122,
           -9, 13, 1, 5, 12 };

   private static final byte[] scrypt = new byte[] { 43, 6, 1, 4,
           1, -38, 71, 4, 11 };

   private static final byte[] hmacWithSha1 = new byte[] { 42, -122, 72, -122,
           -9, 13, 2, 7 };

   private static final byte[] hmacWithSha224 = new byte[] { 42, -122, 72, -122,
           -9, 13, 2, 8 };

   private static final byte[] hmacWithSha256 = new byte[] { 42, -122, 72, -122,
           -9, 13, 2, 9 };

   private static final byte[] hmacWithSha384 = new byte[] { 42, -122, 72, -122,
           -9, 13, 2, 10 };

   private static final byte[] hmacWithSha512 = new byte[] { 42, -122, 72, -122,
           -9, 13, 2, 11 };

   private static final byte[] hmacWithSha512224 = new byte[] { 42, -122, 72,
           -122, -9, 13, 2, 12 };

   private static final byte[] hmacWithSha512256 = new byte[] { 42, -122, 72,
           -122, -9, 13, 2, 13 };

   private static final byte[] aes128cbc = new byte[] { 96, -122, 72, 1,
           101, 3, 4, 1, 2 };

   private static final byte[] aes192cbc = new byte[] { 96, -122, 72, 1,
           101, 3, 4, 1, 22 };

   private static final byte[] aes256cbc = new byte[] { 96, -122, 72, 1,
           101, 3, 4, 1, 42 };

   private static final byte[] descbc = new byte[] { 43, 14, 3, 2, 7 };

   private static final byte[] des3cbc = new byte[] { 42, -122, 72, -122,
           -9, 13, 3, 7 };

   private static final byte[] rc2cbc = new byte[] { 42, -122, 72, -122,
           -9, 13, 3, 2 };

   private static final byte[] rc5cbc = new byte[] { 42, -122, 72, -122,
           -9, 13, 3, 9 };

   private static final byte[] pbeWithMD2AndDESCBC = new byte[] { 42, -122, 72,
           -122, -9, 13, 1, 5, 1 };

   private static final byte[] pbeWithMD2AndRC2CBC = new byte[] { 42, -122, 72,
           -122, -9, 13, 1, 5, 4 };

   private static final byte[] pbeWithMD5AndDESCBC = new byte[] { 42, -122, 72,
           -122, -9, 13, 1, 5, 3 };

   private static final byte[] pbeWithMD5AndRC2CBC = new byte[] { 42, -122, 72,
           -122, -9, 13, 1, 5, 6 };

   private static final byte[] pbeWithSHA1AndDESCBC = new byte[] { 42, -122, 72,
           -122, -9, 13, 1, 5, 10 };

   private static final byte[] pbeWithSHA1AndRC2CBC = new byte[] { 42, -122, 72,
           -122, -9, 13, 1, 5, 11 };

   private KeyPair kpair = null;

   void generate(int key_size) throws JSchException {}

   private static final byte[] begin = Util.str2byte("-----BEGIN DSA PRIVATE KEY-----");

   private static final byte[] end = Util.str2byte("-----END DSA PRIVATE KEY-----");

   byte[] getBegin() {
      return begin;
   }

   byte[] getEnd() {
      return end;
   }

   byte[] getPrivateKey() {
      return null;
   }

   boolean parse(byte[] plain) {
      byte[] _data = null;
      byte[] prv_array = null;
      byte[] _plain = null;
      KeyPair _key = null;
      try {
         KeyPair.ASN1 asn1 = new KeyPair.ASN1(plain);
         if (!asn1.isSEQUENCE())
            throw new KeyPair.ASN1Exception();
         KeyPair.ASN1[] contents = asn1.getContents();
         if (contents.length < 3 || contents.length > 4)
            throw new KeyPair.ASN1Exception();
         if (!contents[0].isINTEGER())
            throw new KeyPair.ASN1Exception();
         if (!contents[1].isSEQUENCE())
            throw new KeyPair.ASN1Exception();
         if (!contents[2].isOCTETSTRING())
            throw new KeyPair.ASN1Exception();
         if (contents.length > 3 && !contents[3].isCONTEXTCONSTRUCTED(0))
            throw new KeyPair.ASN1Exception();
         int version = parseASN1IntegerAsInt(contents[0].getContent());
         if (version != 0)
            throw new KeyPair.ASN1Exception();
         KeyPair.ASN1 privateKeyAlgorithm = contents[1];
         KeyPair.ASN1 privateKey = contents[2];
         contents = privateKeyAlgorithm.getContents();
         if (contents.length == 0)
            throw new KeyPair.ASN1Exception();
         if (!contents[0].isOBJECT())
            throw new KeyPair.ASN1Exception();
         byte[] privateKeyAlgorithmID = contents[0].getContent();
         _data = privateKey.getContent();
         KeyPair _kpair = null;
         if (Util.array_equals(privateKeyAlgorithmID, rsaEncryption)) {
            if (contents.length != 2)
               throw new KeyPair.ASN1Exception();
            if (!contents[1].isNULL())
               throw new KeyPair.ASN1Exception();
            _kpair = new KeyPairRSA();
            _kpair.copy(this);
            if (_kpair.parse(_data)) {
               this.kpair = _kpair;
               return true;
            }
            throw new JSchException("failed to parse RSA");
         }
         if (Util.array_equals(privateKeyAlgorithmID, dsaEncryption)) {
            List<byte[]> values = (List)new ArrayList<>(3);
            if (contents.length > 1 && contents[1].isSEQUENCE()) {
               contents = contents[1].getContents();
               if (contents.length != 3)
                  throw new KeyPair.ASN1Exception();
               if (!contents[0].isINTEGER())
                  throw new KeyPair.ASN1Exception();
               if (!contents[1].isINTEGER())
                  throw new KeyPair.ASN1Exception();
               if (!contents[2].isINTEGER())
                  throw new KeyPair.ASN1Exception();
               values.add(contents[0].getContent());
               values.add(contents[1].getContent());
               values.add(contents[2].getContent());
            }
            asn1 = new KeyPair.ASN1(_data);
            if (values.size() == 0) {
               if (!asn1.isSEQUENCE())
                  throw new KeyPair.ASN1Exception();
               contents = asn1.getContents();
               if (contents.length != 2)
                  throw new KeyPair.ASN1Exception();
               if (!contents[0].isSEQUENCE())
                  throw new KeyPair.ASN1Exception();
               if (!contents[1].isINTEGER())
                  throw new KeyPair.ASN1Exception();
               prv_array = contents[1].getContent();
               contents = contents[0].getContents();
               if (contents.length != 3)
                  throw new KeyPair.ASN1Exception();
               if (!contents[0].isINTEGER())
                  throw new KeyPair.ASN1Exception();
               if (!contents[1].isINTEGER())
                  throw new KeyPair.ASN1Exception();
               if (!contents[2].isINTEGER())
                  throw new KeyPair.ASN1Exception();
               values.add(contents[0].getContent());
               values.add(contents[1].getContent());
               values.add(contents[2].getContent());
            } else {
               if (!asn1.isINTEGER())
                  throw new KeyPair.ASN1Exception();
               prv_array = asn1.getContent();
            }
            byte[] P_array = values.get(0);
            byte[] Q_array = values.get(1);
            byte[] G_array = values.get(2);
            byte[] pub_array = (new BigInteger(G_array))
                    .modPow(new BigInteger(prv_array), new BigInteger(P_array)).toByteArray();
            _key = new KeyPairDSA(P_array, Q_array, G_array, pub_array, prv_array);
            _plain = _key.getPrivateKey();
            _kpair = new KeyPairDSA();
            _kpair.copy(this);
            if (_kpair.parse(_plain)) {
               this.kpair = _kpair;
               return true;
            }
            throw new JSchException("failed to parse DSA");
         }
         if (Util.array_equals(privateKeyAlgorithmID, ecPublicKey)) {
            byte[] name;
            KeyPair.ASN1 publicKey;
            if (contents.length != 2)
               throw new KeyPair.ASN1Exception();
            if (!contents[1].isOBJECT())
               throw new KeyPair.ASN1Exception();
            byte[] namedCurve = contents[1].getContent();
            if (!Util.array_equals(namedCurve, secp256r1)) {
               name = Util.str2byte("nistp256");
            } else if (!Util.array_equals(namedCurve, secp384r1)) {
               name = Util.str2byte("nistp384");
            } else if (!Util.array_equals(namedCurve, secp521r1)) {
               name = Util.str2byte("nistp521");
            } else {
               throw new JSchException("unsupported named curve oid: " + Util.toHex(namedCurve));
            }
            KeyPair.ASN1 ecPrivateKey = new KeyPair.ASN1(_data);
            if (!ecPrivateKey.isSEQUENCE())
               throw new KeyPair.ASN1Exception();
            contents = ecPrivateKey.getContents();
            if (contents.length < 3 || contents.length > 4)
               throw new KeyPair.ASN1Exception();
            if (!contents[0].isINTEGER())
               throw new KeyPair.ASN1Exception();
            if (!contents[1].isOCTETSTRING())
               throw new KeyPair.ASN1Exception();
            version = parseASN1IntegerAsInt(contents[0].getContent());
            if (version != 1)
               throw new KeyPair.ASN1Exception();
            prv_array = contents[1].getContent();
            if (contents.length == 3) {
               publicKey = contents[2];
            } else {
               publicKey = contents[3];
               if (!contents[2].isCONTEXTCONSTRUCTED(0))
                  throw new KeyPair.ASN1Exception();
               KeyPair.ASN1[] goo = contents[2].getContents();
               if (goo.length != 1)
                  throw new KeyPair.ASN1Exception();
               if (!goo[0].isOBJECT())
                  throw new KeyPair.ASN1Exception();
               if (!Util.array_equals(goo[0].getContent(), namedCurve))
                  throw new KeyPair.ASN1Exception();
            }
            if (!publicKey.isCONTEXTCONSTRUCTED(1))
               throw new KeyPair.ASN1Exception();
            contents = publicKey.getContents();
            if (contents.length != 1)
               throw new KeyPair.ASN1Exception();
            if (!contents[0].isBITSTRING())
               throw new KeyPair.ASN1Exception();
            byte[] Q_array = contents[0].getContent();
            byte[][] tmp = KeyPairECDSA.fromPoint(Q_array);
            byte[] r_array = tmp[0];
            byte[] s_array = tmp[1];
            _key = new KeyPairECDSA(name, r_array, s_array, prv_array);
            _plain = _key.getPrivateKey();
            _kpair = new KeyPairECDSA();
            _kpair.copy(this);
            if (_kpair.parse(_plain)) {
               this.kpair = _kpair;
               return true;
            }
            throw new JSchException("failed to parse ECDSA");
         }
         if (Util.array_equals(privateKeyAlgorithmID, ed25519) ||
                 Util.array_equals(privateKeyAlgorithmID, ed448)) {
            if (contents.length != 1)
               throw new KeyPair.ASN1Exception();
            KeyPair.ASN1 curvePrivateKey = new KeyPair.ASN1(_data);
            if (!curvePrivateKey.isOCTETSTRING())
               throw new KeyPair.ASN1Exception();
            prv_array = curvePrivateKey.getContent();
            if (Util.array_equals(privateKeyAlgorithmID, ed25519)) {
               _kpair = new KeyPairEd25519();
            } else {
               _kpair = new KeyPairEd448();
            }
            _kpair.copy(this);
            if (_kpair.parse(prv_array)) {
               this.kpair = _kpair;
               return true;
            }
            throw new JSchException("failed to parse EdDSA");
         }
         throw new JSchException(
                 "unsupported privateKeyAlgorithm oid: " + Util.toHex(privateKeyAlgorithmID));
      } catch (ASN1Exception e) {
         e.printStackTrace();
         return false;
      } catch (Exception e) {
         e.printStackTrace();
         return false;
      } finally {
         Util.bzero(_data);
         Util.bzero(prv_array);
         Util.bzero(_plain);
         if (_key != null)
            _key.dispose();
      }
   }

   public byte[] getPublicKeyBlob() {
      if (this.kpair != null)
         return this.kpair.getPublicKeyBlob();
      return super.getPublicKeyBlob();
   }

   byte[] getKeyTypeName() {
      if (this.kpair != null)
         return this.kpair.getKeyTypeName();
      return new byte[0];
   }

   public int getKeyType() {
      if (this.kpair != null)
         return this.kpair.getKeyType();
      return 4;
   }

   public int getKeySize() {
      return this.kpair.getKeySize();
   }

   public byte[] getSignature(byte[] data) {
      return this.kpair.getSignature(data);
   }

   public byte[] getSignature(byte[] data, String alg) {
      return this.kpair.getSignature(data, alg);
   }

   public Signature getVerifier() {
      return this.kpair.getVerifier();
   }

   public Signature getVerifier(String alg) {
      return this.kpair.getVerifier(alg);
   }

   public byte[] forSSHAgent() throws Exception {
      return this.kpair.forSSHAgent();
   }

   public boolean decrypt(byte[] _passphrase) {
      if (!isEncrypted())
         return true;
      if (_passphrase == null)
         return !isEncrypted();
      byte[] _data = null;
      byte[] key = null;
      byte[] plain = null;
      try {
         String kdfname;
         KDF kdfinst;
         byte[] encryptfuncid;
         KeyPair.ASN1 encryptparams, asn1 = new KeyPair.ASN1(this.data);
         if (!asn1.isSEQUENCE())
            throw new KeyPair.ASN1Exception();
         KeyPair.ASN1[] contents = asn1.getContents();
         if (contents.length != 2)
            throw new KeyPair.ASN1Exception();
         if (!contents[0].isSEQUENCE())
            throw new KeyPair.ASN1Exception();
         if (!contents[1].isOCTETSTRING())
            throw new KeyPair.ASN1Exception();
         _data = contents[1].getContent();
         KeyPair.ASN1 pbes = contents[0];
         contents = pbes.getContents();
         if (contents.length != 2)
            throw new KeyPair.ASN1Exception();
         if (!contents[0].isOBJECT())
            throw new KeyPair.ASN1Exception();
         if (!contents[1].isSEQUENCE())
            throw new KeyPair.ASN1Exception();
         byte[] pbesid = contents[0].getContent();
         KeyPair.ASN1 pbesparam = contents[1];
         if (Util.array_equals(pbesid, pbes2)) {
            contents = pbesparam.getContents();
            if (contents.length != 2)
               throw new KeyPair.ASN1Exception();
            KeyPair.ASN1 kdf = contents[0];
            KeyPair.ASN1 encryptfunc = contents[1];
            if (!kdf.isSEQUENCE())
               throw new KeyPair.ASN1Exception();
            if (!encryptfunc.isSEQUENCE())
               throw new KeyPair.ASN1Exception();
            contents = encryptfunc.getContents();
            if (contents.length != 2)
               throw new KeyPair.ASN1Exception();
            if (!contents[0].isOBJECT())
               throw new KeyPair.ASN1Exception();
            encryptfuncid = contents[0].getContent();
            encryptparams = contents[1];
            contents = kdf.getContents();
            if (contents.length != 2)
               throw new KeyPair.ASN1Exception();
            if (!contents[0].isOBJECT())
               throw new KeyPair.ASN1Exception();
            if (!contents[1].isSEQUENCE())
               throw new KeyPair.ASN1Exception();
            byte[] kdfid = contents[0].getContent();
            if (Util.array_equals(kdfid, pbkdf2)) {
               KeyPair.ASN1 pbkdf2func = contents[1];
               if (!pbkdf2func.isSEQUENCE())
                  throw new KeyPair.ASN1Exception();
               KeyPair.ASN1 prf = null;
               contents = pbkdf2func.getContents();
               if (contents.length < 2 || contents.length > 4)
                  throw new KeyPair.ASN1Exception();
               if (!contents[0].isOCTETSTRING())
                  throw new KeyPair.ASN1Exception();
               if (!contents[1].isINTEGER())
                  throw new KeyPair.ASN1Exception();
               if (contents.length == 4) {
                  if (!contents[2].isINTEGER())
                     throw new KeyPair.ASN1Exception();
                  if (!contents[3].isSEQUENCE())
                     throw new KeyPair.ASN1Exception();
                  prf = contents[3];
               } else if (contents.length == 3) {
                  if (contents[2].isSEQUENCE()) {
                     prf = contents[2];
                  } else if (!contents[2].isINTEGER()) {
                     throw new KeyPair.ASN1Exception();
                  }
               }
               byte[] prfid = null;
               byte[] salt = contents[0].getContent();
               int iterations = parseASN1IntegerAsInt(contents[1].getContent());
               if (prf != null) {
                  contents = prf.getContents();
                  if (contents.length != 2)
                     throw new KeyPair.ASN1Exception();
                  if (!contents[0].isOBJECT())
                     throw new KeyPair.ASN1Exception();
                  if (!contents[1].isNULL())
                     throw new KeyPair.ASN1Exception();
                  prfid = contents[0].getContent();
               }
               kdfname = getPBKDF2Name(prfid);
               PBKDF2 pbkdf2kdf = getPBKDF2(kdfname);
               pbkdf2kdf.init(salt, iterations);
               kdfinst = pbkdf2kdf;
            } else if (Util.array_equals(kdfid, scrypt)) {
               contents = contents[1].getContents();
               if (contents.length < 4 || contents.length > 5)
                  throw new KeyPair.ASN1Exception();
               if (!contents[0].isOCTETSTRING())
                  throw new KeyPair.ASN1Exception();
               if (!contents[1].isINTEGER())
                  throw new KeyPair.ASN1Exception();
               if (!contents[2].isINTEGER())
                  throw new KeyPair.ASN1Exception();
               if (!contents[3].isINTEGER())
                  throw new KeyPair.ASN1Exception();
               if (contents.length > 4 && !contents[4].isINTEGER())
                  throw new KeyPair.ASN1Exception();
               byte[] salt = contents[0].getContent();
               int cost = parseASN1IntegerAsInt(contents[1].getContent());
               int blocksize = parseASN1IntegerAsInt(contents[2].getContent());
               int parallel = parseASN1IntegerAsInt(contents[3].getContent());
               kdfname = "scrypt";
               SCrypt scryptkdf = getSCrypt();
               scryptkdf.init(salt, cost, blocksize, parallel);
               kdfinst = scryptkdf;
            } else {
               throw new JSchException("unsupported kdf oid: " + Util.toHex(kdfid));
            }
         } else {
            String message;
            if (Util.array_equals(pbesid, pbeWithMD2AndDESCBC)) {
               message = "pbeWithMD2AndDES-CBC unsupported";
            } else if (Util.array_equals(pbesid, pbeWithMD2AndRC2CBC)) {
               message = "pbeWithMD2AndRC2-CBC unsupported";
            } else if (Util.array_equals(pbesid, pbeWithMD5AndDESCBC)) {
               message = "pbeWithMD5AndDES-CBC unsupported";
            } else if (Util.array_equals(pbesid, pbeWithMD5AndRC2CBC)) {
               message = "pbeWithMD5AndRC2-CBC unsupported";
            } else if (Util.array_equals(pbesid, pbeWithSHA1AndDESCBC)) {
               message = "pbeWithSHA1AndDES-CBC unsupported";
            } else if (Util.array_equals(pbesid, pbeWithSHA1AndRC2CBC)) {
               message = "pbeWithSHA1AndRC2-CBC unsupported";
            } else {
               message = "unsupported encryption oid: " + Util.toHex(pbesid);
            }
            throw new JSchException(message);
         }
         byte[][] ivp = new byte[1][];
         Cipher cipher = getCipher(encryptfuncid, encryptparams, ivp);
         byte[] iv = ivp[0];
         key = kdfinst.getKey(_passphrase, cipher.getBlockSize());
         if (key == null)
            throw new JSchException("failed to generate key from KDF " + kdfname);
         cipher.init(1, key, iv);
         plain = new byte[_data.length];
         cipher.update(_data, 0, _data.length, plain, 0);
         if (parse(plain)) {
            this.encrypted = false;
            Util.bzero(this.data);
            return true;
         }
         throw new JSchException("failed to parse decrypted key");
      } catch (ASN1Exception e) {
         e.printStackTrace();
         return false;
      } catch (Exception e) {
         e.printStackTrace();
         return false;
      } finally {
         Util.bzero(_data);
         Util.bzero(key);
         Util.bzero(plain);
      }
   }

   static String getPBKDF2Name(byte[] id) throws JSchException {
      String name = null;
      if (id == null || Util.array_equals(id, hmacWithSha1)) {
         name = "pbkdf2-hmac-sha1";
      } else if (Util.array_equals(id, hmacWithSha224)) {
         name = "pbkdf2-hmac-sha224";
      } else if (Util.array_equals(id, hmacWithSha256)) {
         name = "pbkdf2-hmac-sha256";
      } else if (Util.array_equals(id, hmacWithSha384)) {
         name = "pbkdf2-hmac-sha384";
      } else if (Util.array_equals(id, hmacWithSha512)) {
         name = "pbkdf2-hmac-sha512";
      } else if (Util.array_equals(id, hmacWithSha512224)) {
         name = "pbkdf2-hmac-sha512-224";
      } else if (Util.array_equals(id, hmacWithSha512256)) {
         name = "pbkdf2-hmac-sha512-256";
      }
      if (name == null)
         throw new JSchException("unsupported pbkdf2 function oid: " + Util.toHex(id));
      return name;
   }

   static PBKDF2 getPBKDF2(String name) throws JSchException {
      try {
         Class<? extends PBKDF2> c = Class.forName(Util.getConfig(name)).asSubclass(PBKDF2.class);
         return c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
      } catch (Exception e) {
         throw new JSchException(String.valueOf(name) + " is not supported", e);
      }
   }

   static SCrypt getSCrypt() throws JSchException {
      try {
         Class<? extends SCrypt> c = Class.forName(Util.getConfig("scrypt")).asSubclass(SCrypt.class);
         return c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
      } catch (Exception e) {
         throw new JSchException("scrypt is not supported", e);
      }
   }

   static Cipher getCipher(byte[] id, KeyPair.ASN1 encryptparams, byte[][] ivp) throws Exception {
      String name = null;
      if (Util.array_equals(id, aes128cbc)) {
         name = "aes128-cbc";
      } else if (Util.array_equals(id, aes192cbc)) {
         name = "aes192-cbc";
      } else if (Util.array_equals(id, aes256cbc)) {
         name = "aes256-cbc";
      } else {
         if (Util.array_equals(id, descbc))
            throw new JSchException("unsupported cipher function: des-cbc");
         if (Util.array_equals(id, des3cbc))
            throw new JSchException("unsupported cipher function: 3des-cbc");
         if (Util.array_equals(id, rc2cbc))
            throw new JSchException("unsupported cipher function: rc2-cbc");
         if (Util.array_equals(id, rc5cbc))
            throw new JSchException("unsupported cipher function: rc5-cbc");
      }
      if (name == null)
         throw new JSchException("unsupported cipher function oid: " + Util.toHex(id));
      if (!encryptparams.isOCTETSTRING())
         throw new KeyPair.ASN1Exception();
      ivp[0] = encryptparams.getContent();
      try {
         Class<? extends Cipher> c = Class.forName(Util.getConfig(name)).asSubclass(Cipher.class);
         return c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
      } catch (Exception e) {
         throw new JSchException(String.valueOf(name) + " is not supported", e);
      }
   }

   static int parseASN1IntegerAsInt(byte[] content) {
      BigInteger b = new BigInteger(content);
      if (b.bitLength() <= 31)
         return b.intValue();
      throw new ArithmeticException("BigInteger out of int range");
   }
}
