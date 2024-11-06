package ch.ethz.ssh2.jsch;

import java.util.Locale;

public abstract class KeyExchange {
   static final int PROPOSAL_KEX_ALGS = 0;

   static final int PROPOSAL_SERVER_HOST_KEY_ALGS = 1;

   static final int PROPOSAL_ENC_ALGS_CTOS = 2;

   static final int PROPOSAL_ENC_ALGS_STOC = 3;

   static final int PROPOSAL_MAC_ALGS_CTOS = 4;

   static final int PROPOSAL_MAC_ALGS_STOC = 5;

   static final int PROPOSAL_COMP_ALGS_CTOS = 6;

   static final int PROPOSAL_COMP_ALGS_STOC = 7;

   static final int PROPOSAL_LANG_CTOS = 8;

   static final int PROPOSAL_LANG_STOC = 9;

   static final int PROPOSAL_MAX = 10;

   static final String[] PROPOSAL_NAMES = new String[] { "KEX algorithms", "host key algorithms", "ciphers c2s", "ciphers s2c", "MACs c2s",
           "MACs s2c", "compression c2s", "compression s2c", "languages c2s", "languages s2c" };

   static String kex = "diffie-hellman-group1-sha1";

   static String server_host_key = "ssh-rsa,ssh-dss";

   static String enc_c2s = "blowfish-cbc";

   static String enc_s2c = "blowfish-cbc";

   static String mac_c2s = "hmac-md5";

   static String mac_s2c = "hmac-md5";

   static String lang_c2s = "";

   static String lang_s2c = "";

   public static final int STATE_END = 0;

   protected HASH sha = null;

   protected byte[] K = null;

   protected byte[] H = null;

   protected byte[] K_S = null;

   public abstract void init(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, byte[] paramArrayOfbyte3, byte[] paramArrayOfbyte4) throws Exception;

   void doInit(byte[] V_S, byte[] V_C, byte[] I_S, byte[] I_C) throws Exception {}

   protected final int RSA = 0;

   protected final int DSS = 1;

   protected final int ECDSA = 2;

   protected final int EDDSA = 3;

   private int type = 0;

   private String key_alg_name = "";

   public abstract boolean next(Buffer paramBuffer) throws Exception;

   public abstract int getState();

   public String getKeyType() {
      if (this.type == 1)
         return "DSA";
      if (this.type == 0)
         return "RSA";
      if (this.type == 3)
         return "EDDSA";
      return "ECDSA";
   }

   public String getKeyAlgorithName() {
      return this.key_alg_name;
   }

   protected static String[] guess(byte[] I_S, byte[] I_C) throws Exception {
      String[] guess = new String[10];
      Buffer sb = new Buffer(I_S);
      sb.setOffSet(17);
      Buffer cb = new Buffer(I_C);
      cb.setOffSet(17);
      for (int i = 0; i < 10; i++) {
         byte[] sp = sb.getString();
         byte[] cp = cb.getString();
         int j = 0;
         int k = 0;
         label48: while (j < cp.length) {
            while (j < cp.length && cp[j] != 44)
               j++;
            if (k == j)
               throw new JSchAlgoNegoFailException(i, Util.byte2str(cp), Util.byte2str(sp));
            String algorithm = Util.byte2str(cp, k, j - k);
            int l = 0;
            int m = 0;
            while (l < sp.length) {
               while (l < sp.length && sp[l] != 44)
                  l++;
               if (m == l)
                  throw new JSchAlgoNegoFailException(i, Util.byte2str(cp), Util.byte2str(sp));
               if (algorithm.equals(Util.byte2str(sp, m, l - m))) {
                  guess[i] = algorithm;
                  break label48;
               }
               m = ++l;
            }
            k = ++j;
         }
         if (j == 0) {
            guess[i] = "";
         } else if (guess[i] == null) {
            throw new JSchAlgoNegoFailException(i, Util.byte2str(cp), Util.byte2str(sp));
         }
      }
      boolean _s2cAEAD = false;
      boolean _c2sAEAD = false;
      try {
         Class<? extends Cipher> _s2cclazz =
                 Class.forName(Util.getConfig(guess[3])).asSubclass(Cipher.class);
         Cipher _s2ccipher = _s2cclazz.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
         _s2cAEAD = _s2ccipher.isAEAD();
         if (_s2cAEAD)
            guess[5] = null;
         Class<? extends Cipher> _c2sclazz =
                 Class.forName(Util.getConfig(guess[2])).asSubclass(Cipher.class);
         Cipher _c2scipher = _c2sclazz.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
         _c2sAEAD = _c2scipher.isAEAD();
         if (_c2sAEAD)
            guess[4] = null;
      } catch (Exception|NoClassDefFoundError e) {
         throw new JSchException(e.toString(), e);
      }
      return guess;
   }

   public String getFingerPrint() {
      HASH hash = null;
      try {
         String _c = Util.getConfig("FingerprintHash").toLowerCase(Locale.ROOT);
         Class<? extends HASH> c = Class.forName(Util.getConfig(_c)).asSubclass(HASH.class);
         hash = c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
      } catch (Exception e) {
         e.printStackTrace();
      }
      return Util.getFingerPrint(hash, getHostKey(), true, false);
   }

   byte[] getK() {
      return this.K;
   }

   void clearK() {
      Util.bzero(this.K);
      this.K = null;
   }

   byte[] getH() {
      return this.H;
   }

   HASH getHash() {
      return this.sha;
   }

   byte[] getHostKey() {
      return this.K_S;
   }

   protected byte[] normalize(byte[] secret) {
      int len = secret.length;
      if (len < 2)
         return secret;
      int a = 0;
      int s0 = secret[0] & 0xFF;
      for (int i = 0; i < 8; i++) {
         int k = s0 >>> i;
         k &= 0x1;
         a |= k;
      }
      a ^= 0x1;
      int offset = 0;
      for (int j = 1; j < len; j++) {
         int m = secret[j] & 0x80;
         m >>>= 7;
         m ^= 0x1;
         a &= m;
         offset += a;
         m = secret[j] & Byte.MAX_VALUE;
         for (int k = 0; k < 7; k++) {
            int l = m >>> k;
            l &= 0x1;
            l ^= 0x1;
            a &= l;
         }
      }
      len -= offset;
      byte[] foo = new byte[len];
      byte[] bar = new byte[offset];
      System.arraycopy(secret, 0, bar, 0, offset);
      System.arraycopy(secret, offset, foo, 0, len);
      Util.bzero(secret);
      return foo;
   }

   protected boolean verify(String alg, byte[] K_S, int index, byte[] sig_of_H) throws Exception {
      int i = index;
      boolean result = false;
      if (alg.equals("ssh-rsa")) {
         this.type = 0;
         this.key_alg_name = alg;
         int j = K_S[i++] << 24 & 0xFF000000 | K_S[i++] << 16 & 0xFF0000 |
                 K_S[i++] << 8 & 0xFF00 | K_S[i++] & 0xFF;
         byte[] tmp = new byte[j];
         System.arraycopy(K_S, i, tmp, 0, j);
         i += j;
         byte[] ee = tmp;
         j = K_S[i++] << 24 & 0xFF000000 | K_S[i++] << 16 & 0xFF0000 |
                 K_S[i++] << 8 & 0xFF00 | K_S[i++] & 0xFF;
         tmp = new byte[j];
         System.arraycopy(K_S, i, tmp, 0, j);
         i += j;
         byte[] n = tmp;
         SignatureRSA sig = null;
         Buffer buf = new Buffer(sig_of_H);
         String foo = Util.byte2str(buf.getString());
         try {
            Class<? extends SignatureRSA> c =
                    Class.forName(Util.getConfig(foo)).asSubclass(SignatureRSA.class);
            sig = c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
            sig.init();
         } catch (Exception e) {
            throw new JSchException(e.toString(), e);
         }
         sig.setPubKey(ee, n);
         sig.update(this.H);
         result = sig.verify(sig_of_H);
      } else if (alg.equals("ssh-dss")) {
         byte[] q = null;
         this.type = 1;
         this.key_alg_name = alg;
         int j = K_S[i++] << 24 & 0xFF000000 | K_S[i++] << 16 & 0xFF0000 |
                 K_S[i++] << 8 & 0xFF00 | K_S[i++] & 0xFF;
         byte[] tmp = new byte[j];
         System.arraycopy(K_S, i, tmp, 0, j);
         i += j;
         byte[] p = tmp;
         j = K_S[i++] << 24 & 0xFF000000 | K_S[i++] << 16 & 0xFF0000 |
                 K_S[i++] << 8 & 0xFF00 | K_S[i++] & 0xFF;
         tmp = new byte[j];
         System.arraycopy(K_S, i, tmp, 0, j);
         i += j;
         q = tmp;
         j = K_S[i++] << 24 & 0xFF000000 | K_S[i++] << 16 & 0xFF0000 |
                 K_S[i++] << 8 & 0xFF00 | K_S[i++] & 0xFF;
         tmp = new byte[j];
         System.arraycopy(K_S, i, tmp, 0, j);
         i += j;
         byte[] g = tmp;
         j = K_S[i++] << 24 & 0xFF000000 | K_S[i++] << 16 & 0xFF0000 |
                 K_S[i++] << 8 & 0xFF00 | K_S[i++] & 0xFF;
         tmp = new byte[j];
         System.arraycopy(K_S, i, tmp, 0, j);
         i += j;
         byte[] f = tmp;
         SignatureDSA sig = null;
         try {
            Class<? extends SignatureDSA> c =
                    Class.forName(Util.getConfig("signature.dss")).asSubclass(SignatureDSA.class);
            sig = c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
            sig.init();
         } catch (Exception e) {
            throw new JSchException(e.toString(), e);
         }
         sig.setPubKey(f, p, q, g);
         sig.update(this.H);
         result = sig.verify(sig_of_H);
         System.out.println("ssh_dss_verify: signature " + result);
      } else if (alg.equals("ecdsa-sha2-nistp256") || alg.equals("ecdsa-sha2-nistp384") ||
              alg.equals("ecdsa-sha2-nistp521")) {
         this.type = 2;
         this.key_alg_name = alg;
         int j = K_S[i++] << 24 & 0xFF000000 | K_S[i++] << 16 & 0xFF0000 |
                 K_S[i++] << 8 & 0xFF00 | K_S[i++] & 0xFF;
         byte[] tmp = new byte[j];
         System.arraycopy(K_S, i, tmp, 0, j);
         i += j;
         j = K_S[i++] << 24 & 0xFF000000 | K_S[i++] << 16 & 0xFF0000 |
                 K_S[i++] << 8 & 0xFF00 | K_S[i++] & 0xFF;
         i++;
         tmp = new byte[(j - 1) / 2];
         System.arraycopy(K_S, i, tmp, 0, tmp.length);
         i += (j - 1) / 2;
         byte[] r = tmp;
         tmp = new byte[(j - 1) / 2];
         System.arraycopy(K_S, i, tmp, 0, tmp.length);
         i += (j - 1) / 2;
         byte[] s = tmp;
         SignatureECDSA sig = null;
         try {
            Class<? extends SignatureECDSA> c =
                    Class.forName(Util.getConfig(alg)).asSubclass(SignatureECDSA.class);
            sig = c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
            sig.init();
         } catch (Exception e) {
            throw new JSchException(e.toString(), e);
         }
         sig.setPubKey(r, s);
         sig.update(this.H);
         result = sig.verify(sig_of_H);
      } else if (alg.equals("ssh-ed25519") || alg.equals("ssh-ed448")) {
         this.type = 3;
         this.key_alg_name = alg;
         int j = K_S[i++] << 24 & 0xFF000000 | K_S[i++] << 16 & 0xFF0000 |
                 K_S[i++] << 8 & 0xFF00 | K_S[i++] & 0xFF;
         byte[] tmp = new byte[j];
         System.arraycopy(K_S, i, tmp, 0, j);
         i += j;
         SignatureEdDSA sig = null;
         try {
            Class<? extends SignatureEdDSA> c =
                    Class.forName(Util.getConfig(alg)).asSubclass(SignatureEdDSA.class);
            sig = c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
            sig.init();
         } catch (Exception|NoClassDefFoundError e) {
            throw new JSchException(e.toString(), e);
         }
         sig.setPubKey(tmp);
         sig.update(this.H);
         result = sig.verify(sig_of_H);
      } else {
         System.out.println("unknown alg: " + alg);
      }
      return result;
   }

   protected byte[] encodeAsMPInt(byte[] raw) {
      int i = (raw[0] & 0x80) >>> 7;
      int len = raw.length + i;
      byte[] foo = new byte[len + 4];
      byte[] bar = new byte[i ^ 0x1];
      foo[0] = (byte)(len >>> 24);
      foo[1] = (byte)(len >>> 16);
      foo[2] = (byte)(len >>> 8);
      foo[3] = (byte)len;
      System.arraycopy(raw, 0, foo, 4 + i, len - i);
      Util.bzero(raw);
      return foo;
   }

   protected byte[] encodeAsString(byte[] raw) {
      int len = raw.length;
      byte[] foo = new byte[len + 4];
      foo[0] = (byte)(len >>> 24);
      foo[1] = (byte)(len >>> 16);
      foo[2] = (byte)(len >>> 8);
      foo[3] = (byte)len;
      System.arraycopy(raw, 0, foo, 4, len);
      Util.bzero(raw);
      return foo;
   }
}
