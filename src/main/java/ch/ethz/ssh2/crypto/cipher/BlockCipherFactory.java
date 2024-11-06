package ch.ethz.ssh2.crypto.cipher;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class BlockCipherFactory {
   private static final List<BlockCipherFactory.CipherEntry> ciphers = new ArrayList();

   static {
      ciphers.add(new BlockCipherFactory.CipherEntry("aes128-ctr", 16, 16, "ch.ethz.ssh2.crypto.cipher.AES"));
      ciphers.add(new BlockCipherFactory.CipherEntry("aes192-ctr", 16, 24, "ch.ethz.ssh2.crypto.cipher.AES"));
      ciphers.add(new BlockCipherFactory.CipherEntry("aes256-ctr", 16, 32, "ch.ethz.ssh2.crypto.cipher.AES"));
      ciphers.add(new BlockCipherFactory.CipherEntry("blowfish-ctr", 8, 16, "ch.ethz.ssh2.crypto.cipher.BlowFish"));
      ciphers.add(new BlockCipherFactory.CipherEntry("aes128-cbc", 16, 16, "ch.ethz.ssh2.crypto.cipher.AES"));
      ciphers.add(new BlockCipherFactory.CipherEntry("aes192-cbc", 16, 24, "ch.ethz.ssh2.crypto.cipher.AES"));
      ciphers.add(new BlockCipherFactory.CipherEntry("aes256-cbc", 16, 32, "ch.ethz.ssh2.crypto.cipher.AES"));
      ciphers.add(new BlockCipherFactory.CipherEntry("blowfish-cbc", 8, 16, "ch.ethz.ssh2.crypto.cipher.BlowFish"));
      ciphers.add(new BlockCipherFactory.CipherEntry("3des-ctr", 8, 24, "ch.ethz.ssh2.crypto.cipher.DESede"));
      ciphers.add(new BlockCipherFactory.CipherEntry("3des-cbc", 8, 24, "ch.ethz.ssh2.crypto.cipher.DESede"));
   }

   public static String[] getDefaultCipherList() {
      List<String> list = new ArrayList(ciphers.size());
      Iterator var2 = ciphers.iterator();

      while(var2.hasNext()) {
         BlockCipherFactory.CipherEntry ce = (BlockCipherFactory.CipherEntry)var2.next();
         list.add(ce.type);
      }

      return (String[])list.toArray(new String[ciphers.size()]);
   }

   public static void checkCipherList(String[] cipherCandidates) {
      String[] var4 = cipherCandidates;
      int var3 = cipherCandidates.length;

      for(int var2 = 0; var2 < var3; ++var2) {
         String cipherCandidate = var4[var2];
         getEntry(cipherCandidate);
      }

   }

   public static BlockCipher createCipher(String type, boolean encrypt, byte[] key, byte[] iv) {
      try {
         BlockCipherFactory.CipherEntry ce = getEntry(type);
         Class<?> cc = Class.forName(ce.cipherClass);
         BlockCipher bc = (BlockCipher)cc.newInstance();
         if (type.endsWith("-cbc")) {
            bc.init(encrypt, key);
            return new CBCMode(bc, iv, encrypt);
         } else if (type.endsWith("-ctr")) {
            bc.init(true, key);
            return new CTRMode(bc, iv, encrypt);
         } else {
            throw new IllegalArgumentException("Cannot instantiate " + type);
         }
      } catch (ClassNotFoundException var7) {
         throw new IllegalArgumentException("Cannot instantiate " + type, var7);
      } catch (InstantiationException var8) {
         throw new IllegalArgumentException("Cannot instantiate " + type, var8);
      } catch (IllegalAccessException var9) {
         throw new IllegalArgumentException("Cannot instantiate " + type, var9);
      }
   }

   private static BlockCipherFactory.CipherEntry getEntry(String type) {
      Iterator var2 = ciphers.iterator();

      while(var2.hasNext()) {
         BlockCipherFactory.CipherEntry ce = (BlockCipherFactory.CipherEntry)var2.next();
         if (ce.type.equals(type)) {
            return ce;
         }
      }

      throw new IllegalArgumentException("Unkown algorithm " + type);
   }

   public static int getBlockSize(String type) {
      BlockCipherFactory.CipherEntry ce = getEntry(type);
      return ce.blocksize;
   }

   public static int getKeySize(String type) {
      BlockCipherFactory.CipherEntry ce = getEntry(type);
      return ce.keysize;
   }

   private static final class CipherEntry {
      String type;
      int blocksize;
      int keysize;
      String cipherClass;

      public CipherEntry(String type, int blockSize, int keySize, String cipherClass) {
         this.type = type;
         this.blocksize = blockSize;
         this.keysize = keySize;
         this.cipherClass = cipherClass;
      }
   }
}
