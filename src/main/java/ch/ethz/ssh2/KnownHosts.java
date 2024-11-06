package ch.ethz.ssh2;

import ch.ethz.ssh2.crypto.Base64;
import ch.ethz.ssh2.crypto.digest.Digest;
import ch.ethz.ssh2.crypto.digest.HMAC;
import ch.ethz.ssh2.crypto.digest.MD5;
import ch.ethz.ssh2.crypto.digest.SHA1;
import ch.ethz.ssh2.signature.DSAPublicKey;
import ch.ethz.ssh2.signature.DSASHA1Verify;
import ch.ethz.ssh2.signature.RSAPublicKey;
import ch.ethz.ssh2.signature.RSASHA1Verify;
import ch.ethz.ssh2.util.StringEncoder;
import java.io.BufferedReader;
import java.io.CharArrayReader;
import java.io.CharArrayWriter;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

public class KnownHosts {
   public static final int HOSTKEY_IS_OK = 0;

   public static final int HOSTKEY_IS_NEW = 1;

   public static final int HOSTKEY_HAS_CHANGED = 2;

   private class KnownHostsEntry {
      String[] patterns;

      Object key;

      KnownHostsEntry(String[] patterns, Object key) {
         this.patterns = patterns;
         this.key = key;
      }
   }

   private final LinkedList<KnownHostsEntry> publicKeys = new LinkedList<>();

   public KnownHosts() {}

   public KnownHosts(char[] knownHostsData) throws IOException {
      initialize(knownHostsData);
   }

   public KnownHosts(String knownHosts) throws IOException {
      initialize(new File(knownHosts));
   }

   public KnownHosts(File knownHosts) throws IOException {
      initialize(knownHosts);
   }

   public void addHostkey(String[] hostnames, String serverHostKeyAlgorithm, byte[] serverHostKey) throws IOException {
      if (hostnames == null)
         throw new IllegalArgumentException("hostnames may not be null");
      if ("ssh-rsa".equals(serverHostKeyAlgorithm)) {
         RSAPublicKey rpk = RSASHA1Verify.decodeSSHRSAPublicKey(serverHostKey);
         synchronized (this.publicKeys) {
            this.publicKeys.add(new KnownHostsEntry(hostnames, rpk));
         }
      } else if ("ssh-dss".equals(serverHostKeyAlgorithm)) {
         DSAPublicKey dpk = DSASHA1Verify.decodeSSHDSAPublicKey(serverHostKey);
         synchronized (this.publicKeys) {
            this.publicKeys.add(new KnownHostsEntry(hostnames, dpk));
         }
      } else {
         throw new IOException("Unknwon host key type (" + serverHostKeyAlgorithm + ")");
      }
   }

   public void addHostkeys(char[] knownHostsData) throws IOException {
      initialize(knownHostsData);
   }

   public void addHostkeys(File knownHosts) throws IOException {
      initialize(knownHosts);
   }

   public static String createHashedHostname(String hostname) {
      SHA1 sha1 = new SHA1();
      byte[] salt = new byte[sha1.getDigestLength()];
      (new SecureRandom()).nextBytes(salt);
      byte[] hash = hmacSha1Hash(salt, hostname);
      String base64_salt = new String(Base64.encode(salt));
      String base64_hash = new String(Base64.encode(hash));
      return new String("|1|" + base64_salt + "|" + base64_hash);
   }

   private static byte[] hmacSha1Hash(byte[] salt, String hostname) {
      SHA1 sha1 = new SHA1();
      if (salt.length != sha1.getDigestLength())
         throw new IllegalArgumentException("Salt has wrong length (" + salt.length + ")");
      HMAC hmac = new HMAC((Digest)sha1, salt, salt.length);
      hmac.update(StringEncoder.GetBytes(hostname));
      byte[] dig = new byte[hmac.getDigestLength()];
      hmac.digest(dig);
      return dig;
   }

   private boolean checkHashed(String entry, String hostname) {
      if (!entry.startsWith("|1|"))
         return false;
      int delim_idx = entry.indexOf('|', 3);
      if (delim_idx == -1)
         return false;
      String salt_base64 = entry.substring(3, delim_idx);
      String hash_base64 = entry.substring(delim_idx + 1);
      byte[] salt = null;
      byte[] hash = null;
      try {
         salt = Base64.decode(salt_base64.toCharArray());
         hash = Base64.decode(hash_base64.toCharArray());
      } catch (IOException e) {
         return false;
      }
      SHA1 sha1 = new SHA1();
      if (salt.length != sha1.getDigestLength())
         return false;
      byte[] dig = hmacSha1Hash(salt, hostname);
      for (int i = 0; i < dig.length; i++) {
         if (dig[i] != hash[i])
            return false;
      }
      return true;
   }

   private int checkKey(String remoteHostname, Object remoteKey) {
      int result = 1;
      synchronized (this.publicKeys) {
         for (KnownHostsEntry ke : this.publicKeys) {
            if (!hostnameMatches(ke.patterns, remoteHostname))
               continue;
            boolean res = matchKeys(ke.key, remoteKey);
            if (res)
               return 0;
            result = 2;
         }
      }
      return result;
   }

   private List<Object> getAllKeys(String hostname) {
      List<Object> keys = new ArrayList();
      synchronized (this.publicKeys) {
         for (KnownHostsEntry ke : this.publicKeys) {
            if (!hostnameMatches(ke.patterns, hostname))
               continue;
            keys.add(ke.key);
         }
      }
      return keys;
   }

   public String[] getPreferredServerHostkeyAlgorithmOrder(String hostname) {
      String[] algos = recommendHostkeyAlgorithms(hostname);
      if (algos != null)
         return algos;
      InetAddress[] ipAdresses = null;
      try {
         ipAdresses = InetAddress.getAllByName(hostname);
      } catch (UnknownHostException e) {
         return null;
      }
      for (int i = 0; i < ipAdresses.length; i++) {
         algos = recommendHostkeyAlgorithms(ipAdresses[i].getHostAddress());
         if (algos != null)
            return algos;
      }
      return null;
   }

   private boolean hostnameMatches(String[] hostpatterns, String hostname) {
      boolean isMatch = false;
      boolean negate = false;
      hostname = hostname.toLowerCase();
      for (int k = 0; k < hostpatterns.length; k++) {
         if (hostpatterns[k] != null) {
            String pattern = null;
            if (hostpatterns[k].length() > 0 && hostpatterns[k].charAt(0) == '!') {
               pattern = hostpatterns[k].substring(1);
               negate = true;
            } else {
               pattern = hostpatterns[k];
               negate = false;
            }
            if (!isMatch || negate)
               if (pattern.charAt(0) == '|') {
                  if (checkHashed(pattern, hostname)) {
                     if (negate)
                        return false;
                     isMatch = true;
                  }
               } else {
                  pattern = pattern.toLowerCase();
                  if (pattern.indexOf('?') != -1 || pattern.indexOf('*') != -1) {
                     if (pseudoRegex(pattern.toCharArray(), 0, hostname.toCharArray(), 0)) {
                        if (negate)
                           return false;
                        isMatch = true;
                     }
                  } else if (pattern.compareTo(hostname) == 0) {
                     if (negate)
                        return false;
                     isMatch = true;
                  }
               }
         }
      }
      return isMatch;
   }

   private void initialize(char[] knownHostsData) throws IOException {
      BufferedReader br = new BufferedReader(new CharArrayReader(knownHostsData));
      while (true) {
         String line = br.readLine();
         if (line == null)
            break;
         line = line.trim();
         if (line.startsWith("#"))
            continue;
         String[] arr = line.split(" ");
         if (arr.length >= 3)
            if (arr[1].compareTo("ssh-rsa") == 0 || arr[1].compareTo("ssh-dss") == 0) {
               String[] hostnames = arr[0].split(",");
               byte[] msg = Base64.decode(arr[2].toCharArray());
               try {
                  addHostkey(hostnames, arr[1], msg);
               } catch (IOException iOException) {}
            }
      }
   }

   private void initialize(File knownHosts) throws IOException {
      char[] buff = new char[512];
      CharArrayWriter cw = new CharArrayWriter();
      knownHosts.createNewFile();
      FileReader fr = new FileReader(knownHosts);
      while (true) {
         int len = fr.read(buff);
         if (len < 0)
            break;
         cw.write(buff, 0, len);
      }
      fr.close();
      initialize(cw.toCharArray());
   }

   private boolean matchKeys(Object key1, Object key2) {
      if (key1 instanceof RSAPublicKey && key2 instanceof RSAPublicKey) {
         RSAPublicKey savedRSAKey = (RSAPublicKey)key1;
         RSAPublicKey remoteRSAKey = (RSAPublicKey)key2;
         if (!savedRSAKey.getE().equals(remoteRSAKey.getE()))
            return false;
         if (!savedRSAKey.getN().equals(remoteRSAKey.getN()))
            return false;
         return true;
      }
      if (key1 instanceof DSAPublicKey && key2 instanceof DSAPublicKey) {
         DSAPublicKey savedDSAKey = (DSAPublicKey)key1;
         DSAPublicKey remoteDSAKey = (DSAPublicKey)key2;
         if (!savedDSAKey.getG().equals(remoteDSAKey.getG()))
            return false;
         if (!savedDSAKey.getP().equals(remoteDSAKey.getP()))
            return false;
         if (!savedDSAKey.getQ().equals(remoteDSAKey.getQ()))
            return false;
         if (!savedDSAKey.getY().equals(remoteDSAKey.getY()))
            return false;
         return true;
      }
      return false;
   }

   private boolean pseudoRegex(char[] pattern, int i, char[] match, int j) {
      while (true) {
         if (pattern.length == i)
            return (match.length == j);
         if (pattern[i] == '*') {
            i++;
            if (pattern.length == i)
               return true;
            if (pattern[i] != '*' && pattern[i] != '?') {
               do {
                  if (pattern[i] == match[j] && pseudoRegex(pattern, i + 1, match, j + 1))
                     return true;
                  j++;
               } while (match.length != j);
               return false;
            }
            do {
               if (pseudoRegex(pattern, i, match, j))
                  return true;
               j++;
            } while (match.length != j);
            return false;
         }
         if (match.length == j)
            return false;
         if (pattern[i] != '?' && pattern[i] != match[j])
            return false;
         i++;
         j++;
      }
   }

   private String[] recommendHostkeyAlgorithms(String hostname) {
      String preferredAlgo = null;
      List<Object> keys = getAllKeys(hostname);
      for (Object key : keys) {
         String thisAlgo = null;
         if (key instanceof RSAPublicKey) {
            thisAlgo = "ssh-rsa";
         } else if (key instanceof DSAPublicKey) {
            thisAlgo = "ssh-dss";
         } else {
            continue;
         }
         if (preferredAlgo != null) {
            if (preferredAlgo.compareTo(thisAlgo) != 0)
               return null;
            continue;
         }
         preferredAlgo = thisAlgo;
      }
      if (preferredAlgo == null)
         return null;
      if (preferredAlgo.equals("ssh-rsa"))
         return new String[] { "ssh-rsa", "ssh-dss" };
      return new String[] { "ssh-dss", "ssh-rsa" };
   }

   public int verifyHostkey(String hostname, String serverHostKeyAlgorithm, byte[] serverHostKey) throws IOException {
      Object remoteKey = null;
      if ("ssh-rsa".equals(serverHostKeyAlgorithm)) {
         remoteKey = RSASHA1Verify.decodeSSHRSAPublicKey(serverHostKey);
      } else if ("ssh-dss".equals(serverHostKeyAlgorithm)) {
         remoteKey = DSASHA1Verify.decodeSSHDSAPublicKey(serverHostKey);
      } else {
         throw new IllegalArgumentException("Unknown hostkey type " + serverHostKeyAlgorithm);
      }
      int result = checkKey(hostname, remoteKey);
      if (result == 0)
         return result;
      InetAddress[] ipAdresses = null;
      try {
         ipAdresses = InetAddress.getAllByName(hostname);
      } catch (UnknownHostException e) {
         return result;
      }
      for (int i = 0; i < ipAdresses.length; i++) {
         int newresult = checkKey(ipAdresses[i].getHostAddress(), remoteKey);
         if (newresult == 0)
            return newresult;
         if (newresult == 2)
            result = 2;
      }
      return result;
   }

   public static void addHostkeyToFile(File knownHosts, String[] hostnames, String serverHostKeyAlgorithm, byte[] serverHostKey) throws IOException {
      if (hostnames == null || hostnames.length == 0) {
         throw new IllegalArgumentException("Need at least one hostname specification");
      }
      if (serverHostKeyAlgorithm == null || serverHostKey == null) {
         throw new IllegalArgumentException();
      }
      CharArrayWriter writer = new CharArrayWriter();
      for (int i = 0; i < hostnames.length; i++) {
         if (i != 0) {
            writer.write(44);
         }
         writer.write(hostnames[i]);
      }
      writer.write(32);
      writer.write(serverHostKeyAlgorithm);
      writer.write(32);
      writer.write(Base64.encode(serverHostKey));
      writer.write("\n");
      char[] entry = writer.toCharArray();
      RandomAccessFile raf = new RandomAccessFile(knownHosts, "rw");
      long len = raf.length();
      if (len > 0) {
         raf.seek(len - 1);
         int last = raf.read();
         if (last != 10) {
            raf.write(10);
         }
      }
      raf.write(StringEncoder.GetBytes(new String(entry)));
      raf.close();
   }

   private static byte[] rawFingerPrint(String type, String keyType, byte[] hostkey) {
      Digest dig;
      if ("md5".equals(type)) {
         dig = new MD5();
      } else if ("sha1".equals(type)) {
         dig = new SHA1();
      } else {
         throw new IllegalArgumentException("Unknown hash type " + type);
      }
      if (!"ssh-rsa".equals(keyType) && !"ssh-dss".equals(keyType)) {
         throw new IllegalArgumentException("Unknown key type " + keyType);
      }
      if (hostkey == null) {
         throw new IllegalArgumentException("hostkey is null");
      }
      dig.update(hostkey);
      byte[] res = new byte[dig.getDigestLength()];
      dig.digest(res);
      return res;
   }



   private static String rawToHexFingerprint(byte[] fingerprint) {
      char[] alpha = "0123456789abcdef".toCharArray();
      StringBuilder sb = new StringBuilder();
      for (int i = 0; i < fingerprint.length; i++) {
         if (i != 0)
            sb.append(':');
         int b = fingerprint[i] & 0xFF;
         sb.append(alpha[b >> 4]);
         sb.append(alpha[b & 0xF]);
      }
      return sb.toString();
   }

   private static String rawToBubblebabbleFingerprint(byte[] raw) {
      char[] v = "aeiouy".toCharArray();
      char[] c = "bcdfghklmnprstvzx".toCharArray();
      StringBuilder sb = new StringBuilder();
      int seed = 1;
      int rounds = raw.length / 2 + 1;
      sb.append('x');
      for (int i = 0; i < rounds; i++) {
         if (i + 1 < rounds || raw.length % 2 != 0) {
            sb.append(v[((raw[2 * i] >> 6 & 0x3) + seed) % 6]);
            sb.append(c[raw[2 * i] >> 2 & 0xF]);
            sb.append(v[((raw[2 * i] & 0x3) + seed / 6) % 6]);
            if (i + 1 < rounds) {
               sb.append(c[raw[2 * i + 1] >> 4 & 0xF]);
               sb.append('-');
               sb.append(c[raw[2 * i + 1] & 0xF]);
               seed = (seed * 5 + (raw[2 * i] & 0xFF) * 7 + (raw[2 * i + 1] & 0xFF)) % 36;
            }
         } else {
            sb.append(v[seed % 6]);
            sb.append('x');
            sb.append(v[seed / 6]);
         }
      }
      sb.append('x');
      return sb.toString();
   }

   public static String createHexFingerprint(String keytype, byte[] publickey) {
      byte[] raw = rawFingerPrint("md5", keytype, publickey);
      return rawToHexFingerprint(raw);
   }

   public static String createBubblebabbleFingerprint(String keytype, byte[] publickey) {
      byte[] raw = rawFingerPrint("sha1", keytype, publickey);
      return rawToBubblebabbleFingerprint(raw);
   }
}
