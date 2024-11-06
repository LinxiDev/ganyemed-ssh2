package ch.ethz.ssh2.jsch;

import java.util.Locale;

public class HostKey {
   private static final byte[][] names = new byte[][]{Util.str2byte("ssh-dss"), Util.str2byte("ssh-rsa"), Util.str2byte("ecdsa-sha2-nistp256"), Util.str2byte("ecdsa-sha2-nistp384"), Util.str2byte("ecdsa-sha2-nistp521"), Util.str2byte("ssh-ed25519"), Util.str2byte("ssh-ed448")};
   public static final int UNKNOWN = -1;
   public static final int GUESS = 0;
   public static final int SSHDSS = 1;
   public static final int SSHRSA = 2;
   public static final int ECDSA256 = 3;
   public static final int ECDSA384 = 4;
   public static final int ECDSA521 = 5;
   public static final int ED25519 = 6;
   public static final int ED448 = 7;
   protected String marker;
   protected String host;
   protected int type;
   protected byte[] key;
   protected String comment;

   public HostKey(String host, byte[] key) throws JSchException {
      this(host, 0, key);
   }

   public HostKey(String host, int type, byte[] key) throws JSchException {
      this(host, type, key, (String)null);
   }

   public HostKey(String host, int type, byte[] key, String comment) throws JSchException {
      this("", host, type, key, comment);
   }

   public HostKey(String marker, String host, int type, byte[] key, String comment) throws JSchException {
      this.marker = marker;
      this.host = host;
      if (type == 0) {
         if (key[8] == 100) {
            this.type = 1;
         } else if (key[8] == 114) {
            this.type = 2;
         } else if (key[8] == 101 && key[10] == 50) {
            this.type = 6;
         } else if (key[8] == 101 && key[10] == 52) {
            this.type = 7;
         } else if (key[8] == 97 && key[20] == 50) {
            this.type = 3;
         } else if (key[8] == 97 && key[20] == 51) {
            this.type = 4;
         } else {
            if (key[8] != 97 || key[20] != 53) {
               throw new JSchException("invalid key type");
            }

            this.type = 5;
         }
      } else {
         this.type = type;
      }

      this.key = key;
      this.comment = comment;
   }

   public String getHost() {
      return this.host;
   }

   public String getType() {
      return this.type != 1 && this.type != 2 && this.type != 6 && this.type != 7 && this.type != 3 && this.type != 4 && this.type != 5 ? "UNKNOWN" : Util.byte2str(names[this.type - 1]);
   }

   protected static int name2type(String name) {
      for(int i = 0; i < names.length; ++i) {
         if (Util.byte2str(names[i]).equals(name)) {
            return i + 1;
         }
      }

      return -1;
   }

   public String getKey() {
      return Util.byte2str(Util.toBase64(this.key, 0, this.key.length, true));
   }

   public String getFingerPrint() {
      HASH hash = null;

      try {
         String _c = Util.getConfig("FingerprintHash").toLowerCase(Locale.ROOT);
         Class<? extends HASH> c = Class.forName(Util.getConfig(_c)).asSubclass(HASH.class);
         hash = (HASH)c.getDeclaredConstructor().newInstance();
      } catch (Exception var4) {
         var4.printStackTrace();
      }

      return Util.getFingerPrint(hash, this.key, false, true);
   }

   public String getComment() {
      return this.comment;
   }

   public String getMarker() {
      return this.marker;
   }

   boolean isMatched(String _host) {
      return this.isIncluded(_host);
   }

   private boolean isIncluded(String _host) {
      int i = 0;
      String hosts = this.host;
      int hostslen = hosts.length();

      int j;
      for(int hostlen = _host.length(); i < hostslen; i = j + 1) {
         j = hosts.indexOf(44, i);
         if (j == -1) {
            if (hostlen != hostslen - i) {
               return false;
            }

            return hosts.regionMatches(true, i, _host, 0, hostlen);
         }

         if (hostlen == j - i && hosts.regionMatches(true, i, _host, 0, hostlen)) {
            return true;
         }
      }

      return false;
   }
}
