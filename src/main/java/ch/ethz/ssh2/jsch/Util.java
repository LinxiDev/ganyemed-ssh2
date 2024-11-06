package ch.ethz.ssh2.jsch;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Vector;

class Util {
   private static final byte[] b64 = str2byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=");

   private static byte val(byte foo) {
      if (foo == 61)
         return 0;
      for (int j = 0; j < b64.length; j++) {
         if (foo == b64[j])
            return (byte)j;
      }
      return 0;
   }

   public static boolean checkCipher(String cipher) {
      try {
         Class<? extends Cipher> c = Class.forName(cipher).asSubclass(Cipher.class);
         Cipher _c = c.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
         _c.init(0, new byte[_c.getBlockSize()], new byte[_c.getIVSize()]);
         return true;
      } catch (Exception|NoClassDefFoundError e) {
         return false;
      }
   }

   static byte[] fromBase64(byte[] buf, int start, int length) throws JSchException {
      try {
         byte[] foo = new byte[length];
         int j = 0;
         for (int i = start; i < start + length; i += 4) {
            foo[j] = (byte)(val(buf[i]) << 2 | (val(buf[i + 1]) & 0x30) >>> 4);
            if (buf[i + 2] == 61) {
               j++;
               break;
            }
            foo[j + 1] = (byte)((val(buf[i + 1]) & 0xF) << 4 | (val(buf[i + 2]) & 0x3C) >>> 2);
            if (buf[i + 3] == 61) {
               j += 2;
               break;
            }
            foo[j + 2] = (byte)((val(buf[i + 2]) & 0x3) << 6 | val(buf[i + 3]) & 0x3F);
            j += 3;
         }
         byte[] bar = new byte[j];
         System.arraycopy(foo, 0, bar, 0, j);
         return bar;
      } catch (ArrayIndexOutOfBoundsException e) {
         throw new JSchException("fromBase64: invalid base64 data", e);
      }
   }

   static byte[] toBase64(byte[] buf, int start, int length, boolean include_pad) {
      byte[] tmp = new byte[length * 2];
      int foo = length / 3 * 3 + start;
      int i = 0;
      int j;
      for (j = start; j < foo; j += 3) {
         int k = buf[j] >>> 2 & 0x3F;
         tmp[i++] = b64[k];
         k = (buf[j] & 0x3) << 4 | buf[j + 1] >>> 4 & 0xF;
         tmp[i++] = b64[k];
         k = (buf[j + 1] & 0xF) << 2 | buf[j + 2] >>> 6 & 0x3;
         tmp[i++] = b64[k];
         k = buf[j + 2] & 0x3F;
         tmp[i++] = b64[k];
      }
      foo = start + length - foo;
      if (foo == 1) {
         int k = buf[j] >>> 2 & 0x3F;
         tmp[i++] = b64[k];
         k = (buf[j] & 0x3) << 4 & 0x3F;
         tmp[i++] = b64[k];
         if (include_pad) {
            tmp[i++] = 61;
            tmp[i++] = 61;
         }
      } else if (foo == 2) {
         int k = buf[j] >>> 2 & 0x3F;
         tmp[i++] = b64[k];
         k = (buf[j] & 0x3) << 4 | buf[j + 1] >>> 4 & 0xF;
         tmp[i++] = b64[k];
         k = (buf[j + 1] & 0xF) << 2 & 0x3F;
         tmp[i++] = b64[k];
         if (include_pad)
            tmp[i++] = 61;
      }
      byte[] bar = new byte[i];
      System.arraycopy(tmp, 0, bar, 0, i);
      return bar;
   }

   static String[] split(String foo, String split) {
      if (foo == null)
         return null;
      byte[] buf = str2byte(foo);
      Vector<String> bar = new Vector<>();
      int start = 0;
      while (true) {
         int index = foo.indexOf(split, start);
         if (index >= 0) {
            bar.addElement(byte2str(buf, start, index - start));
            start = index + 1;
            continue;
         }
         break;
      }
      bar.addElement(byte2str(buf, start, buf.length - start));
      String[] result = new String[bar.size()];
      for (int i = 0; i < result.length; i++)
         result[i] = bar.elementAt(i);
      return result;
   }

   static boolean glob(byte[] pattern, byte[] name) {
      return glob0(pattern, 0, name, 0);
   }

   private static boolean glob0(byte[] pattern, int pattern_index, byte[] name, int name_index) {
      if (name.length > 0 && name[0] == 46) {
         if (pattern.length > 0 && pattern[0] == 46) {
            if (pattern.length == 2 && pattern[1] == 42)
               return true;
            return glob(pattern, pattern_index + 1, name, name_index + 1);
         }
         return false;
      }
      return glob(pattern, pattern_index, name, name_index);
   }

   private static boolean glob(byte[] pattern, int pattern_index, byte[] name, int name_index) {
      int patternlen = pattern.length;
      if (patternlen == 0)
         return false;
      int namelen = name.length;
      int i = pattern_index;
      int j = name_index;
      while (i < patternlen && j < namelen) {
         if (pattern[i] == 92) {
            if (i + 1 == patternlen)
               return false;
            i++;
            if (pattern[i] != name[j])
               return false;
            i += skipUTF8Char(pattern[i]);
            j += skipUTF8Char(name[j]);
            continue;
         }
         if (pattern[i] == 42) {
            while (i < patternlen &&
                    pattern[i] == 42)
               i++;
            if (patternlen == i)
               return true;
            byte foo = pattern[i];
            if (foo == 63) {
               while (j < namelen) {
                  if (glob(pattern, i, name, j))
                     return true;
                  j += skipUTF8Char(name[j]);
               }
               return false;
            }
            if (foo == 92) {
               if (i + 1 == patternlen)
                  return false;
               i++;
               foo = pattern[i];
               while (j < namelen) {
                  if (foo == name[j] &&
                          glob(pattern, i + skipUTF8Char(foo), name, j + skipUTF8Char(name[j])))
                     return true;
                  j += skipUTF8Char(name[j]);
               }
               return false;
            }
            while (j < namelen) {
               if (foo == name[j] &&
                       glob(pattern, i, name, j))
                  return true;
               j += skipUTF8Char(name[j]);
            }
            return false;
         }
         if (pattern[i] == 63) {
            i++;
            j += skipUTF8Char(name[j]);
            continue;
         }
         if (pattern[i] != name[j])
            return false;
         i += skipUTF8Char(pattern[i]);
         j += skipUTF8Char(name[j]);
         if (j >= namelen) {
            if (i >= patternlen)
               return true;
            if (pattern[i] == 42)
               break;
         }
      }
      if (i == patternlen && j == namelen)
         return true;
      if (j >= namelen &&
              pattern[i] == 42) {
         boolean ok = true;
         while (i < patternlen) {
            if (pattern[i++] != 42) {
               ok = false;
               break;
            }
         }
         return ok;
      }
      return false;
   }

   static String quote(String path) {
      byte[] _path = str2byte(path);
      int count = 0;
      for (int i = 0; i < _path.length; i++) {
         byte b = _path[i];
         if (b == 92 || b == 63 || b == 42)
            count++;
      }
      if (count == 0)
         return path;
      byte[] _path2 = new byte[_path.length + count];
      for (int k = 0, j = 0; k < _path.length; k++) {
         byte b = _path[k];
         if (b == 92 || b == 63 || b == 42)
            _path2[j++] = 92;
         _path2[j++] = b;
      }
      return byte2str(_path2);
   }

   static String unquote(String path) {
      byte[] foo = str2byte(path);
      byte[] bar = unquote(foo);
      if (foo.length == bar.length)
         return path;
      return byte2str(bar);
   }

   static byte[] unquote(byte[] path) {
      int pathlen = path.length;
      int i = 0;
      while (i < pathlen) {
         if (path[i] == 92) {
            if (i + 1 == pathlen)
               break;
            System.arraycopy(path, i + 1, path, i, path.length - i + 1);
            pathlen--;
            i++;
            continue;
         }
         i++;
      }
      if (pathlen == path.length)
         return path;
      byte[] foo = new byte[pathlen];
      System.arraycopy(path, 0, foo, 0, pathlen);
      return foo;
   }

   private static String[] chars = new String[] {
           "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
           "a", "b", "c", "d", "e", "f" };

   static String getFingerPrint(HASH hash, byte[] data, boolean include_prefix, boolean force_hex) {
      try {
         hash.init();
         hash.update(data, 0, data.length);
         byte[] foo = hash.digest();
         StringBuilder sb = new StringBuilder();
         if (include_prefix) {
            sb.append(hash.name());
            sb.append(":");
         }
         if (force_hex || hash.name().equals("MD5")) {
            for (int i = 0; i < foo.length; i++) {
               int bar = foo[i] & 0xFF;
               sb.append(chars[bar >>> 4 & 0xF]);
               sb.append(chars[bar & 0xF]);
               if (i + 1 < foo.length)
                  sb.append(":");
            }
         } else {
            byte[] b64str = toBase64(foo, 0, foo.length, false);
            sb.append(byte2str(b64str, 0, b64str.length));
         }
         return sb.toString();
      } catch (Exception e) {
         return "???";
      }
   }

   static boolean array_equals(byte[] foo, byte[] bar) {
      int i = foo.length;
      if (i != bar.length)
         return false;
      for (int j = 0; j < i; j++) {
         if (foo[j] != bar[j])
            return false;
      }
      return true;
   }

   static Socket createSocket(String host, int port, int timeout) throws JSchException {
      Socket socket = new Socket();
      try {
         socket.connect(new InetSocketAddress(host, port), timeout);
         return socket;
      } catch (Exception e) {
         try {
            socket.close();
         } catch (Exception exception) {}
         String message =
                 (e instanceof java.net.SocketTimeoutException) ? "timeout: socket is not established" : e.toString();
         throw new JSchException(message, e);
      }
   }

   static byte[] str2byte(String str, Charset encoding) {
      if (str == null)
         return null;
      return str.getBytes(encoding);
   }

   static byte[] str2byte(String str) {
      return str2byte(str, StandardCharsets.UTF_8);
   }

   static String byte2str(byte[] str, Charset encoding) {
      return byte2str(str, 0, str.length, encoding);
   }

   static String byte2str(byte[] str, int s, int l, Charset encoding) {
      return new String(str, s, l, encoding);
   }

   static String byte2str(byte[] str) {
      return byte2str(str, 0, str.length, StandardCharsets.UTF_8);
   }

   static String byte2str(byte[] str, int s, int l) {
      return byte2str(str, s, l, StandardCharsets.UTF_8);
   }

   static String toHex(byte[] str) {
      StringBuilder sb = new StringBuilder();
      for (int i = 0; i < str.length; i++) {
         String foo = Integer.toHexString(str[i] & 0xFF);
         sb.append("0x" + ((foo.length() == 1) ? "0" : "") + foo);
         if (i + 1 < str.length)
            sb.append(":");
      }
      return sb.toString();
   }

   static final byte[] empty = str2byte("");

   static void bzero(byte[] foo) {
      if (foo == null)
         return;
      for (int i = 0; i < foo.length; i++)
         foo[i] = 0;
   }

   static String diffString(String str, String[] not_available) {
      String[] stra = split(str, ",");
      String result = null;
      for (int i = 0; i < stra.length; i++) {
         int j = 0;
         while (true) {
            if (j < not_available.length) {
               if (stra[i].equals(not_available[j])) {
                  break;
               }
               j++;
            } else if (result == null) {
               result = stra[i];
            } else {
               result = String.valueOf(result) + "," + stra[i];
            }
         }
      }
      return result;
   }


   static String checkTilde(String str) {
      try {
         if (str.startsWith("~"))
            str = str.replace("~", System.getProperty("user.home"));
      } catch (SecurityException securityException) {}
      return str;
   }

   private static int skipUTF8Char(byte b) {
      if ((byte)(b & 0x80) == 0)
         return 1;
      if ((byte)(b & 0xE0) == -64)
         return 2;
      if ((byte)(b & 0xF0) == -32)
         return 3;
      return 1;
   }

   static byte[] fromFile(String _file) throws Throwable {
      String _file2 = checkTilde(_file);
      File file = new File(_file2);
      Throwable th = null;
      try {
         InputStream fis = new FileInputStream(_file2);
         byte[] result = new byte[(int) file.length()];
         int len = 0;
         while (true) {
            int i = fis.read(result, len, result.length - len);
            if (i <= 0) {
               break;
            }
            len += i;
         }
         if (fis != null) {
            fis.close();
         }
         return result;
      } catch (Throwable th2) {
         if (0 == 0) {
            th = th2;
         } else if (null != th2) {
            th.addSuppressed(th2);
         }
         throw th;
      }
   }

   static boolean arraysequals(byte[] a, byte[] b) {
      if (a.length != b.length)
         return false;
      int res = 0;
      for (int i = 0; i < a.length; i++)
         res |= a[i] ^ b[i];
      return (res == 0);
   }

   static String getSystemEnv(String name) {
      try {
         return System.getenv(name);
      } catch (SecurityException e) {
         return null;
      }
   }

   static String getSystemProperty(String key) {
      try {
         return System.getProperty(key);
      } catch (SecurityException e) {
         return null;
      }
   }

   static String getSystemProperty(String key, String def) {
      try {
         return System.getProperty(key, def);
      } catch (SecurityException e) {
         return def;
      }
   }

   public static String getConfig(String key) {
      synchronized (KeyPair.config) {
         if (key.equals("PubkeyAcceptedKeyTypes"))
            key = "PubkeyAcceptedAlgorithms";
         return KeyPair.config.get(key);
      }
   }
}
