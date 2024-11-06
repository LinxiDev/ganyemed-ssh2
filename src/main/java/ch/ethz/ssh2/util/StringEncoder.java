package ch.ethz.ssh2.util;

import java.io.UnsupportedEncodingException;

public class StringEncoder {
   public static byte[] GetBytes(String data) {
      try {
         return data.getBytes("UTF-8");
      } catch (UnsupportedEncodingException var2) {
         throw new RuntimeException(var2);
      }
   }

   public static String GetString(byte[] data) {
      return GetString(data, 0, data.length);
   }

   public static String GetString(byte[] data, int off, int len) {
      try {
         return new String(data, off, len, "UTF-8");
      } catch (UnsupportedEncodingException var4) {
         throw new RuntimeException(var4);
      }
   }
}
