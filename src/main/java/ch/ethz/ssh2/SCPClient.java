package ch.ethz.ssh2;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.UnsupportedCharsetException;

public class SCPClient {
   Connection conn;
   String charsetName = null;

   public void setCharset(String charset) throws IOException {
      if (charset == null) {
         this.charsetName = charset;
      } else {
         try {
            Charset.forName(charset);
         } catch (UnsupportedCharsetException var3) {
            throw new IOException("This charset is not supported", var3);
         }

         this.charsetName = charset;
      }
   }

   public String getCharset() {
      return this.charsetName;
   }

   public SCPClient(Connection conn) {
      if (conn == null) {
         throw new IllegalArgumentException("Cannot accept null argument!");
      } else {
         this.conn = conn;
      }
   }

   protected void readResponse(InputStream is) throws IOException {
      int c = is.read();
      if (c != 0) {
         if (c == -1) {
            throw new IOException("Remote scp terminated unexpectedly.");
         } else if (c != 1 && c != 2) {
            throw new IOException("Remote scp sent illegal error code.");
         } else if (c == 2) {
            throw new IOException("Remote scp terminated with error.");
         } else {
            String err = this.receiveLine(is);
            throw new IOException("Remote scp terminated with error (" + err + ").");
         }
      }
   }

   protected String receiveLine(InputStream is) throws IOException {
      StringBuilder sb = new StringBuilder(30);

      while(sb.length() <= 8192) {
         int c = is.read();
         if (c < 0) {
            throw new IOException("Remote scp terminated unexpectedly.");
         }

         if (c == 10) {
            return sb.toString();
         }

         sb.append((char)c);
      }

      throw new IOException("Remote scp sent a too long line");
   }

   protected SCPClient.LenNamePair parseCLine(String line) throws IOException {
      if (line.length() < 8) {
         throw new IOException("Malformed C line sent by remote SCP binary, line too short.");
      } else if (line.charAt(4) == ' ' && line.charAt(5) != ' ') {
         int length_name_sep = line.indexOf(32, 5);
         if (length_name_sep == -1) {
            throw new IOException("Malformed C line sent by remote SCP binary.");
         } else {
            String length_substring = line.substring(5, length_name_sep);
            String name_substring = line.substring(length_name_sep + 1);
            if (length_substring.length() > 0 && name_substring.length() > 0) {
               if (6 + length_substring.length() + name_substring.length() != line.length()) {
                  throw new IOException("Malformed C line sent by remote SCP binary.");
               } else {
                  long len;
                  try {
                     len = Long.parseLong(length_substring);
                  } catch (NumberFormatException var8) {
                     throw new IOException("Malformed C line sent by remote SCP binary, cannot parse file length.");
                  }

                  if (len < 0L) {
                     throw new IOException("Malformed C line sent by remote SCP binary, illegal file length.");
                  } else {
                     SCPClient.LenNamePair lnp = new SCPClient.LenNamePair();
                     lnp.length = len;
                     lnp.filename = name_substring;
                     return lnp;
                  }
               }
            } else {
               throw new IOException("Malformed C line sent by remote SCP binary.");
            }
         }
      } else {
         throw new IOException("Malformed C line sent by remote SCP binary.");
      }
   }

   public SCPOutputStream put(String remoteFile, long length, String remoteTargetDirectory, String mode) throws IOException {
      Session sess = null;
      if (remoteFile == null) {
         throw new IllegalArgumentException("Null argument.");
      } else {
         if (remoteTargetDirectory == null) {
            remoteTargetDirectory = "";
         }

         if (mode == null) {
            mode = "0600";
         }

         if (mode.length() != 4) {
            throw new IllegalArgumentException("Invalid mode.");
         } else {
            for(int i = 0; i < mode.length(); ++i) {
               if (!Character.isDigit(mode.charAt(i))) {
                  throw new IllegalArgumentException("Invalid mode.");
               }
            }

            remoteTargetDirectory = remoteTargetDirectory.length() > 0 ? remoteTargetDirectory : ".";
            String cmd = "scp -t -d \"" + remoteTargetDirectory + "\"";
            sess = this.conn.openSession();
            sess.execCommand(cmd, this.charsetName);
            return new SCPOutputStream(this, sess, remoteFile, length, mode);
         }
      }
   }

   public SCPInputStream get(String remoteFile) throws IOException {
      Session sess = null;
      if (remoteFile == null) {
         throw new IllegalArgumentException("Null argument.");
      } else if (remoteFile.length() == 0) {
         throw new IllegalArgumentException("Cannot accept empty filename.");
      } else {
         String cmd = "scp -f";
         cmd = cmd + " \"" + remoteFile + "\"";
         sess = this.conn.openSession();
         sess.execCommand(cmd, this.charsetName);
         return new SCPInputStream(this, sess);
      }
   }

   public class LenNamePair {
      public long length;
      String filename;
   }
}
