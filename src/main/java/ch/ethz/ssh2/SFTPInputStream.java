package ch.ethz.ssh2;

import java.io.IOException;
import java.io.InputStream;

public class SFTPInputStream extends InputStream {
   private SFTPv3FileHandle handle;
   private long readOffset = 0L;

   public SFTPInputStream(SFTPv3FileHandle handle) {
      this.handle = handle;
   }

   public int read(byte[] buffer, int offset, int len) throws IOException {
      int read = this.handle.getClient().read(this.handle, this.readOffset, buffer, offset, len);
      if (read > 0) {
         this.readOffset += (long)read;
      }

      return read;
   }

   public int read() throws IOException {
      byte[] buffer = new byte[1];
      int b = this.handle.getClient().read(this.handle, this.readOffset, buffer, 0, 1);
      if (b > 0) {
         ++this.readOffset;
      }

      return b;
   }

   public long skip(long n) {
      this.readOffset += n;
      return n;
   }

   public void close() throws IOException {
      this.handle.getClient().closeFile(this.handle);
   }
}
