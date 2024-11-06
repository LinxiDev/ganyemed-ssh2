package ch.ethz.ssh2;

import java.io.IOException;
import java.io.OutputStream;

public class SFTPOutputStream extends OutputStream {
   private SFTPv3FileHandle handle;
   private long writeOffset = 0L;

   public SFTPOutputStream(SFTPv3FileHandle handle) {
      this.handle = handle;
   }

   public void write(byte[] buffer, int offset, int len) throws IOException {
      this.handle.getClient().write(this.handle, this.writeOffset, buffer, offset, len);
      this.writeOffset += (long)len;
   }

   public void write(int b) throws IOException {
      byte[] buffer = new byte[]{(byte)b};
      this.handle.getClient().write(this.handle, this.writeOffset, buffer, 0, 1);
      ++this.writeOffset;
   }

   public long skip(long n) {
      this.writeOffset += n;
      return n;
   }

   public void close() throws IOException {
      this.handle.getClient().closeFile(this.handle);
   }
}
