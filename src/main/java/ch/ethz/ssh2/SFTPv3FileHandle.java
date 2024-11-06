package ch.ethz.ssh2;

public class SFTPv3FileHandle {
   protected final SFTPv3Client client;
   protected final byte[] fileHandle;
   protected boolean isClosed;

   protected SFTPv3FileHandle(SFTPv3Client client, byte[] h) {
      this.client = client;
      this.fileHandle = h;
   }

   public SFTPv3Client getClient() {
      return this.client;
   }

   public boolean isClosed() {
      return this.isClosed;
   }
}
