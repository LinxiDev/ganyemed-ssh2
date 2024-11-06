package ch.ethz.ssh2.jsch;

public class SftpException extends Exception {
   private static final long serialVersionUID = -1L;
   public int id;

   public SftpException(int id, String message) {
      super(message);
      this.id = id;
   }

   public SftpException(int id, String message, Throwable e) {
      super(message, e);
      this.id = id;
   }

   public String toString() {
      return this.id + ": " + this.getMessage();
   }
}
