package ch.ethz.ssh2.jsch;

public class JSchException extends Exception {
   private static final long serialVersionUID = -1L;

   public JSchException() {
   }

   public JSchException(String s) {
      super(s);
   }

   public JSchException(String s, Throwable e) {
      super(s, e);
   }
}
