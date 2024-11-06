package ch.ethz.ssh2.jsch;

public class JSchRevokedHostKeyException extends JSchHostKeyException {
   private static final long serialVersionUID = -1L;

   JSchRevokedHostKeyException() {
   }

   JSchRevokedHostKeyException(String s) {
      super(s);
   }
}
