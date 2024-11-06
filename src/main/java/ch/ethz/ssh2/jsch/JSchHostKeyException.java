package ch.ethz.ssh2.jsch;

public abstract class JSchHostKeyException extends JSchException {
   private static final long serialVersionUID = -1L;

   JSchHostKeyException() {
   }

   JSchHostKeyException(String s) {
      super(s);
   }
}
