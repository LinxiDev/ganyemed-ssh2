package ch.ethz.ssh2.jsch;

public class JSchUnknownHostKeyException extends JSchHostKeyException {
   private static final long serialVersionUID = -1L;

   JSchUnknownHostKeyException() {
   }

   JSchUnknownHostKeyException(String s) {
      super(s);
   }
}
