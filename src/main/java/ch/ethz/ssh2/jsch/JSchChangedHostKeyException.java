package ch.ethz.ssh2.jsch;

public class JSchChangedHostKeyException extends JSchHostKeyException {
   private static final long serialVersionUID = -1L;

   JSchChangedHostKeyException() {
   }

   JSchChangedHostKeyException(String s) {
      super(s);
   }
}
