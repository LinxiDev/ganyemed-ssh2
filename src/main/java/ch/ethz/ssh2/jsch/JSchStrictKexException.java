package ch.ethz.ssh2.jsch;

public class JSchStrictKexException extends JSchException {
   private static final long serialVersionUID = -1L;

   JSchStrictKexException() {
   }

   JSchStrictKexException(String s) {
      super(s);
   }
}
