package ch.ethz.ssh2.jsch;

public class JSchProxyException extends JSchException {
   private static final long serialVersionUID = -1L;

   public JSchProxyException(String s) {
      super(s);
   }

   public JSchProxyException(String s, Throwable e) {
      super(s, e);
   }
}
