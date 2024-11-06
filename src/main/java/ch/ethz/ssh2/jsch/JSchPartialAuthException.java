package ch.ethz.ssh2.jsch;

class JSchPartialAuthException extends JSchException {
   private static final long serialVersionUID = -1L;
   String methods;

   public JSchPartialAuthException() {
   }

   public JSchPartialAuthException(String s) {
      super(s);
      this.methods = s;
   }

   public String getMethods() {
      return this.methods;
   }
}
