package ch.ethz.ssh2.jsch;

class JSchAuthCancelException extends JSchException {
   private static final long serialVersionUID = -1L;
   String method;

   JSchAuthCancelException() {
   }

   JSchAuthCancelException(String s) {
      super(s);
      this.method = s;
   }

   public String getMethod() {
      return this.method;
   }
}
