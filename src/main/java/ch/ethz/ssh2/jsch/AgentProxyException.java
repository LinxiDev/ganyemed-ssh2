package ch.ethz.ssh2.jsch;

public class AgentProxyException extends Exception {
   private static final long serialVersionUID = -1L;

   public AgentProxyException(String message) {
      super(message);
   }

   public AgentProxyException(String message, Throwable e) {
      super(message, e);
   }
}
