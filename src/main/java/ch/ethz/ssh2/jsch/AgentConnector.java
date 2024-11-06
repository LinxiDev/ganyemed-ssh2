package ch.ethz.ssh2.jsch;

public interface AgentConnector {
   String getName();

   boolean isAvailable();

   void query(Buffer var1) throws AgentProxyException;
}
