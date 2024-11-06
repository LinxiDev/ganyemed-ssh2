package ch.ethz.ssh2.jsch;

import java.util.Vector;

public class AgentIdentityRepository implements IdentityRepository {
   private AgentProxy agent;

   public AgentIdentityRepository(AgentConnector connector) {
      this.agent = new AgentProxy(connector);
   }

   public Vector<Identity> getIdentities() {
      return this.agent.getIdentities();
   }

   public boolean add(byte[] identity) {
      return this.agent.addIdentity(identity);
   }

   public boolean remove(byte[] blob) {
      return this.agent.removeIdentity(blob);
   }

   public void removeAll() {
      this.agent.removeAllIdentities();
   }

   public String getName() {
      return this.agent.getConnector().getName();
   }

   public int getStatus() {
      return this.agent.getConnector().isAvailable() ? 2 : 1;
   }
}
