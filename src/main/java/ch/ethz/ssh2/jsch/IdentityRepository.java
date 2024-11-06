package ch.ethz.ssh2.jsch;

import java.util.Vector;

public interface IdentityRepository {
   int UNAVAILABLE = 0;
   int NOTRUNNING = 1;
   int RUNNING = 2;

   String getName();

   int getStatus();

   Vector<Identity> getIdentities();

   boolean add(byte[] var1);

   boolean remove(byte[] var1);

   void removeAll();
}
