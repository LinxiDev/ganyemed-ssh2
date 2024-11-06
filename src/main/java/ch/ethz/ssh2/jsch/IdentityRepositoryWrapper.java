package ch.ethz.ssh2.jsch;

import java.util.Vector;

class IdentityRepositoryWrapper implements IdentityRepository {
   private IdentityRepository ir;
   private Vector<Identity> cache;
   private boolean keep_in_cache;

   IdentityRepositoryWrapper(IdentityRepository ir) {
      this(ir, false);
   }

   IdentityRepositoryWrapper(IdentityRepository ir, boolean keep_in_cache) {
      this.cache = new Vector();
      this.keep_in_cache = false;
      this.ir = ir;
      this.keep_in_cache = keep_in_cache;
   }

   public String getName() {
      return this.ir.getName();
   }

   public int getStatus() {
      return this.ir.getStatus();
   }

   public boolean add(byte[] identity) {
      return this.ir.add(identity);
   }

   public boolean remove(byte[] blob) {
      return this.ir.remove(blob);
   }

   public void removeAll() {
      this.cache.removeAllElements();
      this.ir.removeAll();
   }

   public Vector<Identity> getIdentities() {
      Vector<Identity> result = new Vector();

      for(int i = 0; i < this.cache.size(); ++i) {
         Identity identity = (Identity)this.cache.elementAt(i);
         result.add(identity);
      }

      Vector<Identity> tmp = this.ir.getIdentities();

      for(int i = 0; i < tmp.size(); ++i) {
         result.add((Identity)tmp.elementAt(i));
      }

      return result;
   }

   void add(Identity identity) {
      if (!this.keep_in_cache && !identity.isEncrypted() && identity instanceof IdentityFile) {
         try {
            this.ir.add(((IdentityFile)identity).getKeyPair().forSSHAgent());
         } catch (Exception var3) {
         }
      } else {
         this.cache.addElement(identity);
      }

   }

   void check() {
      if (this.cache.size() > 0) {
         Object[] identities = this.cache.toArray();

         for(int i = 0; i < identities.length; ++i) {
            Identity identity = (Identity)identities[i];
            this.cache.removeElement(identity);
            this.add(identity);
         }
      }

   }
}
