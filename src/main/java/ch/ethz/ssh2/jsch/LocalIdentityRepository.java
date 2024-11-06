package ch.ethz.ssh2.jsch;

import java.util.Vector;

class LocalIdentityRepository implements IdentityRepository {
   private static final String name = "Local Identity Repository";
   private Vector<Identity> identities = new Vector();

   public String getName() {
      return "Local Identity Repository";
   }

   public int getStatus() {
      return 2;
   }

   public synchronized Vector<Identity> getIdentities() {
      this.removeDupulicates();
      Vector<Identity> v = new Vector();

      for(int i = 0; i < this.identities.size(); ++i) {
         v.addElement((Identity)this.identities.elementAt(i));
      }

      return v;
   }

   public synchronized void add(Identity identity) {
      if (!this.identities.contains(identity)) {
         byte[] blob1 = identity.getPublicKeyBlob();
         if (blob1 == null) {
            this.identities.addElement(identity);
            return;
         }

         int i = 0;

         while(true) {
            if (i >= this.identities.size()) {
               this.identities.addElement(identity);
               break;
            }

            byte[] blob2 = ((Identity)this.identities.elementAt(i)).getPublicKeyBlob();
            if (blob2 != null && Util.array_equals(blob1, blob2)) {
               if (identity.isEncrypted() || !((Identity)this.identities.elementAt(i)).isEncrypted()) {
                  return;
               }

               this.remove(blob2);
            }

            ++i;
         }
      }

   }

   public synchronized boolean add(byte[] identity) {
      try {
         Identity _identity = IdentityFile.newInstance("from remote:", identity, (byte[])null);
         this.add((Identity)_identity);
         return true;
      } catch (Exception var3) {
         return false;
      }
   }

   synchronized void remove(Identity identity) {
      if (this.identities.contains(identity)) {
         this.identities.removeElement(identity);
         identity.clear();
      } else {
         this.remove(identity.getPublicKeyBlob());
      }

   }

   public synchronized boolean remove(byte[] blob) {
      if (blob == null) {
         return false;
      } else {
         for(int i = 0; i < this.identities.size(); ++i) {
            Identity _identity = (Identity)this.identities.elementAt(i);
            byte[] _blob = _identity.getPublicKeyBlob();
            if (_blob != null && Util.array_equals(blob, _blob)) {
               this.identities.removeElement(_identity);
               _identity.clear();
               return true;
            }
         }

         return false;
      }
   }

   public synchronized void removeAll() {
      for(int i = 0; i < this.identities.size(); ++i) {
         Identity identity = (Identity)this.identities.elementAt(i);
         identity.clear();
      }

      this.identities.removeAllElements();
   }

   private void removeDupulicates() {
      Vector<byte[]> v = new Vector();
      int len = this.identities.size();
      if (len != 0) {
         int i;
         for(i = 0; i < len; ++i) {
            Identity foo = (Identity)this.identities.elementAt(i);
            byte[] foo_blob = foo.getPublicKeyBlob();
            if (foo_blob != null) {
               for(int j = i + 1; j < len; ++j) {
                  Identity bar = (Identity)this.identities.elementAt(j);
                  byte[] bar_blob = bar.getPublicKeyBlob();
                  if (bar_blob != null && Util.array_equals(foo_blob, bar_blob) && foo.isEncrypted() == bar.isEncrypted()) {
                     v.addElement(foo_blob);
                     break;
                  }
               }
            }
         }

         for(i = 0; i < v.size(); ++i) {
            this.remove((byte[])v.elementAt(i));
         }

      }
   }
}
