package ch.ethz.ssh2.crypto;

import java.io.IOException;

public class PEMDecryptException extends IOException {
   private static final long serialVersionUID = 1L;

   public PEMDecryptException(String message) {
      super(message);
   }
}
