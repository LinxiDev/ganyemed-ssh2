package ch.ethz.ssh2;

import java.io.IOException;

public class RequestMismatchException extends IOException {
   public RequestMismatchException() {
      super("The server sent an invalid id field.");
   }

   public RequestMismatchException(String message) {
      super(message);
   }
}
