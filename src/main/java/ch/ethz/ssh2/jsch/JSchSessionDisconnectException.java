package ch.ethz.ssh2.jsch;

public class JSchSessionDisconnectException extends JSchException {
   private static final long serialVersionUID = -1L;
   private final int reasonCode;
   private final String description;
   private final String languageTag;

   JSchSessionDisconnectException(String s, int reasonCode, String description, String languageTag) {
      super(s);
      this.reasonCode = reasonCode;
      this.description = description;
      this.languageTag = languageTag;
   }

   public int getReasonCode() {
      return this.reasonCode;
   }

   public String getDescription() {
      return this.description;
   }

   public String getLanguageTag() {
      return this.languageTag;
   }
}
