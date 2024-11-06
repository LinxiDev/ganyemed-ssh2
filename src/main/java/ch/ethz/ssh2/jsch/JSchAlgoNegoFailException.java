package ch.ethz.ssh2.jsch;

import java.util.Locale;

public class JSchAlgoNegoFailException extends JSchException {
   private static final long serialVersionUID = -1L;
   private final String algorithmName;
   private final String jschProposal;
   private final String serverProposal;

   JSchAlgoNegoFailException(int algorithmIndex, String jschProposal, String serverProposal) {
      super(failString(algorithmIndex, jschProposal, serverProposal));
      this.algorithmName = algorithmNameFromIndex(algorithmIndex);
      this.jschProposal = jschProposal;
      this.serverProposal = serverProposal;
   }

   public String getAlgorithmName() {
      return this.algorithmName;
   }

   public String getJSchProposal() {
      return this.jschProposal;
   }

   public String getServerProposal() {
      return this.serverProposal;
   }

   private static String failString(int algorithmIndex, String jschProposal, String serverProposal) {
      return String.format(Locale.ROOT, "Algorithm negotiation fail: algorithmName=\"%s\" jschProposal=\"%s\" serverProposal=\"%s\"", algorithmNameFromIndex(algorithmIndex), jschProposal, serverProposal);
   }

   private static String algorithmNameFromIndex(int algorithmIndex) {
      switch(algorithmIndex) {
      case 0:
         return "kex";
      case 1:
         return "server_host_key";
      case 2:
         return "cipher.c2s";
      case 3:
         return "cipher.s2c";
      case 4:
         return "mac.c2s";
      case 5:
         return "mac.s2c";
      case 6:
         return "compression.c2s";
      case 7:
         return "compression.s2c";
      case 8:
         return "lang.c2s";
      case 9:
         return "lang.s2c";
      default:
         return "";
      }
   }
}
