package be.nitroxis.oauth.util;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public final class CSRFTokenUtil {

  private final static String DEFAULT_PRNG = "SHA1PRNG";

  /**
   * Generates a random token used to protect against CSRF attacks with the a default cryptographic
   * strong pseudo-number random generator (SHA1PRNG).
   *
   * @return a random token
   * @throws NoSuchAlgorithmException if PRNG algorithm is not valid
   */
  public static String getToken() throws NoSuchAlgorithmException {
    return getToken(DEFAULT_PRNG);
  }

  /**
   * Generates a random token used to protect against CSRF attacks with a given cryptographic
   * pseudo-number random generator (SHA1PRNG).
   *
   * @param prng the given pseudo-random number generator
   * @return a random token
   * @throws NoSuchAlgorithmException if PRNG algorithm is not valid
   */
  public static String getToken(final String prng) throws NoSuchAlgorithmException {
    // FIXME check is the use of the secure random is correct
    SecureRandom sr = SecureRandom.getInstance(prng);

    return "" + sr.nextLong();
  }
}
