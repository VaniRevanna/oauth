package be.nitroxis.oauth.util;

import java.util.Collection;
import java.util.HashSet;
import javax.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class Database {

  private final Collection<String> codes;

  private final Collection<String> tokens;

  public Database() {
    this.codes = new HashSet<>();
    this.tokens = new HashSet<>();
  }

  public void addCode(final String code) {
    codes.add(code);
  }

  public boolean isCodeValid(final String code) {
    return codes.contains(code);
  }

  public void addToken(final String token) {
    tokens.add(token);
  }

  public boolean isTokenValid(final String token) {
    return tokens.contains(token);
  }
}
