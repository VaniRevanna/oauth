package be.nitroxis.oauth;

import be.nitroxis.oauth.util.Database;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuer;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuerImpl;
import org.apache.oltu.oauth2.as.issuer.UUIDValueGenerator;
import org.apache.oltu.oauth2.as.issuer.ValueGenerator;
import org.apache.oltu.oauth2.as.request.OAuthTokenRequest;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.error.OAuthError.TokenResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.apache.oltu.oauth2.common.message.types.GrantType;

@Path("/token")
public class TokenEndpoint {

  @Inject
  private Database database;

  @POST
  @Consumes("application/x-www-form-urlencoded")
  @Produces("application/json")
  public Response authorize(@Context final HttpServletRequest req)
    throws OAuthSystemException, OAuthProblemException {

    OAuthTokenRequest request = new OAuthTokenRequest(req);
    ValueGenerator generator = new UUIDValueGenerator();
    OAuthIssuer issuer = new OAuthIssuerImpl(generator);
    ResponseFactory factory = new ResponseFactory(request, issuer, database);

    return factory.newInstance();
  }
}

class ResponseFactory {

  interface ResponseBuilder {

    Response build() throws OAuthSystemException;
  }

  private final OAuthTokenRequest request;

  private final Database database;

  private final OAuthIssuer issuer;

  public ResponseFactory(
    final OAuthTokenRequest request,
    final OAuthIssuer issuer,
    final Database database) {

    this.request = request;
    this.issuer = issuer;
    this.database = database;
  }

  Response newInstance() throws OAuthSystemException {
    ResponseBuilder builder;

    String id = request.getClientId();
    String secret = request.getClientSecret();
    GrantType type = GrantType.valueOf(request.getParam(OAuth.OAUTH_GRANT_TYPE));
    String code = request.getParam(OAuth.OAUTH_CODE);

    if (!checkClientId(id)) {
      builder = new InvalidClientResponseBuilder(
        HttpServletResponse.SC_BAD_REQUEST,
        TokenResponse.INVALID_CLIENT,
        "Client authentication failed"
      );
    } else if (!checkClientSecret(secret)) {
      builder = new InvalidClientResponseBuilder(
        HttpServletResponse.SC_UNAUTHORIZED,
        TokenResponse.UNAUTHORIZED_CLIENT,
        "Client authentication failed"
      );
    } else if (GrantType.AUTHORIZATION_CODE.equals(type) && !isAuthCodeValid(code)) {
      builder = new InvalidClientResponseBuilder(
        HttpServletResponse.SC_BAD_REQUEST,
        TokenResponse.INVALID_GRANT,
        "invalid authorization code"
      );
    } else if (GrantType.REFRESH_TOKEN.equals(type)) {
      // FIXME refresh token is not supported in this implementation
      builder = new InvalidClientResponseBuilder(
        HttpServletResponse.SC_BAD_REQUEST,
        TokenResponse.UNSUPPORTED_GRANT_TYPE,
        "Unsupported refresh token"
      );
    } else {
      builder = new AccessTokenResponseBuilder(issuer, database);
    }

    return builder.build();
  }

  protected boolean checkClientId(final String id) {
    // FIXME use a client identifier while building a registration step
    return true;
  }

  protected boolean checkClientSecret(final String secret) {
    // FIXME add some client secret check that should have been exchanged at registration time
    return true;
  }

  protected boolean isAuthCodeValid(final String code) {
    return database.isCodeValid(code);
  }
}

class InvalidClientResponseBuilder implements ResponseFactory.ResponseBuilder {

  private final int httpResponseCode;

  private final String oAuthTokenResponse;

  private final String description;

  InvalidClientResponseBuilder(
    final int httpResponseCode,
    final String oAuthTokenResponse,
    final String description) {

    this.httpResponseCode = httpResponseCode;
    this.oAuthTokenResponse = oAuthTokenResponse;
    this.description = description;
  }

  @Override
  public Response build() throws OAuthSystemException {
    OAuthResponse response = OAuthASResponse.errorResponse(httpResponseCode)
      .setError(oAuthTokenResponse)
      .setErrorDescription(description)
      .buildJSONMessage();
    int status = response.getResponseStatus();
    String body = response.getBody();

    return Response.status(status).entity(body).build();
  }
}

class AccessTokenResponseBuilder implements ResponseFactory.ResponseBuilder {

  private final Database database;

  private final OAuthIssuer issuer;

  AccessTokenResponseBuilder(final OAuthIssuer issuer, final Database database) {
    this.issuer = issuer;
    this.database = database;
  }

  @Override
  public Response build() throws OAuthSystemException {
    String token = issuer.accessToken();
    database.addToken(token);

    OAuthResponse response = OAuthASResponse.tokenResponse(HttpServletResponse.SC_OK)
      .setAccessToken(token)
      .setExpiresIn("3600")
      .buildJSONMessage();
    int status = response.getResponseStatus();
    String body = response.getBody();

    return Response.status(status).entity(body).build();
  }
}
