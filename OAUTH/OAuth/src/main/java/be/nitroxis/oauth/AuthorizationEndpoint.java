package be.nitroxis.oauth;

import be.nitroxis.oauth.util.Database;
import java.net.URI;
import java.net.URISyntaxException;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuer;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuerImpl;
import org.apache.oltu.oauth2.as.issuer.UUIDValueGenerator;
import org.apache.oltu.oauth2.as.issuer.ValueGenerator;
import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.as.response.OAuthASResponse.OAuthAuthorizationResponseBuilder;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.apache.oltu.oauth2.common.message.types.ResponseType;

@Path("/authorize")
public class AuthorizationEndpoint {

  public static final long EXPIRATION_TIME = 3600L;

  @Inject
  private Database database;

  @GET
  public Response authorize(@Context final HttpServletRequest req)
    throws OAuthSystemException, OAuthProblemException, URISyntaxException {

    OAuthAuthzRequest request = new OAuthAuthzRequest(req);
    ValueGenerator generator = new UUIDValueGenerator();
    OAuthIssuer issuer = new OAuthIssuerImpl(generator);

    // Create response according to response type
    OAuthAuthorizationResponseBuilder builder =
      OAuthASResponse.authorizationResponse(req, HttpServletResponse.SC_FOUND);
    ResponseType type = ResponseType.valueOf(request.getParam(OAuth.OAUTH_RESPONSE_TYPE));

    switch (type) {
      case CODE:
        String code = issuer.authorizationCode();
        database.addCode(code);
        builder.setCode(code);
        break;

      case TOKEN:
        String token = issuer.accessToken();
        database.addToken(token);
        builder.setAccessToken(token);
        builder.setExpiresIn(EXPIRATION_TIME);
        break;

      default:
        throw OAuthProblemException.error("Unknown response type");
    }

    String uri = request.getParam(OAuth.OAUTH_REDIRECT_URI);
    OAuthResponse response = builder.location(uri).buildQueryMessage();
    URI url = new URI(response.getLocationUri());
    int status = response.getResponseStatus();

    return Response.status(status).location(url).build();
  }
}
