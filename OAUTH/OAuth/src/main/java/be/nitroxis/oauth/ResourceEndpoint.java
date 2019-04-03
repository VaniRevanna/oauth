package be.nitroxis.oauth;

import be.nitroxis.oauth.util.Database;
import java.net.InetAddress;
import java.net.UnknownHostException;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import org.apache.oltu.oauth2.common.OAuth.HeaderType;
import org.apache.oltu.oauth2.common.error.OAuthError.ResourceResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.apache.oltu.oauth2.common.message.types.ParameterStyle;
import org.apache.oltu.oauth2.rs.request.OAuthAccessResourceRequest;
import org.apache.oltu.oauth2.rs.response.OAuthRSResponse;

@Path("/resource")
public class ResourceEndpoint {

    @Inject
    private Database database;

    @GET
    @Produces("text/html")
    public Response get(@Context final HttpServletRequest req)
      throws OAuthSystemException, OAuthProblemException, UnknownHostException {

      OAuthAccessResourceRequest request =
        new OAuthAccessResourceRequest(req, ParameterStyle.HEADER);
      String token = request.getAccessToken();
      boolean valid = database.isTokenValid(token);
      Response response;

      if (valid) {
        response = Response.status(Status.OK).entity("access_token_valid").build();
      } else {
        String name = InetAddress.getLocalHost().getHostName();
        OAuthResponse message = OAuthRSResponse
          .errorResponse(HttpServletResponse.SC_UNAUTHORIZED)
          .setRealm(name)
          .setError(ResourceResponse.INVALID_TOKEN)
          .buildHeaderMessage();
        response = Response
          .status(Status.UNAUTHORIZED)
          .header(HeaderType.WWW_AUTHENTICATE, message.getHeader(HeaderType.WWW_AUTHENTICATE))
          .build();
      }

      return response;
    }
}
