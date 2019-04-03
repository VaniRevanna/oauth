package be.nitroxis.oauth;

import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.UriInfo;
import org.json.JSONException;
import org.json.JSONObject;

@Path("/redirect")
public class RedirectEndpoint {

    private static final Logger LOGGER = Logger.getLogger(RedirectEndpoint.class.getName());

    @Context
    private HttpHeaders headers;

    @Context
    private UriInfo info;

    @GET
    public String redirect() {
        JSONObject object = new JSONObject();
        JSONObject headers = new JSONObject();
        JSONObject parameters = new JSONObject();
        String json;

        try {
          // Headers
          MultivaluedMap<String, String> h = this.headers.getRequestHeaders();

          for (final Map.Entry<String, List<String>> entry : h.entrySet()) {
            headers.put(entry.getKey(), entry.getValue().get(0));
          }

          object.put("headers", headers);

          // Query parameters
          MultivaluedMap<String, String> params = info.getQueryParameters();

          for (final Map.Entry<String, List<String>> entry : params.entrySet()) {
            parameters.put(entry.getKey(), entry.getValue().get(0));
          }

          object.put("queryParameters", parameters);

          json = object.toString(4);
        } catch (final JSONException e) {
            LOGGER.log(Level.SEVERE, null, e);
            json = "error";
        }

        return json;
    }
}
