import org.w3c.dom.Element;
import javax.servlet.http.HttpServletRequest;
import java.util.Map;
import mondrian.xmla.impl.AuthenticatingXmlaRequestCallback;
import mondrian.xmla.XmlaConstants;
import java.util.Base64;


public class CustomAuthentication extends AuthenticatingXmlaRequestCallback {
 
public void preAction(HttpServletRequest request, Element[] requestSoapParts, Map<String, Object> context)
            throws Exception {
        String authHeader = request.getHeader("authorization");
        String encodedValue = authHeader.split(" ")[1];
        String decodedValue = Base64.base64Decode(encodedValue);
        int k = decodedValue.indexOf(":");
        if (k > 0) {
            String user = decodedValue.substring(0, k);
            String password = decodedValue.substring(k + 1, decodedValue.length());
            context.put(XmlaConstants.CONTEXT_XMLA_USERNAME, user);
            context.put(XmlaConstants.CONTEXT_XMLA_PASSWORD, password);
        }
 
        super.preAction(request, requestSoapParts, context);
    }
 
  /**
     * Implementation of authentication
     */
    @Override
    public String authenticate(String username, String password, String sessionID) {
        try {
            if(username.equals("username") && username.equals("password")){
                System.out.println("login successful");
            }
            else {
                throw new Exception("Wrong username or password");
            }
        } catch (Exception e) {
            throwAuthenticationException("User: " + username + e.getMessage());
        }
        //role
        return "xmla";
    }
}