<%@ page import="javax.ws.rs.core.*" language="java" contentType="text/html; charset=ISO-8859-1"
 pageEncoding="ISO-8859-1"%>
<html>
<head>
    <title>Product Admin Interface</title>
</head>
<body bgcolor="#F5F6CE">
<%
      String logoutUri = UriBuilder.fromUri("http://localhost:8080/auth-server/rest/realms/demo/tokens/logout")
                                     .queryParam("redirect_uri", "http://localhost:8080/product-portal").build().toString();
%>
<p><a href="<%=logoutUri%>">logout</a></p>
<h1>Product Admin Interface</h1>
User <b><%=request.getUserPrincipal().getName()%></b> made this request.
</body>
</html>
