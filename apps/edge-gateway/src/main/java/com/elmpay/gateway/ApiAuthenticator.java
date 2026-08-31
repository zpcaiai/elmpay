package com.elmpay.gateway;

import com.sun.net.httpserver.HttpExchange;
import java.util.Optional;

/** Authenticates one API request into an immutable tenant/project/merchant principal. */
public interface ApiAuthenticator {
    Optional<ApiPrincipal> authenticate(HttpExchange exchange);
}
