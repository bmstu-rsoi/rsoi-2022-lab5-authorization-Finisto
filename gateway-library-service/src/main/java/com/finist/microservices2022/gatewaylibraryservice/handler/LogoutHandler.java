package com.finist.microservices2022.gatewaylibraryservice.handler;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Controller
public class LogoutHandler extends SecurityContextLogoutHandler {

    private final ClientRegistrationRepository clientRegistrationRepository;


    @Autowired
    public LogoutHandler(ClientRegistrationRepository clientRegistrationRepository) {
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        super.logout(request, response, authentication);

        String issuer = (String) getClientRegistration().getProviderDetails().getConfigurationMetadata().get("issuer");
        String clientId = getClientRegistration().getClientId();
        String returnTo = ServletUriComponentsBuilder.fromCurrentContextPath().build().toString();

        String logoutUrlString = UriComponentsBuilder
                .fromHttpUrl(issuer)
                .path("/v2")
                .queryParam("logout",clientId)
                .queryParam("returnTo", returnTo)
                .encode()
                .build().toUriString();

        try {
            response.sendRedirect(logoutUrlString);
        } catch (IOException e) {
            // Handle or log error redirecting to logout URL
            throw new RuntimeException(e);
        }
    }

    private ClientRegistration getClientRegistration(){
        return this.clientRegistrationRepository.findByRegistrationId("auth0");
    }

}
