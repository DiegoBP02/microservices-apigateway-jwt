package com.javatechie.filter;

import com.javatechie.util.JwtUtil;
import com.netflix.discovery.converters.Auto;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    @Autowired
    private RouteValidator validator;

//    @Autowired
//    private RestTemplate template;

    @Autowired
    private JwtUtil jwtUtil;

    public AuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (((exchange, chain) -> {
            if(validator.isSecured.test(exchange.getRequest())){
                if(!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)){
                    throw new RuntimeException(("Missing authorization header"));
                }

                String authHeader = exchange.getRequest()
                        .getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
                if(authHeader != null&& authHeader.startsWith("Bearer ")){
                    authHeader = authHeader.substring(7);
                }

                try{
//                  template.getForObject("http://IDENTITY-SERVICE/validate?token=" + authHeader, String.class);
                    jwtUtil.validateToken(authHeader);
                } catch (Exception e){
                    System.out.println("Invalid access...!");
                    throw new RuntimeException("Unauthorized access to application");
                }
            }
            return chain.filter(exchange);
        }));
    }

    public static class Config{

    }

}
