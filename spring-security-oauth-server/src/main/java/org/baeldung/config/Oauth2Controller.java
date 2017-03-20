package org.baeldung.config;
/*
 * Copyright (c) 2017. CodeGen Ltd. - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Created by ishara on 3/20/2017 10:52 AM
 */

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;

@Controller
public class Oauth2Controller
{
    @Resource(name = "tokenStore")
    TokenStore tokenStore;

    @RequestMapping(value = "/oauth/revoke-token", method = RequestMethod.GET)
    public ResponseEntity logout( HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null) {
            String tokenValue = authHeader.replace("Bearer", "").trim();
            OAuth2AccessToken accessToken = tokenStore.readAccessToken(tokenValue);
            if( accessToken != null )
            {
                tokenStore.removeAccessToken( accessToken );
                if( accessToken.getRefreshToken() != null )
                {
                    tokenStore.removeRefreshToken( accessToken.getRefreshToken() );
                }
                return new ResponseEntity( HttpStatus.OK );
            }
            else
            {
                return new ResponseEntity( HttpStatus.NOT_FOUND );
            }
        }
        else
        {
            return new ResponseEntity( HttpStatus.UNAUTHORIZED );
        }
    }
}
