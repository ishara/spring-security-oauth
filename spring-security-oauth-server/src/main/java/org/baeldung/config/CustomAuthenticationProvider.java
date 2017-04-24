package org.baeldung.config;
/*
 * Copyright (c) 2017. CodeGen Ltd. - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Created by ishara on 3/20/2017 4:24 PM
 */

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.List;

public class CustomAuthenticationProvider implements AuthenticationProvider
{
    @Override public Authentication authenticate( Authentication authentication ) throws AuthenticationException
    {
        final String name = authentication.getName();
        final String password = authentication.getCredentials().toString();

        if( name.equals( "john" ) && password.equals( "123" ) )
        {
            final List<GrantedAuthority> grantedAuths = new ArrayList<>();
            grantedAuths.add( new SimpleGrantedAuthority( "ROLE_USER" ) );
            final UserDetails principal = new User( name, password, grantedAuths );
            final Authentication auth = new UsernamePasswordAuthenticationToken( principal, password, grantedAuths );
            return auth;
        }
        else
        {
            return null;
        }
    }

    @Override public boolean supports( Class<?> authentication )
    {
        return authentication.equals( UsernamePasswordAuthenticationToken.class );
    }
}
