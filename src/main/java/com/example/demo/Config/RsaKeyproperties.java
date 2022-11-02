package com.example.demo.Config;


import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@ConfigurationProperties(prefix = "rsa")
public record RsaKeyproperties(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
}
