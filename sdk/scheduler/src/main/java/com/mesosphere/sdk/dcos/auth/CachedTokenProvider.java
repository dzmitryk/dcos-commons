package com.mesosphere.sdk.dcos.auth;

import com.auth0.jwt.interfaces.DecodedJWT;

import java.io.IOException;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * CachedTokenProvider retrieves token from underlying provider and caches the value. It automatically triggers
 * getToken() method on underlying provider when token is about to expire.
 */
public class CachedTokenProvider implements TokenProvider {

    private final TokenProvider provider;
    private Optional<DecodedJWT> token;
    private final int ttlSeconds;

    private final ReadWriteLock internalLock = new ReentrantReadWriteLock();
    private final Lock rlock = internalLock.readLock();
    private final Lock rwlock = internalLock.writeLock();


    public CachedTokenProvider(TokenProvider provider, int ttlSeconds) {
        this.provider = provider;
        this.ttlSeconds = ttlSeconds;
        this.token = Optional.empty();
    }

    public CachedTokenProvider(TokenProvider provider) {
        this(provider, 30);
    }

    @Override
    public DecodedJWT getToken() throws IOException {
        rlock.lock();
        try {
            if (token.isPresent()) {
                Instant triggerRefresh = token.get()
                        .getExpiresAt()
                        .toInstant()
                        .minusSeconds(this.ttlSeconds);

                if (triggerRefresh.isAfter(Instant.now())) {
                    return token.get();
                }
            }
        } finally {
            rlock.unlock();
        }

        return refreshToken();
    }

    private DecodedJWT refreshToken() throws IOException {
        rwlock.lock();
        try {
            DecodedJWT newToken = provider.getToken();
            token = Optional.of(newToken);
            return newToken;
        }
        finally {
            rwlock.unlock();
        }
    }
}
