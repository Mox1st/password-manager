package de.mox1st.passwordmanager.service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

public class LoginAttemptLimiter {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final Duration BLOCK_DURATION = Duration.ofSeconds(30);

    private final Clock clock;
    private int failedAttempts;
    private Instant blockedUntil;

    public LoginAttemptLimiter() {
        this(Clock.systemUTC());
    }

    public LoginAttemptLimiter(Clock clock) {
        this.clock = clock;
    }

    public synchronized boolean isBlocked() {
        if (blockedUntil == null) {
            return false;
        }

        if (clock.instant().isBefore(blockedUntil)) {
            return true;
        }

        blockedUntil = null;
        failedAttempts = 0;
        return false;
    }

    public synchronized void recordFailedAttempt() {
        if (isBlocked()) {
            return;
        }

        failedAttempts++;
        if (failedAttempts >= MAX_FAILED_ATTEMPTS) {
            blockedUntil = clock.instant().plus(BLOCK_DURATION);
        }
    }

    public synchronized void reset() {
        failedAttempts = 0;
        blockedUntil = null;
    }
}
