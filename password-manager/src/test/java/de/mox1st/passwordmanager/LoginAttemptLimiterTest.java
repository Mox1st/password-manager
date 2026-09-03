package de.mox1st.passwordmanager;

import de.mox1st.passwordmanager.service.LoginAttemptLimiter;
import org.junit.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class LoginAttemptLimiterTest {

    @Test
    public void blocksAfterFiveFailedAttempts() {
        MutableClock clock = new MutableClock();
        LoginAttemptLimiter limiter = new LoginAttemptLimiter(clock);

        for (int attempt = 0; attempt < 5; attempt++) {
            limiter.recordFailedAttempt();
        }

        assertTrue(limiter.isBlocked());
    }

    @Test
    public void successfulLoginResetsAttempts() {
        MutableClock clock = new MutableClock();
        LoginAttemptLimiter limiter = new LoginAttemptLimiter(clock);

        for (int attempt = 0; attempt < 4; attempt++) {
            limiter.recordFailedAttempt();
        }
        limiter.reset();
        limiter.recordFailedAttempt();

        assertFalse(limiter.isBlocked());
    }

    @Test
    public void allowsLoginAfterBlockExpires() {
        MutableClock clock = new MutableClock();
        LoginAttemptLimiter limiter = new LoginAttemptLimiter(clock);

        for (int attempt = 0; attempt < 5; attempt++) {
            limiter.recordFailedAttempt();
        }
        clock.advance(Duration.ofSeconds(30));

        assertFalse(limiter.isBlocked());
    }

    private static final class MutableClock extends Clock {
        private Instant currentTime = Instant.EPOCH;

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return currentTime;
        }

        private void advance(Duration duration) {
            currentTime = currentTime.plus(duration);
        }
    }
}
