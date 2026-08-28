-- One-time codes that are actually one-time.
--
-- `verifyTotp` accepts any code inside its validation window, which means the same six digits work
-- more than once for up to ninety seconds. Anyone who observes a code — a phishing proxy, a
-- shoulder-surf, malware reading the screen — can replay it while it is still current, which is
-- the one property a second factor exists to deny.
--
-- Recording the timestep each account has already spent makes a code single-use, and doing it in
-- the database rather than in process memory means it holds when more than one API process is
-- running.

ALTER TABLE staff_user ADD COLUMN IF NOT EXISTS totp_last_timestep bigint;
ALTER TABLE client_user ADD COLUMN IF NOT EXISTS totp_last_timestep bigint;

-- The portal verifies client codes and therefore has to be able to spend them. Migration 0001
-- grants UPDATE column by column, so a new column needs a new grant or every client sign-in fails.
GRANT UPDATE (totp_last_timestep) ON client_user TO attestor_portal;
