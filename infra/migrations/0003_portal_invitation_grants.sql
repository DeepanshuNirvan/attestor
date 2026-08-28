-- Let a client accept an invitation.
--
-- Migration 0001 revokes `client_invitation` from the portal role, and grants no INSERT on
-- `client_user`. Both were right when the console pre-created the account and the portal only
-- signed people in. The account is now created at acceptance instead — which is the correct
-- design, because a half-made row with no password is worse — and that left the one route a new
-- client has to use unable to run a single one of its queries. `/invitations/accept` fails with a
-- permission error on the portal, so no client can ever reach the portal at all.
--
-- The grants below are the whole of what that route needs and nothing else. In particular the
-- portal still cannot issue an invitation, change who one is for, or extend one: only read one by
-- its token hash and mark it spent. The tokens themselves are stored hashed, so read access to
-- this table does not disclose a usable token.

GRANT SELECT ON client_invitation TO attestor_portal;
GRANT UPDATE (accepted_at) ON client_invitation TO attestor_portal;

-- Creating the account is the acceptance. The row is written once, with the password and the
-- sealed authenticator together, and cannot sign in until the authenticator is confirmed.
GRANT INSERT ON client_user TO attestor_portal;
