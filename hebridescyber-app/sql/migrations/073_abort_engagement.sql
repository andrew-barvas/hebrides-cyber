-- Migration 073: abort_engagement(), the engagement stop path
-- (docs/EXPLOITABILITY-ENGINE.md §10.6). One transaction, so a stop can't land
-- half done: the engagement is aborted, every authorisation linked to it is
-- revoked and its open simulations are withdrawn, or nothing changes and the
-- caller can try again.
--
-- Calling it on an engagement that's already aborted revokes anything linked
-- since, and reports `already_aborted`. A closed engagement is left alone.
-- Service role only: the route decides who may stop what. Idempotent.

CREATE OR REPLACE FUNCTION public.abort_engagement(p_engagement_id uuid, p_reason text)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public
AS $$
DECLARE
  v_state text;
  v_hosts text[];
  v_withdrawn integer;
BEGIN
  SELECT state INTO v_state FROM engagements WHERE id = p_engagement_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('outcome', 'not_found');
  END IF;
  IF v_state = 'closed' THEN
    RETURN jsonb_build_object('outcome', 'closed');
  END IF;

  IF v_state <> 'aborted' THEN
    UPDATE engagements SET state = 'aborted', aborted_at = now(), abort_reason = p_reason WHERE id = p_engagement_id;
  END IF;

  WITH revoked AS (
    UPDATE offensive_scan_authorizations SET revoked_at = now()
    WHERE engagement_id = p_engagement_id AND revoked_at IS NULL
    RETURNING target_host
  )
  SELECT coalesce(array_agg(target_host ORDER BY target_host), '{}') INTO v_hosts FROM revoked;

  WITH withdrawn AS (
    UPDATE exploit_simulations SET status = 'withdrawn', status_changed_at = now()
    WHERE engagement_id = p_engagement_id AND status IN ('planned', 'accepted', 'validation_scheduled')
    RETURNING 1
  )
  SELECT count(*) INTO v_withdrawn FROM withdrawn;

  RETURN jsonb_build_object(
    'outcome', CASE WHEN v_state = 'aborted' THEN 'already_aborted' ELSE 'aborted' END,
    'from', v_state,
    'revoked_hosts', to_jsonb(v_hosts),
    'simulations_withdrawn', v_withdrawn
  );
END;
$$;

REVOKE ALL ON FUNCTION public.abort_engagement(uuid, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.abort_engagement(uuid, text) FROM anon, authenticated;
GRANT EXECUTE ON FUNCTION public.abort_engagement(uuid, text) TO service_role;
