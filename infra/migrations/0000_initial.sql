CREATE TABLE "acknowledgement" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"engagement_id" uuid NOT NULL,
	"kind" text NOT NULL,
	"acknowledged_text" text NOT NULL,
	"acknowledged_by" uuid NOT NULL,
	"note" text DEFAULT '' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ai_usage" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"engagement_id" uuid,
	"model" text NOT NULL,
	"purpose" text NOT NULL,
	"input_tokens" integer DEFAULT 0 NOT NULL,
	"output_tokens" integer DEFAULT 0 NOT NULL,
	"estimated_cost_usd" real DEFAULT 0 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "audit_log" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"actor_id" text NOT NULL,
	"actor_kind" text NOT NULL,
	"action" text NOT NULL,
	"subject_type" text NOT NULL,
	"subject_id" text NOT NULL,
	"ip_address" text,
	"user_agent" text,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "authorisation" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"engagement_id" uuid NOT NULL,
	"signed_by" text NOT NULL,
	"signer_role" text NOT NULL,
	"signer_email" text NOT NULL,
	"signed_at" timestamp with time zone,
	"document_object_key" text NOT NULL,
	"document_sha256" text NOT NULL,
	"asset_list" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"exclusion_list" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"source_addresses" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"emergency_contact" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"critical_notification_hours" integer DEFAULT 24 NOT NULL,
	"valid_from" timestamp with time zone NOT NULL,
	"valid_until" timestamp with time zone NOT NULL,
	"revoked_at" timestamp with time zone,
	"revoked_reason" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "client" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"legal_name" text NOT NULL,
	"country" text DEFAULT 'IN' NOT NULL,
	"contacts" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"billing_details" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"dpa_signed_at" timestamp with time zone,
	"policy_yaml" text DEFAULT '' NOT NULL,
	"notes" text DEFAULT '' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "client_engagement_access" (
	"client_user_id" uuid NOT NULL,
	"engagement_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "client_engagement_access_client_user_id_engagement_id_pk" PRIMARY KEY("client_user_id","engagement_id")
);
--> statement-breakpoint
CREATE TABLE "client_invitation" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"client_id" uuid NOT NULL,
	"email" text NOT NULL,
	"role" text DEFAULT 'clientMember' NOT NULL,
	"token_hash" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"accepted_at" timestamp with time zone,
	"invited_by" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "client_user" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"client_id" uuid NOT NULL,
	"email" text NOT NULL,
	"name" text NOT NULL,
	"password_hash" text,
	"role" text DEFAULT 'clientMember' NOT NULL,
	"totp_secret_sealed" text,
	"totp_enrolled_at" timestamp with time zone,
	"invited_by" uuid,
	"invited_at" timestamp with time zone,
	"activated_at" timestamp with time zone,
	"deactivated_at" timestamp with time zone,
	"portal_terms_version" text,
	"portal_terms_accepted_at" timestamp with time zone,
	"notification_preferences" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"last_login_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "credential_intake_link" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"engagement_id" uuid NOT NULL,
	"token_hash" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"used_at" timestamp with time zone,
	"created_by" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "credential_set" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"engagement_id" uuid NOT NULL,
	"label" text NOT NULL,
	"role_name" text NOT NULL,
	"auth_type" text NOT NULL,
	"sealed_value" text NOT NULL,
	"key_salt" text NOT NULL,
	"nonce" text NOT NULL,
	"is_secondary" boolean DEFAULT false NOT NULL,
	"tenant_id" text,
	"expires_at" timestamp with time zone NOT NULL,
	"last_verified_at" timestamp with time zone,
	"verification_error" text,
	"revoked_at" timestamp with time zone,
	"shredded_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "engagement" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"client_id" uuid NOT NULL,
	"reference" text NOT NULL,
	"reference_year" integer NOT NULL,
	"reference_sequence" integer NOT NULL,
	"type" text NOT NULL,
	"title" text NOT NULL,
	"state" text DEFAULT 'draft' NOT NULL,
	"test_type" text DEFAULT 'greyBox' NOT NULL,
	"starts_at" timestamp with time zone,
	"ends_at" timestamp with time zone,
	"timezone" text DEFAULT 'Asia/Kolkata' NOT NULL,
	"currency" text DEFAULT 'INR' NOT NULL,
	"quoted_amount" integer DEFAULT 0 NOT NULL,
	"advance_paid_at" timestamp with time zone,
	"final_paid_at" timestamp with time zone,
	"advance_gate_override" jsonb,
	"invoice_state" text DEFAULT 'notIssued' NOT NULL,
	"methodology_versions" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"ai_assist_enabled" boolean DEFAULT false NOT NULL,
	"agentic_enabled" boolean DEFAULT false NOT NULL,
	"report_template_id" text DEFAULT 'attestor-standard-v1' NOT NULL,
	"policy_yaml" text DEFAULT '' NOT NULL,
	"evidence_retention_days" integer DEFAULT 90 NOT NULL,
	"legal_hold" boolean DEFAULT false NOT NULL,
	"third_party_ack_at" timestamp with time zone,
	"cloud_policy_ack_at" timestamp with time zone,
	"pre_flight_checklist" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"review_checklist" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "evidence" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"finding_id" uuid,
	"engagement_id" uuid NOT NULL,
	"scan_run_id" uuid,
	"kind" text NOT NULL,
	"object_key" text NOT NULL,
	"content_type" text DEFAULT 'text/plain' NOT NULL,
	"byte_size" integer DEFAULT 0 NOT NULL,
	"sha256" text NOT NULL,
	"redaction_applied" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"captured_at" timestamp with time zone DEFAULT now() NOT NULL,
	"purged_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "false_positive_memo" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"client_id" uuid NOT NULL,
	"dedupe_key" text NOT NULL,
	"reason" text NOT NULL,
	"created_by" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "finding" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"engagement_id" uuid NOT NULL,
	"scan_run_id" uuid,
	"reference" text,
	"reference_sequence" integer,
	"source" text NOT NULL,
	"tool_name" text,
	"tool_finding_ref" text,
	"check_id" text,
	"title" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"severity" text NOT NULL,
	"severity_override_reason" text,
	"severity_overridden_by" uuid,
	"cvss_version" text,
	"cvss_vector" text,
	"cvss_score" real,
	"cwe_id" integer,
	"owasp_category" text,
	"api_category" text,
	"wstg_id" text,
	"asvs_requirement" text,
	"masvs_control" text,
	"llm_category" text,
	"affected_assets" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"business_impact" text DEFAULT '' NOT NULL,
	"likelihood" text DEFAULT '' NOT NULL,
	"attacker_prerequisites" text DEFAULT '' NOT NULL,
	"reproduction_steps" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"remediation" text DEFAULT '' NOT NULL,
	"references" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"status" text DEFAULT 'candidate' NOT NULL,
	"dedupe_key" text NOT NULL,
	"correlated_into_id" uuid,
	"attack_success_rate" real,
	"attempt_count" integer,
	"ai_draft_fields" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"ai_model" text,
	"first_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"confirmed_at" timestamp with time zone,
	"confirmed_by" uuid,
	"fixed_at" timestamp with time zone,
	"retested_at" timestamp with time zone,
	"risk_accepted_at" timestamp with time zone,
	"risk_accepted_by" text,
	"risk_acceptance_justification" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "finding_comment" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"finding_id" uuid NOT NULL,
	"author_kind" text NOT NULL,
	"staff_user_id" uuid,
	"client_user_id" uuid,
	"parent_id" uuid,
	"markdown" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "notification" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"engagement_id" uuid,
	"client_user_id" uuid,
	"channel" text DEFAULT 'email' NOT NULL,
	"template" text NOT NULL,
	"subject" text NOT NULL,
	"body" text NOT NULL,
	"severity_threshold" text,
	"queued_at" timestamp with time zone DEFAULT now() NOT NULL,
	"approved_at" timestamp with time zone,
	"approved_by" uuid,
	"sent_at" timestamp with time zone,
	"failure_reason" text
);
--> statement-breakpoint
CREATE TABLE "panic_stop" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"scope" text NOT NULL,
	"engagement_id" uuid,
	"active" boolean DEFAULT true NOT NULL,
	"pressed_by" text NOT NULL,
	"reason" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"cleared_by" text,
	"cleared_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "questionnaire_answer" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"category" text NOT NULL,
	"question" text NOT NULL,
	"answer" text NOT NULL,
	"sort_order" integer DEFAULT 0 NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "report" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"engagement_id" uuid NOT NULL,
	"kind" text NOT NULL,
	"version" text NOT NULL,
	"template_id" text NOT NULL,
	"legal_template_versions" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"rendered_html_key" text,
	"pdf_key" text,
	"coverage_snapshot" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"released_at" timestamp with time zone,
	"released_by" uuid,
	"recipient_list" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "report_download" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"report_id" uuid NOT NULL,
	"client_user_id" uuid,
	"staff_user_id" uuid,
	"watermark_text" text NOT NULL,
	"ip_address" text,
	"user_agent" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "report_section" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"engagement_id" uuid NOT NULL,
	"section_key" text NOT NULL,
	"markdown" text DEFAULT '' NOT NULL,
	"is_ai_draft" boolean DEFAULT false NOT NULL,
	"approved_at" timestamp with time zone,
	"approved_by" uuid,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "retainer_schedule" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"client_id" uuid NOT NULL,
	"engagement_id" uuid,
	"cadence" text DEFAULT 'monthly' NOT NULL,
	"modules" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"window_rule" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"next_run_at" timestamp with time zone,
	"last_run_at" timestamp with time zone,
	"active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "retest_request" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"engagement_id" uuid NOT NULL,
	"requested_by" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"finding_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"note" text DEFAULT '' NOT NULL,
	"scheduled_at" timestamp with time zone,
	"completed_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "scan_run" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"engagement_id" uuid NOT NULL,
	"module" text NOT NULL,
	"tool_name" text NOT NULL,
	"tool_version_digest" text DEFAULT '' NOT NULL,
	"policy_snapshot" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"covered_check_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"targets" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"status" text DEFAULT 'queued' NOT NULL,
	"started_at" timestamp with time zone,
	"finished_at" timestamp with time zone,
	"exit_code" integer,
	"raw_output_key" text,
	"stats" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"abort_reason" text,
	"dry_run" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "scope_item" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"engagement_id" uuid NOT NULL,
	"kind" text NOT NULL,
	"value" text NOT NULL,
	"included" boolean DEFAULT true NOT NULL,
	"notes" text DEFAULT '' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "session" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"staff_user_id" uuid,
	"client_user_id" uuid,
	"token_hash" text NOT NULL,
	"ip_address" text,
	"user_agent" text,
	"mfa_satisfied_at" timestamp with time zone,
	"expires_at" timestamp with time zone NOT NULL,
	"revoked_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "staff_user" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"email" text NOT NULL,
	"name" text NOT NULL,
	"password_hash" text NOT NULL,
	"role" text DEFAULT 'tester' NOT NULL,
	"totp_secret_sealed" text,
	"totp_enrolled_at" timestamp with time zone,
	"active" boolean DEFAULT true NOT NULL,
	"last_login_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "acknowledgement" ADD CONSTRAINT "acknowledgement_engagement_id_engagement_id_fk" FOREIGN KEY ("engagement_id") REFERENCES "public"."engagement"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ai_usage" ADD CONSTRAINT "ai_usage_engagement_id_engagement_id_fk" FOREIGN KEY ("engagement_id") REFERENCES "public"."engagement"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "authorisation" ADD CONSTRAINT "authorisation_engagement_id_engagement_id_fk" FOREIGN KEY ("engagement_id") REFERENCES "public"."engagement"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "client_engagement_access" ADD CONSTRAINT "client_engagement_access_client_user_id_client_user_id_fk" FOREIGN KEY ("client_user_id") REFERENCES "public"."client_user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "client_engagement_access" ADD CONSTRAINT "client_engagement_access_engagement_id_engagement_id_fk" FOREIGN KEY ("engagement_id") REFERENCES "public"."engagement"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "client_invitation" ADD CONSTRAINT "client_invitation_client_id_client_id_fk" FOREIGN KEY ("client_id") REFERENCES "public"."client"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "client_user" ADD CONSTRAINT "client_user_client_id_client_id_fk" FOREIGN KEY ("client_id") REFERENCES "public"."client"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "credential_intake_link" ADD CONSTRAINT "credential_intake_link_engagement_id_engagement_id_fk" FOREIGN KEY ("engagement_id") REFERENCES "public"."engagement"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "credential_set" ADD CONSTRAINT "credential_set_engagement_id_engagement_id_fk" FOREIGN KEY ("engagement_id") REFERENCES "public"."engagement"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "engagement" ADD CONSTRAINT "engagement_client_id_client_id_fk" FOREIGN KEY ("client_id") REFERENCES "public"."client"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "evidence" ADD CONSTRAINT "evidence_finding_id_finding_id_fk" FOREIGN KEY ("finding_id") REFERENCES "public"."finding"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "evidence" ADD CONSTRAINT "evidence_engagement_id_engagement_id_fk" FOREIGN KEY ("engagement_id") REFERENCES "public"."engagement"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "evidence" ADD CONSTRAINT "evidence_scan_run_id_scan_run_id_fk" FOREIGN KEY ("scan_run_id") REFERENCES "public"."scan_run"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "false_positive_memo" ADD CONSTRAINT "false_positive_memo_client_id_client_id_fk" FOREIGN KEY ("client_id") REFERENCES "public"."client"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "finding" ADD CONSTRAINT "finding_engagement_id_engagement_id_fk" FOREIGN KEY ("engagement_id") REFERENCES "public"."engagement"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "finding" ADD CONSTRAINT "finding_scan_run_id_scan_run_id_fk" FOREIGN KEY ("scan_run_id") REFERENCES "public"."scan_run"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "finding_comment" ADD CONSTRAINT "finding_comment_finding_id_finding_id_fk" FOREIGN KEY ("finding_id") REFERENCES "public"."finding"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "finding_comment" ADD CONSTRAINT "finding_comment_staff_user_id_staff_user_id_fk" FOREIGN KEY ("staff_user_id") REFERENCES "public"."staff_user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "finding_comment" ADD CONSTRAINT "finding_comment_client_user_id_client_user_id_fk" FOREIGN KEY ("client_user_id") REFERENCES "public"."client_user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "notification" ADD CONSTRAINT "notification_engagement_id_engagement_id_fk" FOREIGN KEY ("engagement_id") REFERENCES "public"."engagement"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "panic_stop" ADD CONSTRAINT "panic_stop_engagement_id_engagement_id_fk" FOREIGN KEY ("engagement_id") REFERENCES "public"."engagement"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "report" ADD CONSTRAINT "report_engagement_id_engagement_id_fk" FOREIGN KEY ("engagement_id") REFERENCES "public"."engagement"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "report_download" ADD CONSTRAINT "report_download_report_id_report_id_fk" FOREIGN KEY ("report_id") REFERENCES "public"."report"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "report_download" ADD CONSTRAINT "report_download_client_user_id_client_user_id_fk" FOREIGN KEY ("client_user_id") REFERENCES "public"."client_user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "report_download" ADD CONSTRAINT "report_download_staff_user_id_staff_user_id_fk" FOREIGN KEY ("staff_user_id") REFERENCES "public"."staff_user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "report_section" ADD CONSTRAINT "report_section_engagement_id_engagement_id_fk" FOREIGN KEY ("engagement_id") REFERENCES "public"."engagement"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "retainer_schedule" ADD CONSTRAINT "retainer_schedule_client_id_client_id_fk" FOREIGN KEY ("client_id") REFERENCES "public"."client"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "retainer_schedule" ADD CONSTRAINT "retainer_schedule_engagement_id_engagement_id_fk" FOREIGN KEY ("engagement_id") REFERENCES "public"."engagement"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "retest_request" ADD CONSTRAINT "retest_request_engagement_id_engagement_id_fk" FOREIGN KEY ("engagement_id") REFERENCES "public"."engagement"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "retest_request" ADD CONSTRAINT "retest_request_requested_by_client_user_id_fk" FOREIGN KEY ("requested_by") REFERENCES "public"."client_user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scan_run" ADD CONSTRAINT "scan_run_engagement_id_engagement_id_fk" FOREIGN KEY ("engagement_id") REFERENCES "public"."engagement"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scope_item" ADD CONSTRAINT "scope_item_engagement_id_engagement_id_fk" FOREIGN KEY ("engagement_id") REFERENCES "public"."engagement"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "session" ADD CONSTRAINT "session_staff_user_id_staff_user_id_fk" FOREIGN KEY ("staff_user_id") REFERENCES "public"."staff_user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "session" ADD CONSTRAINT "session_client_user_id_client_user_id_fk" FOREIGN KEY ("client_user_id") REFERENCES "public"."client_user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "audit_log_subject_idx" ON "audit_log" USING btree ("subject_type","subject_id");--> statement-breakpoint
CREATE INDEX "audit_log_created_idx" ON "audit_log" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "audit_log_action_idx" ON "audit_log" USING btree ("action");--> statement-breakpoint
CREATE INDEX "authorisation_engagement_idx" ON "authorisation" USING btree ("engagement_id");--> statement-breakpoint
CREATE UNIQUE INDEX "client_user_email_unique" ON "client_user" USING btree ("email");--> statement-breakpoint
CREATE INDEX "client_user_client_idx" ON "client_user" USING btree ("client_id");--> statement-breakpoint
CREATE INDEX "credential_set_engagement_idx" ON "credential_set" USING btree ("engagement_id");--> statement-breakpoint
CREATE UNIQUE INDEX "engagement_reference_unique" ON "engagement" USING btree ("reference");--> statement-breakpoint
CREATE INDEX "engagement_client_idx" ON "engagement" USING btree ("client_id");--> statement-breakpoint
CREATE INDEX "engagement_state_idx" ON "engagement" USING btree ("state");--> statement-breakpoint
CREATE INDEX "evidence_finding_idx" ON "evidence" USING btree ("finding_id");--> statement-breakpoint
CREATE INDEX "evidence_engagement_idx" ON "evidence" USING btree ("engagement_id");--> statement-breakpoint
CREATE UNIQUE INDEX "false_positive_unique" ON "false_positive_memo" USING btree ("client_id","dedupe_key");--> statement-breakpoint
CREATE INDEX "finding_engagement_idx" ON "finding" USING btree ("engagement_id");--> statement-breakpoint
CREATE INDEX "finding_status_idx" ON "finding" USING btree ("status");--> statement-breakpoint
CREATE INDEX "finding_severity_idx" ON "finding" USING btree ("severity");--> statement-breakpoint
CREATE UNIQUE INDEX "finding_dedupe_unique" ON "finding" USING btree ("engagement_id","dedupe_key");--> statement-breakpoint
CREATE INDEX "finding_comment_finding_idx" ON "finding_comment" USING btree ("finding_id");--> statement-breakpoint
CREATE INDEX "notification_engagement_idx" ON "notification" USING btree ("engagement_id");--> statement-breakpoint
CREATE INDEX "questionnaire_category_idx" ON "questionnaire_answer" USING btree ("category");--> statement-breakpoint
CREATE INDEX "report_engagement_idx" ON "report" USING btree ("engagement_id");--> statement-breakpoint
CREATE INDEX "report_download_report_idx" ON "report_download" USING btree ("report_id");--> statement-breakpoint
CREATE UNIQUE INDEX "report_section_unique" ON "report_section" USING btree ("engagement_id","section_key");--> statement-breakpoint
CREATE INDEX "retest_request_engagement_idx" ON "retest_request" USING btree ("engagement_id");--> statement-breakpoint
CREATE INDEX "scan_run_engagement_idx" ON "scan_run" USING btree ("engagement_id");--> statement-breakpoint
CREATE INDEX "scan_run_status_idx" ON "scan_run" USING btree ("status");--> statement-breakpoint
CREATE INDEX "scope_item_engagement_idx" ON "scope_item" USING btree ("engagement_id");--> statement-breakpoint
CREATE UNIQUE INDEX "scope_item_unique" ON "scope_item" USING btree ("engagement_id","kind","value","included");--> statement-breakpoint
CREATE UNIQUE INDEX "session_token_unique" ON "session" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "session_client_user_idx" ON "session" USING btree ("client_user_id");--> statement-breakpoint
CREATE INDEX "session_staff_user_idx" ON "session" USING btree ("staff_user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "staff_user_email_unique" ON "staff_user" USING btree ("email");