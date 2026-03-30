CREATE TABLE `proxy_debug_traces` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`downstream_path` text NOT NULL,
	`client_kind` text,
	`session_id` text,
	`trace_hint` text,
	`requested_model` text,
	`downstream_api_key_id` integer,
	`request_headers_json` text,
	`request_body_json` text,
	`sticky_session_key` text,
	`sticky_hit_channel_id` integer,
	`selected_channel_id` integer,
	`selected_route_id` integer,
	`selected_account_id` integer,
	`selected_site_id` integer,
	`selected_site_platform` text,
	`endpoint_candidates_json` text,
	`endpoint_runtime_state_json` text,
	`decision_summary_json` text,
	`final_status` text,
	`final_http_status` integer,
	`final_upstream_path` text,
	`final_response_headers_json` text,
	`final_response_body_json` text,
	`created_at` text DEFAULT (datetime('now')),
	`updated_at` text DEFAULT (datetime('now'))
);
--> statement-breakpoint
CREATE INDEX `proxy_debug_traces_created_at_idx` ON `proxy_debug_traces` (`created_at`);--> statement-breakpoint
CREATE INDEX `proxy_debug_traces_session_created_at_idx` ON `proxy_debug_traces` (`session_id`,`created_at`);--> statement-breakpoint
CREATE INDEX `proxy_debug_traces_model_created_at_idx` ON `proxy_debug_traces` (`requested_model`,`created_at`);--> statement-breakpoint
CREATE INDEX `proxy_debug_traces_final_status_created_at_idx` ON `proxy_debug_traces` (`final_status`,`created_at`);--> statement-breakpoint
CREATE TABLE `proxy_debug_attempts` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`trace_id` integer NOT NULL,
	`attempt_index` integer NOT NULL,
	`endpoint` text NOT NULL,
	`request_path` text NOT NULL,
	`target_url` text NOT NULL,
	`runtime_executor` text,
	`request_headers_json` text,
	`request_body_json` text,
	`response_status` integer,
	`response_headers_json` text,
	`response_body_json` text,
	`raw_error_text` text,
	`recover_applied` integer DEFAULT false,
	`downgrade_decision` integer DEFAULT false,
	`downgrade_reason` text,
	`memory_write_json` text,
	`created_at` text DEFAULT (datetime('now')),
	FOREIGN KEY (`trace_id`) REFERENCES `proxy_debug_traces`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `proxy_debug_attempts_trace_attempt_unique` ON `proxy_debug_attempts` (`trace_id`,`attempt_index`);--> statement-breakpoint
CREATE INDEX `proxy_debug_attempts_trace_created_at_idx` ON `proxy_debug_attempts` (`trace_id`,`created_at`);
