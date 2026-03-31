CREATE TABLE `site_api_endpoints` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`site_id` integer NOT NULL,
	`url` text NOT NULL,
	`enabled` integer DEFAULT true,
	`sort_order` integer DEFAULT 0,
	`cooldown_until` text,
	`last_selected_at` text,
	`last_failed_at` text,
	`last_failure_reason` text,
	`created_at` text DEFAULT (datetime('now')),
	`updated_at` text DEFAULT (datetime('now')),
	FOREIGN KEY (`site_id`) REFERENCES `sites`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `site_api_endpoints_site_url_unique` ON `site_api_endpoints` (`site_id`,`url`);--> statement-breakpoint
CREATE INDEX `site_api_endpoints_site_enabled_sort_idx` ON `site_api_endpoints` (`site_id`,`enabled`,`sort_order`);--> statement-breakpoint
CREATE INDEX `site_api_endpoints_site_cooldown_idx` ON `site_api_endpoints` (`site_id`,`cooldown_until`);