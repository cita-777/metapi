CREATE TABLE `oauth_route_unit_members` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`unit_id` integer NOT NULL,
	`account_id` integer NOT NULL,
	`sort_order` integer DEFAULT 0,
	`success_count` integer DEFAULT 0,
	`fail_count` integer DEFAULT 0,
	`total_latency_ms` integer DEFAULT 0,
	`total_cost` real DEFAULT 0,
	`last_used_at` text,
	`last_selected_at` text,
	`last_fail_at` text,
	`consecutive_fail_count` integer DEFAULT 0 NOT NULL,
	`cooldown_level` integer DEFAULT 0 NOT NULL,
	`cooldown_until` text,
	`created_at` text DEFAULT (datetime('now')),
	`updated_at` text DEFAULT (datetime('now')),
	FOREIGN KEY (`unit_id`) REFERENCES `oauth_route_units`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`account_id`) REFERENCES `accounts`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `oauth_route_unit_members_unit_account_unique` ON `oauth_route_unit_members` (`unit_id`,`account_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `oauth_route_unit_members_account_unique` ON `oauth_route_unit_members` (`account_id`);--> statement-breakpoint
CREATE INDEX `oauth_route_unit_members_unit_sort_idx` ON `oauth_route_unit_members` (`unit_id`,`sort_order`);--> statement-breakpoint
CREATE INDEX `oauth_route_unit_members_unit_cooldown_idx` ON `oauth_route_unit_members` (`unit_id`,`cooldown_until`);--> statement-breakpoint
CREATE TABLE `oauth_route_units` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`site_id` integer NOT NULL,
	`provider` text NOT NULL,
	`name` text NOT NULL,
	`strategy` text DEFAULT 'round_robin' NOT NULL,
	`enabled` integer DEFAULT true,
	`created_at` text DEFAULT (datetime('now')),
	`updated_at` text DEFAULT (datetime('now')),
	FOREIGN KEY (`site_id`) REFERENCES `sites`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `oauth_route_units_site_provider_idx` ON `oauth_route_units` (`site_id`,`provider`);--> statement-breakpoint
CREATE INDEX `oauth_route_units_enabled_idx` ON `oauth_route_units` (`enabled`);--> statement-breakpoint
ALTER TABLE `route_channels` ADD `oauth_route_unit_id` integer;--> statement-breakpoint
CREATE INDEX `route_channels_oauth_route_unit_id_idx` ON `route_channels` (`oauth_route_unit_id`);
